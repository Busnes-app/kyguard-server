package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// runBreakGlass is the only way to create a break-glass admin or reset its factor: on the
// host, never through the web (spec §7.4).
func runBreakGlass(args []string) {
	if len(args) == 0 || (args[0] != "create" && args[0] != "reset-totp") {
		log.Fatal("usage: kyguard-server break-glass create|reset-totp -username NAME")
	}
	fs := flag.NewFlagSet("break-glass "+args[0], flag.ExitOnError)
	username := fs.String("username", "", "break-glass account name")
	_ = fs.Parse(args[1:])
	if *username == "" {
		log.Fatal("-username is required")
	}
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("DB error: %v", err)
	}
	defer st.Close()
	if args[0] == "create" {
		err = createBreakGlass(ctx, cfg, st, *username, os.Stdout)
	} else {
		err = resetBreakGlassTOTP(ctx, cfg, st, *username, os.Stdout)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// createBreakGlass makes a break-glass admin with a generated password and TOTP factor and
// prints both once. Nothing else ever shows them.
func createBreakGlass(ctx context.Context, cfg *config.Config, st store.Store, username string, out io.Writer) error {
	if err := auth.ValidateUsername(username); err != nil {
		return err
	}
	factors, err := auth.NewFactors(st, cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	pass := base64.RawURLEncoding.EncodeToString(raw) // 24 characters, 144 bits
	hash, err := password.Hash(pass)
	if err != nil {
		return err
	}
	user := &store.User{ID: "usr_" + crypto.RandomHex(12), Username: username, DisplayName: username + " (break-glass)", PasswordHash: hash, Role: "admin", Status: "active"}
	secret, sealed, err := factors.NewSecret(user.ID)
	if err != nil {
		return err
	}
	// Account, factor and audit record commit together: a failure leaves nothing to clean up.
	if err := st.MFA().CreateBreakGlass(ctx, user, &store.MFAFactor{ID: "mfa_" + crypto.RandomHex(12), SecretEnc: sealed},
		&store.AuditRecord{Action: "break_glass.created", Resource: "user", Details: "severity=critical via=host"}); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("refusing: an account named %q already exists", username)
		}
		return err
	}
	if _, err := fmt.Fprintf(out, "Break-glass account %q created. Shown once; store both offline.\nPassword: %s\nTOTP: %s\n", username, pass, totp.ProvisioningURI(cfg.Server.AppName, username, secret)); err != nil {
		// Nobody saw the credentials: remove the account so the create can simply be retried.
		if derr := st.Users().DeleteUser(ctx, user.ID); derr != nil {
			return fmt.Errorf("printing the credentials failed (%v) and removing account %q failed (%v): remove it before retrying", err, username, derr)
		}
		return fmt.Errorf("printing the credentials failed, so account %q was removed again; retry: %w", username, err)
	}
	return nil
}

// resetBreakGlassTOTP replaces a break-glass account's TOTP secret, ending its sessions.
func resetBreakGlassTOTP(ctx context.Context, cfg *config.Config, st store.Store, username string, out io.Writer) error {
	factors, err := auth.NewFactors(st, cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}
	user, err := st.Users().GetUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("no account %q: %w", username, err)
	}
	if user.AccountType != store.AccountBreakGlass {
		return fmt.Errorf("refusing: %q is not a break-glass account", username)
	}
	secret, sealed, err := factors.NewSecret(user.ID)
	if err != nil {
		return err
	}
	if err := st.MFA().ReplaceFactor(ctx, user.ID, "mfa_"+crypto.RandomHex(12), sealed,
		&store.AuditRecord{Action: "break_glass.totp_reset", Resource: "user", Details: "severity=critical via=host; sessions revoked"}); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "TOTP for %q replaced; its sessions are revoked. Shown once.\nTOTP: %s\n", username, totp.ProvisioningURI(cfg.Server.AppName, username, secret)); err != nil {
		return fmt.Errorf("the TOTP secret was replaced but printing it failed; run reset-totp again: %w", err)
	}
	return nil
}
