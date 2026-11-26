package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/sso"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"golang.org/x/oauth2"
)

// ssoProvider is one configured identity provider: KySignOn or the generic OIDC profile.
type ssoProvider interface {
	BuildAuthURL(ctx context.Context, redirectURI, state, verifier, nonce string) (string, error)
	ExchangeCode(ctx context.Context, code, verifier, redirectURI, expectedNonce string) (*sso.IdentityClaims, error)
}

func (s *Server) ssoClient(name string) ssoProvider {
	if name == "oidc" {
		return s.oidc
	}
	return s.kysignon
}

// handleSSOLogin starts the authorization code flow for the named provider.
func (s *Server) handleSSOLogin(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := crypto.RandomHex(16)
		nonce := crypto.RandomHex(16)
		verifier := oauth2.GenerateVerifier()

		// kyguard-cli login (spec §7.6): the CLI's loopback port and PKCE challenge ride with
		// this state, so the callback hands the login to that CLI instead of this browser.
		cli, ok := cliLoginParams(r)
		if !ok {
			s.writeError(w, http.StatusBadRequest, "cli_port must be 1024-65535 and cli_challenge a base64url S256 challenge")
			return
		}

		redirectURI := fmt.Sprintf("%s/api/sso/%s/callback", s.config.Server.AppURL, name)
		authURL, err := s.ssoClient(name).BuildAuthURL(r.Context(), redirectURI, state, verifier, nonce)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Store verifier and nonce in short-lived cookies (__Host- on https, so Path=/).
		host, secure := s.config.Security.HostCookies, s.config.Security.CookieSecure
		if cli != "" {
			http.SetCookie(w, &http.Cookie{Name: auth.CookieName("ky_cli_"+state, host), Value: cli, Path: "/", MaxAge: 300, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
		}
		http.SetCookie(w, &http.Cookie{
			Name:     auth.CookieName("ky_pkce_"+state, host),
			Value:    verifier,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     auth.CookieName("ky_nonce_"+state, host),
			Value:    nonce,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// handleSSOCallback finishes the named provider's flow: verified ID token, fresh auth_time,
// the account found by (issuer, subject), and its role recomputed from the token.
func (s *Server) handleSSOCallback(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		cookie, err := r.Cookie(auth.CookieName("ky_pkce_"+state, s.config.Security.HostCookies))
		if err != nil || cookie.Value == "" {
			s.writeError(w, http.StatusBadRequest, "Invalid or expired SSO state")
			return
		}
		verifier := cookie.Value
		nonceCookie, err := r.Cookie(auth.CookieName("ky_nonce_"+state, s.config.Security.HostCookies))
		if err != nil || nonceCookie.Value == "" {
			s.writeError(w, http.StatusBadRequest, "Invalid or expired SSO nonce")
			return
		}

		redirectURI := fmt.Sprintf("%s/api/sso/%s/callback", s.config.Server.AppURL, name)
		claims, err := s.ssoClient(name).ExchangeCode(r.Context(), code, verifier, redirectURI, nonceCookie.Value)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("SSO exchange failed: %v", err))
			return
		}
		if err := claims.CheckFresh(time.Now()); err != nil {
			s.writeError(w, http.StatusUnauthorized, "Your identity provider did not sign you in just now; sign in again")
			return
		}

		user, status, msg := s.ssoAccount(r, name, claims)
		if user == nil {
			s.writeError(w, status, msg)
			return
		}

		if c, err := r.Cookie(auth.CookieName("ky_cli_"+state, s.config.Security.HostCookies)); err == nil && c.Value != "" {
			s.handOffToCLI(w, r, user, claims, c.Value)
			return
		}

		// Never an active session: a pending one that only TOTP step-up exchanges (spec §7.3).
		_, _, err = s.sessions.IssuePendingSession(r.Context(), w, r, user, claims.Issuer, claims.SessionID, claims.IssuedAt, claims.MFA)
		if errors.Is(err, store.ErrSSOSessionEnded) {
			s.writeError(w, http.StatusUnauthorized, "SSO session already ended")
			return
		}
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Session creation failed")
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// ssoAccount finds or provisions the account whose identity is the token's (issuer,
// subject), adopting a matching SCIM row, and makes its stored role the one the token's
// per-app roles give (spec §7.2). On refusal it returns nil with the status and message.
func (s *Server) ssoAccount(r *http.Request, provider string, claims *sso.IdentityClaims) (*store.User, int, string) {
	ctx := r.Context()
	role := claims.LocalRole()
	user, err := s.store.Users().GetUserBySSO(ctx, claims.Issuer, claims.Subject)
	if err == nil && user.SSOProvider == "scim" {
		_, err = sso.AdoptSCIMUser(store.WithAudit(ctx, &store.AuditRecord{UserID: user.ID, Action: "sso.scim_account_linked", Resource: user.Username, IPAddress: s.requestIP(r)}), s.store.Users(), user, provider)
	}
	if errors.Is(err, store.ErrNotFound) {
		if !s.config.SSO.AutoProvision {
			return nil, http.StatusForbidden, "User account not provisioned"
		}
		user = &store.User{
			ID:          fmt.Sprintf("usr_%s", crypto.RandomHex(12)),
			Username:    claims.PreferredUsername,
			Email:       claims.Email,
			DisplayName: claims.Name,
			Role:        role,
			Status:      "active",
			SSOProvider: provider,
			SSOSubject:  claims.Subject,
			SSOIssuer:   claims.Issuer,
		}
		err = s.store.Users().CreateUser(store.WithAudit(ctx, &store.AuditRecord{UserID: user.ID, Action: "sso.user_provisioned", Resource: user.Username, IPAddress: s.requestIP(r)}), user)
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, http.StatusConflict, fmt.Sprintf("An account named %q already exists here and is not linked to this sign-in. An administrator must rename or remove that account in its directory, or provision it through SCIM with your identity provider subject as its externalId.", claims.PreferredUsername)
		}
	}
	if errors.Is(err, store.ErrConflict) {
		return nil, http.StatusConflict, "Your account changed while you were signing in. Sign in again."
	}
	if err != nil {
		return nil, http.StatusInternalServerError, "Failed to provision SSO user"
	}
	if user.Status != "active" {
		return nil, http.StatusForbidden, "Account is disabled"
	}
	// The role follows the token on every sign-in; the change revokes the user's other
	// sessions in the same transaction and writes no other field, so it cannot undo a
	// concurrent SCIM edit.
	if user.Role != role {
		prevRole := user.Role
		user.Role = role
		rec := &store.AuditRecord{UserID: user.ID, Action: "sso.role_changed", Resource: user.Username, Details: fmt.Sprintf("from=%s to=%s", prevRole, role), IPAddress: s.requestIP(r)}
		if err := s.store.Users().UpdateUserRole(store.WithAudit(ctx, rec), user, prevRole); errors.Is(err, store.ErrConflict) {
			return nil, http.StatusConflict, "Your account changed while you were signing in. Sign in again."
		} else if err != nil {
			return nil, http.StatusInternalServerError, "Failed to update the account role"
		}
	}
	return user, 0, ""
}

// ssoLogoutFence outlives the 5-minute login callback window, so a logout that lands
// while the browser is still finishing that login also ends it.
const ssoLogoutFence = 10 * time.Minute

// handleKySignOnBackchannelLogout is the OpenID Connect Back-Channel Logout receiver: KySignOn
// POSTs a signed logout_token when a login ends, and every local session of it ends here.
func (s *Server) handleKySignOnBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	claims, err := s.kysignon.VerifyLogoutToken(r.Context(), r.PostFormValue("logout_token"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	fenceUntil := time.Now().Add(ssoLogoutFence)
	if claims.SessionID != "" {
		err = s.store.Sessions().EndSSOSession(r.Context(), claims.Issuer, claims.SessionID, fenceUntil)
	} else {
		// iat has whole-second precision: round up so a login from that same second ends too.
		err = s.store.Sessions().EndSSOSubject(r.Context(), claims.Issuer, claims.Subject, claims.IssuedAt.Add(time.Second), fenceUntil)
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	// A failed audit write fails the request; the provider retries, and a repeated logout is
	// a harmless no-op that is audited then.
	if err := s.store.Audit().LogAudit(r.Context(), &store.AuditRecord{
		Action:    "auth.sso_backchannel_logout",
		Resource:  "session",
		IPAddress: s.requestIP(r),
	}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	w.WriteHeader(http.StatusOK)
}
