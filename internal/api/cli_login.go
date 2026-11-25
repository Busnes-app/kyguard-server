package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/sso"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// CLICodeTTL is how long a kyguard-cli login code may wait for its redemption (spec §7.6).
const CLICodeTTL = 60 * time.Second

// pkceChallenge is an RFC 7636 S256 challenge: 43 base64url characters.
var pkceChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// cliLoginParams reads the optional cli_port and cli_challenge of an SSO login as one
// "port:challenge" value; "" for a browser login, ok false when only one is given or either
// is malformed.
func cliLoginParams(r *http.Request) (string, bool) {
	port, challenge := r.URL.Query().Get("cli_port"), r.URL.Query().Get("cli_challenge")
	if port == "" && challenge == "" {
		return "", true
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1024 || n > 65535 || strconv.Itoa(n) != port || !pkceChallenge.MatchString(challenge) {
		return "", false
	}
	return port + ":" + challenge, true
}

// handOffToCLI ends an SSO callback that a kyguard-cli login started: no browser session, but
// a one-time code bound to this verified login and the CLI's challenge, sent to the CLI's
// loopback listener.
func (s *Server) handOffToCLI(w http.ResponseWriter, r *http.Request, user *store.User, claims *sso.IdentityClaims, cli string) {
	port, challenge, _ := strings.Cut(cli, ":")
	code := crypto.RandomHex(32)
	err := s.store.Sessions().CreateCLICode(r.Context(), &store.CLICode{
		CodeHash: crypto.SHA256Hex([]byte(code)), UserID: user.ID, SSOIssuer: claims.Issuer, SSOSID: claims.SessionID,
		IssuedAt: claims.IssuedAt, MFAAsserted: claims.MFA, Challenge: challenge, ExpiresAt: time.Now().Add(CLICodeTTL),
	}, &store.AuditRecord{UserID: user.ID, Action: "auth.cli_code_issued", Resource: "session", IPAddress: s.requestIP(r)})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "CLI sign-in failed")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("http://127.0.0.1:%s/cb?code=%s", port, code), http.StatusFound)
}

// handleCLIExchange redeems a CLI login code with the PKCE verifier for a pending session
// token (spec §7.6). The code is spent by the first attempt, right or wrong.
func (s *Server) handleCLIExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.Code == "" || req.CodeVerifier == "" {
		s.writeError(w, http.StatusBadRequest, "code and code_verifier are required")
		return
	}
	refused := func() {
		s.writeError(w, http.StatusUnauthorized, "This CLI sign-in code is invalid or expired; run kyguard-cli login again")
	}
	ctx := r.Context()
	code, err := s.store.Sessions().TakeCLICode(ctx, crypto.SHA256Hex([]byte(req.Code)))
	if errors.Is(err, store.ErrNotFound) {
		refused()
		return
	}
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "CLI sign-in temporarily unavailable")
		return
	}
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(code.Challenge)) != 1 {
		refused()
		return
	}
	user, err := s.store.Users().GetUserByID(ctx, code.UserID)
	if err != nil || user.Status != "active" {
		refused()
		return
	}
	var token string
	err = detachedWrite(r, func(ctx context.Context) error {
		var err error
		token, err = s.sessions.IssueCLIPendingSession(ctx, r, user, code,
			&store.AuditRecord{UserID: user.ID, Action: "auth.cli_login", Resource: "session", IPAddress: s.requestIP(r)})
		return err
	})
	switch {
	case errors.Is(err, store.ErrSSOSessionEnded):
		s.writeError(w, http.StatusUnauthorized, "Your identity provider ended this sign-in")
	case err != nil:
		s.writeError(w, http.StatusServiceUnavailable, "CLI sign-in temporarily unavailable")
	default:
		s.writeJSON(w, http.StatusOK, map[string]string{"token": token, "stage": store.StagePending})
	}
}
