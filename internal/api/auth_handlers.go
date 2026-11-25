package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// LoginRequest is the only local sign-in: a break-glass account's password and TOTP code
// together (spec §7.4).
type LoginRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	TOTPCode     string `json:"totp_code"`
	CaptchaToken string `json:"captcha_token,omitempty"`
}

func (s *Server) handlePoWChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	challenge, err := auth.GeneratePoWChallenge(s.config.Captcha.DifficultyPoW, s.config.Security.SessionSecret)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate PoW challenge")
		return
	}

	s.writeJSON(w, http.StatusOK, challenge)
}

// Per account and client: a password guess against one account from one client (IPv6 by
// /64). Keyed on both, so nobody elsewhere can lock the admin out by guessing at it.
const (
	loginAccountLimit  = 10
	loginAccountWindow = 15 * time.Minute
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	client := s.limiterIP(r)
	if !s.allowPerIP(r, "login", 20, time.Minute) {
		s.writeError(w, http.StatusTooManyRequests, "Too many login attempts")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" || req.TOTPCode == "" {
		s.writeError(w, http.StatusBadRequest, "Username, password and authenticator code are required")
		return
	}

	// Verify PoW CAPTCHA if enabled. A solved puzzle buys one attempt.
	if s.config.Captcha.Provider == "pow" {
		valid := false
		if s.store.Driver() == "postgres" {
			salt, expires, ok := auth.CheckPoWSolution(req.CaptchaToken, s.config.Security.SessionSecret)
			if ok {
				var err error
				valid, err = s.store.Coordination().SpendChallenge(r.Context(), salt, expires*1000+999)
				if err != nil {
					s.writeError(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable")
					return
				}
			}
		} else {
			valid = auth.VerifyPoWSolution(req.CaptchaToken, s.config.Security.SessionSecret, s.powSpent)
		}
		if !valid {
			s.writeError(w, http.StatusForbidden, "Security check failed. Please complete the CAPTCHA puzzle.")
			return
		}
	}

	// Reserved before any password hashing, so concurrent guesses cannot all slip past a
	// window none of them has filled yet. An exhausted window answers exactly like a wrong
	// password, for known and unknown names alike. The name is hashed so a key stays small.
	accountKey := "login-account:" + crypto.SHA256Hex([]byte(strings.ToLower(req.Username)))[:32] + "|" + client
	refund, allowed, err := s.reserveAttempt(r.Context(), accountKey, loginAccountLimit, loginAccountWindow)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable")
		return
	}
	if !allowed {
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	user, err := s.store.Users().GetUserByUsername(r.Context(), req.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		refund()
		s.writeError(w, http.StatusInternalServerError, "Authentication error")
		return
	}
	ok := false
	if user == nil || user.PasswordHash == "" {
		password.DummyVerify() // an unknown or password-less name costs what a wrong password costs
	} else {
		ok, _ = password.Verify(req.Password, user.PasswordHash)
	}
	// Every attempt is a critical audit record (spec §7.4); a failed write fails the sign-in.
	// A success's record is written in the session's own transaction.
	record := func(userID, outcome string) *store.AuditRecord {
		return &store.AuditRecord{UserID: userID, Action: "auth.break_glass_login", Resource: "session",
			Details: "severity=critical outcome=" + outcome, IPAddress: s.requestIP(r)}
	}
	audit := func(userID, outcome string) bool {
		if err := detachedWrite(r, func(ctx context.Context) error { return s.store.Audit().LogAudit(ctx, record(userID, outcome)) }); err != nil {
			s.writeError(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable")
			return false
		}
		return true
	}
	// A disabled account answers like a wrong password, so the status cannot enumerate it.
	// The TOTP counter is never touched before the password verifies.
	if !ok || user.Status != "active" {
		userID := ""
		if user != nil {
			userID = user.ID
		}
		if audit(userID, "bad_password") {
			s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		}
		return
	}
	if user.AccountType != store.AccountBreakGlass {
		if audit(user.ID, "not_break_glass") {
			s.writeError(w, http.StatusForbidden, "Sign in through your identity provider; local sign-in is for break-glass accounts only")
		}
		return
	}
	factorID, err := s.factors.Check(r.Context(), user.ID, "", req.TOTPCode)
	if err != nil {
		outcome, status, msg := "bad_code", http.StatusUnauthorized, "Invalid credentials"
		if !errors.Is(err, auth.ErrCodeRejected) {
			outcome, status, msg = "error", http.StatusServiceUnavailable, "Authentication temporarily unavailable"
		}
		if audit(user.ID, outcome) {
			s.writeError(w, status, msg)
		}
		return
	}
	refund() // only failures stay counted

	if err := detachedWrite(r, func(ctx context.Context) error {
		_, _, err := s.sessions.IssueBreakGlassSession(ctx, w, r, user, factorID, record(user.ID, "success"))
		return err
	}); err != nil {
		// ErrNotFound: the password or factor was replaced since it was checked.
		if errors.Is(err, store.ErrNotFound) && audit(user.ID, "superseded") {
			s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		} else if !errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable")
		}
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"user":          user,
	})
}

// handleBreakGlassReason records why a break-glass session exists. It is set once and is
// required before the session's first privileged action (spec §7.4).
func (s *Server) handleBreakGlassReason(w http.ResponseWriter, r *http.Request) {
	user, sess, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if user.AccountType != store.AccountBreakGlass {
		s.writeError(w, http.StatusForbidden, "Only a break-glass session gives a reason")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 500 {
		s.writeError(w, http.StatusBadRequest, "Give a reason of 1 to 500 characters")
		return
	}
	// The reason and its audit record commit together, so a failed audit leaves no reason
	// and the user can simply retry.
	rec := &store.AuditRecord{UserID: user.ID, Action: "break_glass.reason", Resource: "session", Details: "severity=critical reason=" + strconv.Quote(req.Reason), IPAddress: s.requestIP(r)}
	if err := detachedWrite(r, func(ctx context.Context) error {
		return s.store.Sessions().SetBreakGlassReason(ctx, sess.TokenHash, req.Reason, rec)
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, "This session already has a reason")
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, "Failed to record the reason")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"recorded": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	_ = s.sessions.RevokeSession(r.Context(), w, r)
	s.writeJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, sess, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
		return
	}
	me := map[string]any{"authenticated": true, "user": user}
	if user.AccountType == store.AccountBreakGlass { // drives the persistent banner
		me["break_glass"] = map[string]any{"reason": sess.BreakGlassReason, "expires_at": sess.ExpiresAt}
	}
	s.writeJSON(w, http.StatusOK, me)
}
