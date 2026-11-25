package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// handleChangePassword changes a break-glass account's password, which needs the current
// password and a TOTP code (spec §7.5). All sessions are revoked atomically with the password
// update; the user signs in again afterward.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	user, _, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if user.AccountType != store.AccountBreakGlass {
		s.writeError(w, http.StatusConflict, "This account signs in through its identity provider and has no local password")
		return
	}
	if !s.allowPerIP(r, "password-change", 10, time.Minute) || !s.allowAttempt("password-change-user:"+user.ID, 5, time.Minute) {
		s.writeError(w, http.StatusTooManyRequests, "Too many password change attempts")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		TOTPCode        string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.NewPassword) > 1024 { // the current one is verified at any length
		s.writeError(w, http.StatusBadRequest, "Password is too long")
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.CurrentPassword == req.NewPassword {
		s.writeError(w, http.StatusBadRequest, "Choose a different password")
		return
	}
	ok, err := password.Verify(req.CurrentPassword, user.PasswordHash)
	if err != nil || !ok {
		s.writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}
	// Checked only after the password, like sign-in, so a password guess never spends codes.
	if err := s.factors.Check(r.Context(), user.ID, "", req.TOTPCode); err != nil {
		if errors.Is(err, auth.ErrCodeRejected) {
			if err := s.store.Audit().LogAudit(context.WithoutCancel(r.Context()), &store.AuditRecord{UserID: user.ID, Action: "auth.totp_failed", Resource: "password", Details: "severity=critical", IPAddress: s.requestIP(r)}); err != nil {
				s.writeError(w, http.StatusServiceUnavailable, "Audit unavailable")
				return
			}
			s.writeError(w, http.StatusUnauthorized, "Authenticator code is incorrect")
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable")
		return
	}
	hash, err := password.Hash(req.NewPassword)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to secure password")
		return
	}
	if err := s.store.Users().CompletePasswordChange(r.Context(), user.ID, user.PasswordHash, hash, s.requestIP(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusConflict, "Account changed; sign in again")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}
	_ = s.sessions.RevokeSession(r.Context(), w, r)
	s.writeJSON(w, http.StatusOK, map[string]bool{"password_changed": true, "login_required": true})
}
