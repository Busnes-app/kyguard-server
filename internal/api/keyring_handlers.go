package api

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"golang.org/x/oauth2"
)

// The registered callback is a browser page. It keeps the sealed subkey in the
// fragment, clears the URL, then posts only the OAuth code and state to exchange.
const keyringCallback = "/vault/keyring-callback"

func (s *Server) keyringEnabled() bool {
	return s.config.Server.BrowserVault && s.config.SSO.Enabled && s.config.SSO.KySignOnKeyringOrg != ""
}

func (s *Server) keyringCookie(w http.ResponseWriter, state, value string, age int) {
	http.SetCookie(w, &http.Cookie{
		Name: auth.CookieName("ky_keyring_"+state, s.config.Security.HostCookies), Value: value,
		Path: "/", Secure: s.config.Security.CookieSecure, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: age,
	})
}

func (s *Server) handleKeyringStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.keyringEnabled() {
		s.writeError(w, http.StatusNotFound, "Suite keyring sign-in is disabled")
		return
	}
	if !s.allowAttempt("keyring-start:"+s.limiterIP(r), 20, time.Minute) {
		s.writeError(w, http.StatusTooManyRequests, "Try again shortly")
		return
	}
	var in struct {
		PublicKey pqcrypto.B64 `json:"keyring_pk"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if decodeStrict(r, &in) != nil {
		s.writeError(w, http.StatusBadRequest, "Expected an X-Wing public key")
		return
	}
	if _, err := xwing.ParsePublicKey(in.PublicKey); err != nil {
		s.writeError(w, http.StatusBadRequest, "Expected an X-Wing public key")
		return
	}
	state, nonce, verifier := crypto.RandomHex(16), crypto.RandomHex(16), oauth2.GenerateVerifier()
	redirect := s.config.Server.AppURL + keyringCallback
	authURL, err := s.kysignon.BuildAuthURL(r.Context(), redirect, state, verifier, nonce)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Could not start KyIdentity sign-in")
		return
	}
	u, err := url.Parse(authURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		s.writeError(w, http.StatusServiceUnavailable, "KyIdentity keyring requires HTTPS authorization")
		return
	}
	q := u.Query()
	q.Set("keyring_pk", pqcrypto.EncodeB64(in.PublicKey))
	u.RawQuery = q.Encode()
	s.keyringCookie(w, state, verifier+"."+nonce, 300)
	s.writeJSON(w, http.StatusOK, map[string]string{
		"authorization_url": u.String(), "state": state, "nonce": nonce, "redirect_uri": redirect,
		"issuer": strings.TrimRight(s.config.SSO.KySignOnIssuer, "/"), "client_id": s.config.SSO.KySignOnClientID,
	})
}

func (s *Server) handleKeyringExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.keyringEnabled() {
		s.writeError(w, http.StatusNotFound, "Suite keyring sign-in is disabled")
		return
	}
	var in struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if decodeStrict(r, &in) != nil || len(in.State) != 32 || in.Code == "" || len(in.Code) > 2048 {
		s.writeError(w, http.StatusBadRequest, "Invalid KyIdentity callback")
		return
	}
	if _, err := hex.DecodeString(in.State); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid KyIdentity callback")
		return
	}
	c, err := r.Cookie(auth.CookieName("ky_keyring_"+in.State, s.config.Security.HostCookies))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid or expired KyIdentity state")
		return
	}
	s.keyringCookie(w, in.State, "", -1)
	verifier, nonce, ok := strings.Cut(c.Value, ".")
	if !ok || verifier == "" || nonce == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid KyIdentity state")
		return
	}
	claims, err := s.kysignon.ExchangeCode(r.Context(), in.Code, verifier, s.config.Server.AppURL+keyringCallback, nonce)
	if err != nil || claims.CheckFresh(time.Now()) != nil {
		s.writeError(w, http.StatusUnauthorized, "KyIdentity sign-in could not be verified")
		return
	}
	org := s.config.SSO.KySignOnKeyringOrg
	// Single-tenant KyIdentity omits org_id from ID tokens. Its configured opaque
	// organization ID still has to authenticate in the browser's HPKE transcript.
	if claims.HasOrganization && claims.Organization != org {
		s.writeError(w, http.StatusForbidden, "This KyIdentity organization is not configured for KyGuard")
		return
	}
	user, status, message := s.ssoAccount(r, "kysignon", claims)
	if user == nil {
		s.writeError(w, status, message)
		return
	}
	_, _, err = s.sessions.IssuePendingSession(r.Context(), w, r, user, claims.Issuer, claims.SessionID, claims.IssuedAt, claims.MFA)
	if errors.Is(err, store.ErrSSOSessionEnded) {
		s.writeError(w, http.StatusUnauthorized, "SSO session already ended")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Session creation failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{
		"issuer": claims.Issuer, "org_id": org, "subject": claims.Subject,
		"user_id": user.ID, "client_id": s.config.SSO.KySignOnClientID, "nonce": nonce,
	})
}
