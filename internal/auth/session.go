package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

const (
	SessionCookieName = "ky_session"
	CSRFCookieName    = "ky_csrf"
	HeaderCSRF        = "X-CSRF-Token"
)

var ErrPasswordChangeRequired = errors.New("password change required")

// ErrStepUpRequired refuses a pending session anywhere but its own routes (spec §7.3).
var ErrStepUpRequired = errors.New("TOTP step-up required")

// PendingTTL is how long a pending session waits for its step-up; SSOSessionTTL is how long the
// active session it becomes lasts, without sliding (spec §7.3).
const (
	PendingTTL    = 5 * time.Minute
	SSOSessionTTL = 12 * time.Hour
)

// pendingAllowed is what a pending session authenticates: its identity, sign-out and step-up.
func pendingAllowed(r *http.Request) bool {
	return (r.Method == http.MethodGet && r.URL.Path == "/api/auth/me") ||
		(r.Method == http.MethodPost && r.URL.Path == "/api/auth/logout") ||
		strings.HasPrefix(r.URL.Path, "/api/auth/stepup/")
}

// CookieName is the name a cookie has on this server: with host cookies (an https app URL,
// config.SecurityConfig.HostCookies) it carries the __Host- prefix, which
// the browser accepts only from this host (Secure, Path=/, no Domain), so a sibling subdomain
// cannot plant a session, CSRF or SSO state cookie. Otherwise the bare name.
func CookieName(name string, host bool) string {
	if host {
		return "__Host-" + name
	}
	return name
}

type SessionManager struct {
	store  store.Store
	config config.SecurityConfig
}

func NewSessionManager(st store.Store, cfg config.SecurityConfig) *SessionManager {
	return &SessionManager{
		store:  st,
		config: cfg,
	}
}

// BreakGlassTTL is a break-glass session's fixed lifetime; it never slides (spec §7.4).
const BreakGlassTTL = 30 * time.Minute

// IssueSession creates an active session for credentials verified just now and writes the
// HttpOnly cookie + CSRF token.
func (sm *SessionManager) IssueSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User) (*store.Session, string, error) {
	return sm.issue(ctx, w, r, user, time.Now().UTC(), "", "", 0, nil, "", nil)
}

// IssueBreakGlassSession issues the session for a break-glass login whose password and TOTP
// code (from factorID) were both verified just now: active, stepped up now, and ending after
// BreakGlassTTL. audit is written in the session's transaction; cookies are set only after it
// commits.
func (sm *SessionManager) IssueBreakGlassSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, factorID string, audit *store.AuditRecord) (*store.Session, string, error) {
	now := time.Now().UTC()
	return sm.issue(ctx, w, r, user, now, "", "", BreakGlassTTL, &now, factorID, audit)
}

// IssuePendingSession is what an SSO callback issues (spec §7.3): a restricted pending session
// bound to the verified login (issuer, sid, the token's original iat) that only TOTP step-up
// turns into an active one. mfa records whether the ID token asserted MFA.
func (sm *SessionManager) IssuePendingSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, issuer, sid string, issuedAt time.Time, mfa bool) (*store.Session, string, error) {
	return sm.create(ctx, w, user, &store.Session{
		UserID: user.ID, UserAgent: r.UserAgent(), IPAddress: ClientIP(r, sm.config.TrustedProxies),
		CreatedAt: issuedAt.UTC(), ExpiresAt: time.Now().UTC().Add(PendingTTL),
		SSOSID: sid, SSOIssuer: issuer, Stage: store.StagePending, MFAAsserted: mfa,
	}, nil)
}

// ExchangePending deletes the pending session and issues a new active one with a new token
// (spec §7.3 rule 2): stepped up now, ending SSOSessionTTL later, and still bound to the
// pending session's login (issuer, sid, original iat) so the logout fences reach it.
// factorID names the factor whose code was checked; newFactor is a first factor enrolled in
// the same transaction. audit commits with the session.
func (sm *SessionManager) ExchangePending(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, pending *store.Session, factorID string, newFactor *store.MFAFactor, audit *store.AuditRecord) (*store.Session, string, error) {
	now := time.Now().UTC()
	active := &store.Session{
		UserID: user.ID, UserAgent: r.UserAgent(), IPAddress: ClientIP(r, sm.config.TrustedProxies),
		CreatedAt: pending.CreatedAt, ExpiresAt: now.Add(SSOSessionTTL), StepupAt: &now,
		SSOSID: pending.SSOSID, SSOIssuer: pending.SSOIssuer, FactorID: factorID, Audit: audit,
	}
	return sm.create(ctx, w, user, active, func(s *store.Session) error {
		return sm.store.Sessions().ExchangeSession(ctx, pending.TokenHash, user.PasswordHash, s, newFactor)
	})
}

// IssueSSOSession issues a session for an SSO login the issuer names by sid and dates it by
// the ID token's issuedAt, so a back-channel logout for that (issuer, sid) or (issuer,
// subject) ends it.
// It fails with store.ErrSSOSessionEnded when the provider already ended that login.
func (sm *SessionManager) IssueSSOSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, issuer, sid string, issuedAt time.Time) (*store.Session, string, error) {
	return sm.issue(ctx, w, r, user, issuedAt.UTC(), issuer, sid, 0, nil, "", nil)
}

func (sm *SessionManager) issue(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, authenticatedAt time.Time, issuer, sid string, ttl time.Duration, stepupAt *time.Time, factorID string, audit *store.AuditRecord) (*store.Session, string, error) {
	if ttl <= 0 {
		ttl = sm.config.SessionTTL
	}
	if ttl <= 0 {
		ttl = SSOSessionTTL
	}

	sess := &store.Session{
		UserID:    user.ID,
		UserAgent: r.UserAgent(),
		IPAddress: ClientIP(r, sm.config.TrustedProxies),
		CreatedAt: authenticatedAt,
		ExpiresAt: time.Now().UTC().Add(ttl),
		SSOSID:    sid,
		SSOIssuer: issuer,
		StepupAt:  stepupAt,
		FactorID:  factorID,
		Audit:     audit,
	}

	return sm.create(ctx, w, user, sess, nil)
}

// create stores sess under a new token (through save, or CreateSession when nil) and only then
// sets the session and CSRF cookies.
func (sm *SessionManager) create(ctx context.Context, w http.ResponseWriter, user *store.User, sess *store.Session, save func(*store.Session) error) (*store.Session, string, error) {
	rawToken := crypto.RandomHex(32)
	sess.TokenHash = crypto.SHA256Hex([]byte(rawToken))
	if save == nil {
		save = func(s *store.Session) error { return sm.store.Sessions().CreateSession(ctx, s, user.PasswordHash) }
	}
	if err := save(sess); err != nil {
		return nil, "", err
	}

	// Set HttpOnly session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName(SessionCookieName, sm.config.HostCookies),
		Value:    rawToken,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   sm.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   sm.config.CookieDomain,
	})

	// Generate CSRF token for state-modifying endpoints
	csrfToken := crypto.RandomHex(24)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName(CSRFCookieName, sm.config.HostCookies),
		Value:    csrfToken,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: false, // Read by JS to put into X-CSRF-Token header
		Secure:   sm.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   sm.config.CookieDomain,
	})

	return sess, rawToken, nil
}

// AuthenticateRequest extracts the session token from cookie or Authorization header and returns the user.
func (sm *SessionManager) AuthenticateRequest(r *http.Request) (*store.User, *store.Session, error) {
	var rawToken string

	// 1. Check Bearer token header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		rawToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// 2. Fallback to HttpOnly cookie
	if rawToken == "" {
		if cookie, err := r.Cookie(CookieName(SessionCookieName, sm.config.HostCookies)); err == nil && cookie.Value != "" {
			rawToken = cookie.Value
		}
	}

	if rawToken == "" {
		return nil, nil, store.ErrNotFound
	}

	tokenHash := crypto.SHA256Hex([]byte(rawToken))
	sess, err := sm.store.Sessions().GetSession(r.Context(), tokenHash)
	if err != nil {
		return nil, nil, err
	}

	user, err := sm.store.Users().GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	if user.Status != "active" {
		_ = sm.store.Sessions().DeleteSession(r.Context(), tokenHash)
		return nil, nil, store.ErrNotFound
	}

	// The password transaction may revoke the session between the two reads.
	// Recheck after loading the user so an old session cannot inherit a cleared flag.
	if _, err := sm.store.Sessions().GetSession(r.Context(), tokenHash); err != nil {
		return nil, nil, err
	}

	if sess.Stage == store.StagePending && !pendingAllowed(r) {
		return nil, nil, ErrStepUpRequired
	}
	// A restricted session never authorizes product operations or private settings.
	if user.MustChangePassword && !((r.Method == http.MethodGet && r.URL.Path == "/api/auth/me") || (r.Method == http.MethodPost && (r.URL.Path == "/api/auth/change-password" || r.URL.Path == "/api/auth/logout"))) {
		return nil, nil, ErrPasswordChangeRequired
	}
	return user, sess, nil
}

// ValidateCSRF compares the X-CSRF-Token header with the CSRF cookie (named per CookieName).
func ValidateCSRF(r *http.Request, host bool) bool {
	cookie, err := r.Cookie(CookieName(CSRFCookieName, host))
	if err != nil || cookie.Value == "" {
		return false
	}
	header := r.Header.Get(HeaderCSRF)
	return len(header) == len(cookie.Value) && subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

// RevokeSession deletes the active session and clears the browser cookies.
func (sm *SessionManager) RevokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	rawToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		rawToken = ""
	}
	if rawToken == "" {
		if cookie, err := r.Cookie(CookieName(SessionCookieName, sm.config.HostCookies)); err == nil {
			rawToken = cookie.Value
		}
	}

	if rawToken != "" {
		tokenHash := crypto.SHA256Hex([]byte(rawToken))
		_ = sm.store.Sessions().DeleteSession(ctx, tokenHash)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName(SessionCookieName, sm.config.HostCookies),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   sm.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   sm.config.CookieDomain,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName(CSRFCookieName, sm.config.HostCookies),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		Secure:   sm.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   sm.config.CookieDomain,
	})

	return nil
}
