package store

import (
	"time"
)

// User represents an identity within the system.
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	PasswordHash string `json:"-"`            // Never serialized to JSON
	Role         string `json:"role"`         // "admin", "user", "manager"
	Status       string `json:"status"`       // "active", "suspended", "inactive"
	SSOProvider  string `json:"sso_provider"` // "local", "kysignon", "oidc", "scim"
	SSOSubject   string `json:"sso_subject,omitempty"`
	// SSOIssuer is the identity provider that vouches for SSOSubject; the account's identity
	// is the pair (spec §7.2). SCIM rows take the configured SCIM issuer.
	SSOIssuer string `json:"-"`
	// AccountType is "sso" or "break_glass"; only break-glass accounts sign in with a
	// password, and only with a TOTP code (spec §7.4). Empty is stored as "sso".
	AccountType string `json:"account_type"`
	// SCIMManaged marks an account SCIM created; SCIM can see and change only these. It
	// survives adoption by a KyIdentity sign-in, which switches SSOProvider to "kysignon".
	SCIMManaged        bool       `json:"-"`
	PushDeviceID       string     `json:"push_device_id,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	// SCIMAttributes, when set, are synced user attributes ("" clears one) that the same
	// transaction as the user write applies (spec §8.2). Never stored on the row.
	SCIMAttributes map[string]string `json:"-"`
}

// Session represents an active authenticated user session.
type Session struct {
	TokenHash string `json:"token_hash"`
	UserID    string `json:"user_id"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
	// CreatedAt is when the credentials behind this session were verified.
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// SSOSID is the identity provider's sid for an SSO login; empty for local sign-in.
	SSOSID string `json:"-"`
	// SSOIssuer is the issuer of the SSO login; the logout fences are keyed by it.
	SSOIssuer string `json:"-"`
	// Stage is "pending" until TOTP step-up exchanges the session, then "active" (§7.3).
	// Empty is stored as "active".
	Stage string `json:"-"`
	// StepupAt is the last TOTP verification for this session; nil when none.
	StepupAt *time.Time `json:"-"`
	// BreakGlassReason is the reason a break-glass session gave before its first privileged
	// action (§7.4).
	BreakGlassReason string `json:"-"`
	// MFAAsserted records that a pending session's ID token asserted MFA (spec §7.2), the
	// condition for enrolling a first factor.
	MFAAsserted bool `json:"-"`
	// PendingSecretEnc is the sealed TOTP secret offered to a pending session for enrollment.
	PendingSecretEnc string `json:"-"`
	// FactorID, when set, is the factor whose code authorized this session; CreateSession
	// refuses it once that factor has been replaced. Not stored.
	FactorID string `json:"-"`
	// Audit, when set, is written in the same transaction as the session. Not stored.
	Audit *AuditRecord `json:"-"`
}

// MFAFactor is one enrolled local factor. SecretEnc is the TOTP secret sealed under the
// deployment key; LastCounter is the highest TOTP counter accepted so far.
type MFAFactor struct {
	ID          string
	UserID      string
	Kind        string
	SecretEnc   string
	LastCounter int64
	CreatedAt   time.Time
}

// Group represents a SCIM/RBAC user group.
type Group struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	ExternalID  string    `json:"external_id,omitempty"`
	Members     []string  `json:"members,omitempty"` // User IDs
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuditRecord logs security and operational events with tamper-evident structure.
type AuditRecord struct {
	ID        int64     `json:"id"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"` // e.g. "auth.login", "scim.user_created"
	Resource  string    `json:"resource"`
	Details   string    `json:"details,omitempty"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
}

// Setting represents a durable server-wide key-value configuration entry.
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}
