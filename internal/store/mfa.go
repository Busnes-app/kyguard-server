package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/crypto"
)

const (
	AccountSSO        = "sso"
	AccountBreakGlass = "break_glass"
	StagePending      = "pending"
	StageActive       = "active"
	FactorTOTP        = "totp"

	// MaxBreakGlass is the most break-glass accounts a deployment may hold (spec §7.4).
	MaxBreakGlass = 5
)

// ErrBreakGlassLimit refuses a sixth break-glass account.
var ErrBreakGlassLimit = errors.New("at most 5 break-glass accounts may exist")

// MFAStore holds local factors and the failed-code counters that bound guessing (spec §7.3).
type MFAStore interface {
	// CreateBreakGlass creates a break-glass admin, its TOTP factor and the audit record in one
	// transaction, refusing with ErrBreakGlassLimit once MaxBreakGlass exist.
	CreateBreakGlass(ctx context.Context, u *User, f *MFAFactor, audit *AuditRecord) error
	// ReplaceFactor installs a new TOTP secret under a new factor ID (counter reset), deletes
	// the user's sessions and writes audit, in one transaction holding the user row, so a
	// session authorized by the old factor cannot be created afterwards. ErrNotFound when the
	// user has no factor.
	ReplaceFactor(ctx context.Context, userID, newFactorID, secretEnc string, audit *AuditRecord) error
	GetFactor(ctx context.Context, userID, kind string) (*MFAFactor, error)
	// DeleteFactor removes an SSO user's TOTP factor, ends the user's sessions and writes audit
	// in one transaction (spec §7.3 rule 6; the next sign-in re-enrolls). ErrNotFound when the
	// user is not an SSO account or has no factor.
	DeleteFactor(ctx context.Context, userID string, audit *AuditRecord) error
	// SpendCounter records counter as used: a compare-and-swap that succeeds only while
	// counter is above the stored last_counter, so a code is accepted at most once.
	// ErrConflict when it is not.
	SpendCounter(ctx context.Context, factorID string, counter int64) error
	// ReserveAttempt records one code attempt for the user (and session, when non-empty) and
	// returns the attempts inside window, this one included. The caller releases it on success;
	// a failure stays counted.
	ReserveAttempt(ctx context.Context, userID, sessionHash string, window time.Duration) (id string, userCount, sessionCount int, err error)
	ReleaseAttempt(ctx context.Context, id string) error
}

type mfaStore struct{ store *SQLStore }

func (s *SQLStore) MFA() MFAStore { return &mfaStore{store: s} }

func (m *mfaStore) CreateBreakGlass(ctx context.Context, u *User, f *MFAFactor, audit *AuditRecord) error {
	s := m.store
	now := time.Now().UTC()
	u.AccountType, u.CreatedAt, u.UpdatedAt = AccountBreakGlass, now, now
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.driver == "postgres" {
		// Serializes concurrent creates so the count below cannot be raced past the limit.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(3, hashtext('kyguard:break-glass'))`); err != nil {
			return err
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(1) FROM users WHERE account_type = ?`), AccountBreakGlass).Scan(&n); err != nil {
		return err
	}
	if n >= MaxBreakGlass {
		return ErrBreakGlassLimit
	}
	if err := s.users.checkUsernameFree(ctx, tx, u.Username, ""); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO users (id, username, email, display_name, password_hash, role, status, sso_provider, sso_subject, scim_managed, push_device_id, must_change_password, created_at, updated_at, account_type)
VALUES (?, ?, ?, ?, ?, ?, ?, 'local', '', ?, '', ?, ?, ?, ?)`),
		u.ID, u.Username, u.Email, u.DisplayName, u.PasswordHash, u.Role, u.Status, false, false, now, now, AccountBreakGlass); err != nil {
		return uniqueErr(err)
	}
	f.UserID, f.Kind, f.CreatedAt, f.LastCounter = u.ID, FactorTOTP, now, -1
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO mfa_factors (id, user_id, kind, secret_enc, last_counter, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
		f.ID, f.UserID, f.Kind, f.SecretEnc, f.LastCounter, now); err != nil {
		return uniqueErr(err)
	}
	audit.UserID = u.ID
	if err := s.insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return uniqueErr(tx.Commit())
}

func (m *mfaStore) ReplaceFactor(ctx context.Context, userID, newFactorID, secretEnc string, audit *AuditRecord) error {
	s := m.store
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	// The same row lock CreateSession takes (withPassword), so the two serialize.
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE users SET updated_at = ? WHERE id = ?`), now, userID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, s.rebind(`UPDATE mfa_factors SET id = ?, secret_enc = ?, last_counter = -1, created_at = ? WHERE user_id = ? AND kind = ?`), newFactorID, secretEnc, now, userID, FactorTOTP)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM sessions WHERE user_id = ?`), userID); err != nil {
		return err
	}
	audit.UserID = userID
	if err := s.insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *mfaStore) DeleteFactor(ctx context.Context, userID string, audit *AuditRecord) error {
	s := m.store
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The user row lock is the one every session issuance holds (withPassword), so an exchange
	// authorized by this factor either commits first, and its session is deleted below, or
	// waits and then finds the factor gone. Break-glass factors are reset only on the host.
	lock, err := tx.ExecContext(ctx, s.rebind(`UPDATE users SET id = id WHERE id = ? AND account_type = ?`), userID, AccountSSO)
	if err != nil {
		return err
	}
	if n, _ := lock.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	res, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM mfa_factors WHERE kind = ? AND user_id = ?`), FactorTOTP, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM sessions WHERE user_id = ?`), userID); err != nil {
		return err
	}
	if err := s.insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *mfaStore) GetFactor(ctx context.Context, userID, kind string) (*MFAFactor, error) {
	var f MFAFactor
	err := m.store.db.QueryRowContext(ctx, m.store.rebind(`SELECT id, user_id, kind, secret_enc, last_counter, created_at FROM mfa_factors WHERE user_id = ? AND kind = ?`), userID, kind).
		Scan(&f.ID, &f.UserID, &f.Kind, &f.SecretEnc, &f.LastCounter, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (m *mfaStore) SpendCounter(ctx context.Context, factorID string, counter int64) error {
	res, err := m.store.db.ExecContext(ctx, m.store.rebind(`UPDATE mfa_factors SET last_counter = ? WHERE id = ? AND last_counter < ?`), counter, factorID, counter)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return nil
}

func (m *mfaStore) ReserveAttempt(ctx context.Context, userID, sessionHash string, window time.Duration) (string, int, int, error) {
	s := m.store
	now := time.Now().UTC()
	id := crypto.RandomHex(16)
	if _, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM totp_attempts WHERE created_at < ?`), now.Add(-window)); err != nil {
		return "", 0, 0, err
	}
	// Committed before counting: two concurrent attempts each see the other, so a race can
	// only refuse both, never admit one past the limit.
	if _, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO totp_attempts (id, user_id, session_hash, created_at) VALUES (?, ?, ?, ?)`), id, userID, sessionHash, now); err != nil {
		return "", 0, 0, err
	}
	var users, sessions int
	if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT
 (SELECT COUNT(1) FROM totp_attempts WHERE user_id = ? AND created_at >= ?),
 (SELECT COUNT(1) FROM totp_attempts WHERE session_hash = ? AND session_hash <> '')`), userID, now.Add(-window), sessionHash).Scan(&users, &sessions); err != nil {
		return "", 0, 0, err
	}
	return id, users, sessions, nil
}

func (m *mfaStore) ReleaseAttempt(ctx context.Context, id string) error {
	_, err := m.store.db.ExecContext(ctx, m.store.rebind(`DELETE FROM totp_attempts WHERE id = ?`), id)
	return err
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}
