package broker

import (
	"context"
	"errors"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// Deterministic connector outcomes. Any other error is ambiguous.
var (
	// ErrAuthFailed is a deterministic authentication failure (AD 52e, SSH denied): the
	// broker stops after that one attempt (§4.6).
	ErrAuthFailed = errors.New("broker: authentication denied")
	// ErrRefused is a deterministic refusal that leaves the target unchanged (password
	// policy, minimum age, an unrecognized prompt before the new password, §4.4).
	ErrRefused = errors.New("broker: target refused the change")
)

// Connector reaches one connector type's targets, dialing only what the verified
// descriptor names (§3.3).
type Connector interface {
	// Login authenticates as the descriptor's identity with password.
	Login(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte) (Session, error)
	// Verify logs in afresh with password and checks the change took effect against the
	// baseline read before the write.
	Verify(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte, baseline string) error
}

// Session is an authenticated connection.
type Session interface {
	// Baseline reads the state the verification compares against (AD pwdLastSet and
	// msDS-KeyVersionNumber).
	Baseline(ctx context.Context) (string, error)
	// Change performs the self-change. It calls commit immediately before the first byte of
	// the new password leaves; if commit fails, nothing is sent and Change returns its error.
	Change(ctx context.Context, oldPassword, newPassword []byte, commit func() error) error
	Close() error
}

// AgeReporter is a Session that can read the account's last change and the target's
// minimum password age (§4.4).
type AgeReporter interface {
	PasswordAge(ctx context.Context) (lastChange time.Time, minAge time.Duration, err error)
}
