package auth

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// FactorLabel is the sealer label for mfa_factors.secret_enc (spec §7.3 rule 4).
const FactorLabel = "kyguard:mfa_factors"

// Attempt limits (spec §7.3 rule 5): failed codes per user across sessions inside the window,
// and per pending session. One counter covers step-up, break-glass login and per-action codes.
const (
	UserCodeLimit    = 10
	SessionCodeLimit = 5
	CodeWindow       = 15 * time.Minute
)

// ErrCodeRejected is every refused code: wrong, replayed, malformed or over a limit. Callers
// cannot tell them apart, so neither can a guesser.
var ErrCodeRejected = errors.New("TOTP code rejected")

// Factors seals TOTP secrets and checks codes against them.
type Factors struct {
	store  store.Store
	sealer recoveryclient.Sealer
}

func NewFactors(st store.Store, key []byte) (*Factors, error) {
	sealer, err := recoveryclient.NewAESGCMSealer(key, FactorLabel)
	if err != nil {
		return nil, err
	}
	return &Factors{store: st, sealer: sealer}, nil
}

// NewSecret returns a fresh TOTP secret and its sealed form for userID. The user ID is sealed
// with the secret, so a sealed value copied onto another user's row does not open.
func (f *Factors) NewSecret(userID string) (secret, sealed string, err error) {
	secret, err = totp.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	sealed, err = f.sealer.Seal([]byte(userID + "\x00" + secret))
	return secret, sealed, err
}

func (f *Factors) open(userID, sealed string) (string, error) {
	plain, err := f.sealer.Open(sealed)
	if err != nil {
		return "", err
	}
	owner, secret, ok := bytes.Cut(plain, []byte{0})
	if !ok || string(owner) != userID {
		return "", errors.New("auth: TOTP factor sealed for another user")
	}
	return string(secret), nil
}

// Check verifies code for userID and spends its counter. sessionHash names the pending session
// the code was entered in ("" outside one); that session is deleted at its SessionCodeLimit-th
// failure. The attempt is counted before the code is looked at, so while a limit is reached
// even a correct code fails. Only ErrCodeRejected means the code was refused; any other error
// is a storage failure.
func (f *Factors) Check(ctx context.Context, userID, sessionHash, code string) error {
	attempt, perUser, perSession, err := f.store.MFA().ReserveAttempt(ctx, userID, sessionHash, CodeWindow)
	if err != nil {
		return err
	}
	if perUser > UserCodeLimit || perSession > SessionCodeLimit {
		return f.reject(ctx, sessionHash, perSession)
	}
	factor, err := f.store.MFA().GetFactor(ctx, userID, store.FactorTOTP)
	if errors.Is(err, store.ErrNotFound) {
		return f.reject(ctx, sessionHash, perSession)
	}
	if err != nil {
		return err
	}
	secret, err := f.open(userID, factor.SecretEnc)
	if err != nil {
		return err
	}
	counter, ok := totp.Validate(secret, code, time.Now())
	if !ok || counter <= factor.LastCounter {
		return f.reject(ctx, sessionHash, perSession)
	}
	if err := f.store.MFA().SpendCounter(ctx, factor.ID, counter); errors.Is(err, store.ErrConflict) {
		return f.reject(ctx, sessionHash, perSession) // a concurrent request spent it first
	} else if err != nil {
		return err
	}
	return f.store.MFA().ReleaseAttempt(ctx, attempt)
}

func (f *Factors) reject(ctx context.Context, sessionHash string, perSession int) error {
	if sessionHash != "" && perSession >= SessionCodeLimit {
		if err := f.store.Sessions().DeleteSession(ctx, sessionHash); err != nil {
			return err
		}
	}
	return ErrCodeRejected
}
