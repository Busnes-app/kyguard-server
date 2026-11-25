package broker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

var (
	bucketManifests   = []byte("manifests")   // 8-byte seq -> canonical manifest, acceptance order
	bucketDescriptors = []byte("descriptors") // digest -> canonical target descriptor
	bucketAccounts    = []byte("accounts")    // account_id -> JSON Account
	bucketBurned      = []byte("burned")      // request_id -> RFC 3339 expiry (§3.7)
	bucketChallenges  = []byte("challenges")  // request_id -> JSON Challenge, single use (§3.7)
)

// Rotation states (§4.2).
const (
	StatePrepared             = "prepared"
	StateMutating             = "mutating"
	StateWriteOutcomeUnknown  = "write_outcome_unknown"
	StateTargetVerified       = "target_verified"
	StateDependenciesComplete = "dependencies_complete"
	StateReleaseAuthorized    = "release_authorized"
	StateAborted              = "aborted"
)

// Health values (§8.1) the broker reports.
const (
	HealthHealthy         = "healthy"
	HealthRotationFailed  = "rotation_failed"
	HealthAuthFailed      = "auth_failed"
	HealthQuarantined     = "quarantined"
	HealthNeedsEnrollment = "needs_enrollment"
)

// Account is the broker's journal record for one account. It holds ciphertext only.
type Account struct {
	ID pqcrypto.UUID `json:"id"`
	// Chains is the broker's copy of the account's envelopes and receipts (§3.7).
	Chains         []ChainCopy      `json:"chains"`
	HighestVersion pqcrypto.Counter `json:"highest_version"`
	Health         string           `json:"health"`
	HealthReason   string           `json:"health_reason,omitempty"`
	Quarantined    bool             `json:"quarantined"`
	// Schedule floor inputs (§3.4).
	PolicyEpoch       pqcrypto.Counter `json:"policy_epoch"`
	PolicyPersistedAt time.Time        `json:"policy_persisted_at"`
	LastConsumedDue   time.Time        `json:"last_consumed_due"`
	CurrentCommitAt   time.Time        `json:"current_commit_at"`
	// Refusal retry state (§4.4). The minimum-age deadline carries across policy epochs.
	Refusals       int       `json:"refusals,omitempty"`
	NextAttemptAt  time.Time `json:"next_attempt_at"`
	MinAgeSeconds  int64     `json:"min_age_seconds,omitempty"`
	MinAgeDeadline time.Time `json:"min_age_deadline"`
	// Run is the latest rotation attempt.
	Run *Run `json:"run,omitempty"`
	// Enrollment is the latest enrollment attempt (§4.5).
	Enrollment *Enrollment `json:"enrollment,omitempty"`
	// Lease is the latest checkout lease (§3.6).
	Lease *Lease `json:"lease,omitempty"`
}

// Lease states (§3.6).
const (
	LeaseActive          = "active"
	LeaseRotationPending = "rotation_pending"
	LeaseClosed          = "closed"
)

// Lease is an ephemeral checkout lease. Its cleanup rotation is the only rotation path while
// it is rotation_pending, and only an attempt that appends release closes it.
type Lease struct {
	RequestID     pqcrypto.UUID    `json:"request_id"`
	Tx            pqcrypto.B64     `json:"tx"`
	TxDigest      pqcrypto.HexID   `json:"tx_digest"`
	SecretVersion pqcrypto.Counter `json:"secret_version"`
	EncKeyID      pqcrypto.HexID   `json:"enc_key_id"`
	OpenedAt      time.Time        `json:"opened_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
	State         string           `json:"state"`
	CloseReason   string           `json:"close_reason,omitempty"`
	Attempt       pqcrypto.Counter `json:"attempt"`
	NextAttemptAt time.Time        `json:"next_attempt_at"`
	Mirrored      bool             `json:"mirrored,omitempty"` // the Control Plane holds this state
}

// Open reports whether the lease is not closed.
func (l *Lease) Open() bool { return l != nil && l.State != LeaseClosed }

// Challenge is a single-use broker challenge awaiting its possession proof.
type Challenge struct {
	Purpose   string        `json:"purpose"`
	Challenge pqcrypto.B64  `json:"challenge"`
	Account   pqcrypto.UUID `json:"account"`
	Tx        pqcrypto.B64  `json:"tx"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// Enrollment is one enroll transaction, journaled from its acceptance (§4.5 step 2).
type Enrollment struct {
	OperationID pqcrypto.UUID `json:"operation_id"`
	Tx          pqcrypto.B64  `json:"tx"`
	Candidate   pqcrypto.B64  `json:"candidate"`
	// AcceptAck is journaled after the Control Plane accepted the reservation; only then is
	// the request ID burned and the one bind allowed. VerifyStarted is journaled before
	// that bind; a restart that finds it without VerifyDone fails without binding again.
	AcceptAck     bool `json:"accept_ack,omitempty"`
	VerifyStarted bool `json:"verify_started,omitempty"`
	VerifyDone    bool `json:"verify_done,omitempty"`
	Verified      bool `json:"verified,omitempty"`
	// Receipts to deliver: the aborts of superseded envelopes and vault_commit, or abort
	// (enrollment_failed). Sent once the Control Plane acknowledged them.
	Receipts []pqcrypto.B64 `json:"receipts,omitempty"`
	Sent     bool           `json:"sent,omitempty"`
}

// Open reports whether the enrollment still blocks the account.
func (e *Enrollment) Open() bool { return e != nil && !e.Sent }

// ChainCopy is an envelope and its receipts as canonical bytes.
type ChainCopy struct {
	Envelope pqcrypto.B64   `json:"envelope"`
	Receipts []pqcrypto.B64 `json:"receipts"`
}

// Run is one rotation attempt, journaled from its first durable state (§3.4, §4.2, §4.3).
type Run struct {
	OperationID   pqcrypto.UUID    `json:"operation_id"`
	PolicyEpoch   pqcrypto.Counter `json:"policy_epoch"`
	Occurrence    pqcrypto.Counter `json:"occurrence"`
	Attempt       pqcrypto.Counter `json:"attempt"`
	Due           time.Time        `json:"due"`
	State         string           `json:"state"`
	SecretVersion pqcrypto.Counter `json:"secret_version"`
	NewEnvelope   pqcrypto.B64     `json:"new_envelope"`
	OldEnvelopeID pqcrypto.UUID    `json:"old_envelope_id,omitempty"`
	// Intent is the canonical mutating intent once journaled; AckReceived is journaled
	// only after the Control Plane acknowledged it, and the write is sent only after that.
	Intent      pqcrypto.B64 `json:"intent,omitempty"`
	AckReceived bool         `json:"ack_received,omitempty"`
	// ProbeRecorded is journaled before the one P_new probe is sent; ProbeDone after its
	// result. A recorded probe without a result counts as used.
	ProbeRecorded bool   `json:"probe_recorded,omitempty"`
	ProbeDone     bool   `json:"probe_done,omitempty"`
	Reason        string `json:"reason,omitempty"`
	// Receipts are the run's signed receipts; Sent once the Control Plane acknowledged them.
	Receipts []pqcrypto.B64 `json:"receipts,omitempty"`
	Sent     bool           `json:"sent,omitempty"`
	// Lease is the request ID of the lease this cleanup rotation closes, if any.
	Lease pqcrypto.UUID `json:"lease,omitempty"`
}

// Open reports whether the run still blocks the account (§4.2 blocking rule).
func (r *Run) Open() bool {
	return r != nil && r.State != StateReleaseAuthorized && r.State != StateAborted
}

func seqKey(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

func (j *Journal) init() error {
	return j.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketManifests, bucketDescriptors, bucketAccounts, bucketBurned, bucketChallenges} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// Trust replays the pinned bundle and every journaled manifest in order.
func (j *Journal) Trust() (*pqcrypto.Trust, error) {
	id, err := j.Identity()
	if err != nil {
		return nil, err
	}
	tr, err := pqcrypto.NewTrust(id.Bundle, id.Fingerprint)
	if err != nil {
		return nil, err
	}
	err = j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketManifests).ForEach(func(_, v []byte) error {
			_, err := tr.Accept(v)
			return err
		})
	})
	if err != nil {
		return nil, fmt.Errorf("broker: journal manifests: %w", err)
	}
	return tr, nil
}

// AppendManifest persists a manifest Trust has just accepted.
func (j *Journal) AppendManifest(raw []byte) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketManifests)
		n, err := b.NextSequence()
		if err != nil {
			return err
		}
		return b.Put(seqKey(n), raw)
	})
}

// PutDescriptor stores a verified target descriptor by digest.
func (j *Journal) PutDescriptor(digest pqcrypto.HexID, raw []byte) error {
	return j.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketDescriptors).Put([]byte(digest), raw) })
}

// Descriptor returns a stored descriptor, or nil.
func (j *Journal) Descriptor(digest pqcrypto.HexID) []byte {
	var out []byte
	j.db.View(func(tx *bolt.Tx) error {
		out = append([]byte(nil), tx.Bucket(bucketDescriptors).Get([]byte(digest))...)
		return nil
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// Account reads an account record; a new account gets an empty one.
func (j *Journal) Account(id pqcrypto.UUID) (*Account, error) {
	a := &Account{ID: id}
	err := j.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketAccounts).Get([]byte(id)); v != nil {
			return json.Unmarshal(v, a)
		}
		return nil
	})
	return a, err
}

// Accounts lists every account record.
func (j *Journal) Accounts() ([]*Account, error) {
	var out []*Account
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAccounts).ForEach(func(_, v []byte) error {
			var a Account
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			out = append(out, &a)
			return nil
		})
	})
	return out, err
}

// ErrStopped is returned by a Save the test crash hook refused: the state is what a crash
// at that point leaves on disk.
var ErrStopped = errors.New("broker: stopped")

// Save writes an account record in one fsynced transaction.
func (j *Journal) Save(a *Account) error {
	v, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketAccounts).Put([]byte(a.ID), v) })
}

// HighestCopied is the highest secret_version among the chains the broker holds.
func (a *Account) HighestCopied() pqcrypto.Counter {
	var hv pqcrypto.Counter
	for _, c := range a.Chains {
		var head struct {
			V pqcrypto.Counter `json:"secret_version"`
		}
		if json.Unmarshal(c.Envelope, &head) == nil && head.V > hv {
			hv = head.V
		}
	}
	return hv
}

// Burned reports whether a request ID has been used.
func (j *Journal) Burned(id pqcrypto.UUID) bool {
	seen := false
	j.db.View(func(tx *bolt.Tx) error {
		seen = tx.Bucket(bucketBurned).Get([]byte(id)) != nil
		return nil
	})
	return seen
}

// SaveBurn writes an account record and burns a request ID in one transaction.
func (j *Journal) SaveBurn(a *Account, id pqcrypto.UUID, until time.Time) error {
	v, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketBurned).Put([]byte(id), []byte(until.UTC().Format(time.RFC3339))); err != nil {
			return err
		}
		return tx.Bucket(bucketAccounts).Put([]byte(a.ID), v)
	})
}

// PutChallenge journals a challenge for a request, replacing an earlier one.
func (j *Journal) PutChallenge(id pqcrypto.UUID, c *Challenge) error {
	v, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketChallenges).Put([]byte(id), v) })
}

// GetChallenge reads a request's challenge, or nil.
func (j *Journal) GetChallenge(id pqcrypto.UUID) *Challenge {
	var c *Challenge
	j.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketChallenges).Get([]byte(id)); v != nil {
			c = &Challenge{}
			if json.Unmarshal(v, c) != nil {
				c = nil
			}
		}
		return nil
	})
	return c
}

// SaveConsume writes an account record, deletes the request's challenge (single use) and,
// with a non-zero until, burns the request ID, all in one transaction.
func (j *Journal) SaveConsume(a *Account, id pqcrypto.UUID, until time.Time) error {
	v, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return j.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketChallenges).Delete([]byte(id)); err != nil {
			return err
		}
		if !until.IsZero() {
			if err := tx.Bucket(bucketBurned).Put([]byte(id), []byte(until.UTC().Format(time.RFC3339))); err != nil {
				return err
			}
		}
		return tx.Bucket(bucketAccounts).Put([]byte(a.ID), v)
	})
}
