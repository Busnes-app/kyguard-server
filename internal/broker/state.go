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
	// StateReserving is journaled before the Control Plane is asked for a version, so a
	// reservation never exists without a local run. It is not a §4.2 state: the run becomes
	// prepared, or aborted with nothing to send when the Control Plane refused.
	StateReserving = "reserving"
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
	// Unreported is set while the last health report was not delivered (resent by Recover).
	Unreported bool `json:"unreported,omitempty"`
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
}

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
	// SeenBefore is the highest version the broker had seen before it reserved; a version the
	// Control Plane returns for this operation must be above it.
	SeenBefore    pqcrypto.Counter `json:"seen_before,omitempty"`
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
}

// Open reports whether the run still blocks the account (§4.2 blocking rule).
func (r *Run) Open() bool {
	return r != nil && r.State != StateReleaseAuthorized && r.State != StateAborted
}

func seqKey(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

func (j *Journal) init() error {
	return j.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketManifests, bucketDescriptors, bucketAccounts} {
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
