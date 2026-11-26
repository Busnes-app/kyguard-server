package broker

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// JournalFile is the broker's bbolt journal (§3.7). It holds no plaintext credential.
const JournalFile = "journal.db"

var bucketMeta = []byte("meta")

// Meta keys.
var (
	keyBrokerID    = []byte("broker_id")
	keyCert        = []byte("cert")
	keyCACert      = []byte("ca_cert")
	keyListener    = []byte("listener_url")
	keyBundle      = []byte("bundle")
	keyFingerprint = []byte("fingerprint")
)

// ErrNotPaired means `kyguard-broker pair` has not run on this host.
var ErrNotPaired = errors.New("broker: not paired; run kyguard-broker pair")

// Journal is the broker's durable state. bbolt holds an exclusive file lock while open and
// fsyncs every committed transaction.
type Journal struct{ db *bolt.DB }

// OpenJournal opens or creates the journal 0600 with its exclusive lock.
func OpenJournal(dir string) (*Journal, error) {
	path := filepath.Join(dir, JournalFile)
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if errors.Is(err, bolt.ErrTimeout) {
		return nil, fmt.Errorf("broker: %s is locked by another kyguard-broker", path)
	}
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&0o077 != 0 {
		db.Close()
		return nil, fmt.Errorf("broker: %s must be 0600", path)
	}
	j := &Journal{db}
	if err := j.init(); err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}

// Close releases the lock.
func (j *Journal) Close() error { return j.db.Close() }

// Identity is what pairing left on this host.
type Identity struct {
	BrokerID    pqcrypto.UUID
	Cert        *x509.Certificate
	CACert      *x509.Certificate
	ListenerURL string
	Bundle      []byte
	Fingerprint pqcrypto.HexID
}

// SavePairing records a pairing once.
func (j *Journal) SavePairing(id *Identity) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if b.Get(keyBrokerID) != nil {
			return errors.New("broker: this journal is already paired")
		}
		for k, v := range map[string][]byte{
			string(keyBrokerID): []byte(id.BrokerID), string(keyCert): id.Cert.Raw, string(keyCACert): id.CACert.Raw,
			string(keyListener): []byte(id.ListenerURL), string(keyBundle): id.Bundle, string(keyFingerprint): []byte(id.Fingerprint),
		} {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	})
}

// Identity reads the pairing back.
func (j *Journal) Identity() (*Identity, error) {
	var id Identity
	err := j.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if b.Get(keyBrokerID) == nil {
			return ErrNotPaired
		}
		// A parsed certificate keeps its input, and bbolt's bytes die with the transaction.
		var err error
		if id.Cert, err = x509.ParseCertificate(bytes.Clone(b.Get(keyCert))); err != nil {
			return err
		}
		if id.CACert, err = x509.ParseCertificate(bytes.Clone(b.Get(keyCACert))); err != nil {
			return err
		}
		id.BrokerID = pqcrypto.UUID(b.Get(keyBrokerID))
		id.ListenerURL = string(b.Get(keyListener))
		id.Bundle = append([]byte(nil), b.Get(keyBundle)...)
		id.Fingerprint = pqcrypto.HexID(b.Get(keyFingerprint))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &id, nil
}
