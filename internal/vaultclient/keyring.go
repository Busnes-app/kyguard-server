package vaultclient

import (
	"bytes"
	"errors"

	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// KeyringHandoff is the KyIdentity X-Wing OIDC handoff transcript. The authorization
// coordinates came from the initiating browser and the verified code exchange.
type KeyringHandoff struct {
	Issuer       string        `json:"issuer"`
	Organization string        `json:"org_id"`
	Subject      string        `json:"subject"`
	Ring         pqcrypto.UUID `json:"keyring_version"`
	ClientID     string        `json:"client_id"`
	KeyVersion   int           `json:"key_version"`
	Code         string        `json:"code"`
	RedirectURI  string        `json:"redirect_uri"`
	Public       pqcrypto.B64  `json:"keyring_pk"`
	Nonce        string        `json:"nonce"`
	Marker       string        `json:"sender_key"`
	Sealed       pqcrypto.B64  `json:"sealed"`
}

func (h KeyringHandoff) Open(seed []byte) ([]byte, error) {
	if h.Marker != "xwing:1" || len(h.Sealed) != 1169 || h.KeyVersion < 1 || h.KeyVersion > 2147483647 ||
		!h.Ring.Valid() || h.Ring[14] != '4' || h.Issuer == "" || h.Organization == "" || h.Subject == "" ||
		h.ClientID == "" || h.Code == "" || h.RedirectURI == "" || h.Nonce == "" {
		return nil, errors.New("invalid KyIdentity keyring handoff")
	}
	recipient, err := xwing.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(recipient.Public().Bytes(), h.Public) {
		return nil, errors.New("KyIdentity handoff did not match this sign-in")
	}
	aad, err := canonical.Marshal([]any{"ky-keyring/1", "handoff-xwing/2", h.Issuer, h.Organization,
		h.Subject, h.Ring, h.ClientID, h.KeyVersion, h.Code, h.RedirectURI, h.Public, h.Nonce})
	if err != nil {
		return nil, err
	}
	info := append([]byte("kyidentity/keyring-handoff/2\x00"), aad...)
	key, err := xwing.Open(recipient, info, aad, h.Sealed)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errors.New("KyIdentity could not unlock the app key for this sign-in")
	}
	return key, nil
}
