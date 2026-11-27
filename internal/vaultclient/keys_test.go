package vaultclient

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
)

type handoffVector struct {
	Seed     pqcrypto.B64
	Expected pqcrypto.B64
	Handoff  KeyringHandoff
}

// KyIdentity's browser-generated packet from internal/api/testdata/keyring_xwing.json
// at f7aea46 must open byte-for-byte here.
func TestKyIdentityHandoffVector(t *testing.T) {
	b, err := os.ReadFile("testdata/kyidentity-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	var v handoffVector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	got, err := v.Handoff.Open(v.Seed)
	if err != nil || !bytes.Equal(got, v.Expected) {
		t.Fatalf("open KyIdentity vector: %v", err)
	}
	for name, mutate := range map[string]func(*KeyringHandoff){
		"wrong org":      func(h *KeyringHandoff) { h.Organization += "2" },
		"wrong subject":  func(h *KeyringHandoff) { h.Subject += "2" },
		"wrong app":      func(h *KeyringHandoff) { h.ClientID += "2" },
		"wrong callback": func(h *KeyringHandoff) { h.RedirectURI += "2" },
		"wrong code":     func(h *KeyringHandoff) { h.Code += "2" },
		"wrong nonce":    func(h *KeyringHandoff) { h.Nonce += "2" },
		"wrong version":  func(h *KeyringHandoff) { h.KeyVersion++ },
		"downgrade":      func(h *KeyringHandoff) { h.Marker = "p256:1" },
	} {
		t.Run(name, func(t *testing.T) {
			h := v.Handoff
			mutate(&h)
			if _, err := h.Open(v.Seed); err == nil {
				t.Fatal("altered handoff opened")
			}
		})
	}
}

func TestBrowserKeyCanOnlyOpenInItsEnrollmentContext(t *testing.T) {
	d := pqtest.New(t)
	key, draft, err := CreateKey(d.ID, "https://identity.example.test", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Trust(t).Check(pqtest.Canon(t, draft)); got != pqcrypto.ErrThreshold {
		t.Fatalf("enrollment lacked a valid self-signature: %v", got)
	}
	for _, tc := range []struct {
		method  string
		ring    pqcrypto.UUID
		version int
		secret  []byte
	}{
		{Passphrase, "", 0, []byte("a test vault passphrase")},
		{SuiteKeyring, "26142ca4-a93c-4dc3-b314-dad35b7fb82f", 1, bytes.Repeat([]byte{3}, 32)},
	} {
		t.Run(tc.method, func(t *testing.T) {
			sealed, err := SealKey(key, draft, tc.method, tc.ring, tc.version, tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			var decoded pqcrypto.KeyEnvelope
			if _, err := canonical.Decode(pqtest.Canon(t, sealed), &decoded); err != nil {
				t.Fatalf("envelope wire format: %v", err)
			}
			got, err := OpenKey(decoded, draft, tc.secret)
			if err != nil || got.Enc.Public().ID() != key.Enc.Public().ID() {
				t.Fatalf("unlock: %v", err)
			}
			switched := *draft
			switched.Subject = "bob"
			if _, err := OpenKey(decoded, &switched, tc.secret); err == nil {
				t.Fatal("the other identity opened the key")
			}
			wrong := bytes.Clone(tc.secret)
			wrong[0] ^= 1
			if _, err := OpenKey(decoded, draft, wrong); err == nil {
				t.Fatal("the wrong unlock secret opened the key")
			}
		})
	}
}
