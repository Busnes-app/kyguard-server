package pqcrypto

const (
	BrowserPassphrase   = "passphrase"
	BrowserSuiteKeyring = "kyidentity"
)

// KeyEnvelope is the opaque versioned browser key bundle accepted by the API.
type KeyEnvelope struct {
	Version    int    `json:"version"`
	Method     string `json:"method"`
	Ring       UUID   `json:"keyring_version,omitzero"`
	KeyVersion int    `json:"key_version,omitempty"`
	Salt       B64    `json:"salt,omitempty"`
	Nonce      B64    `json:"nonce"`
	Ciphertext B64    `json:"ciphertext"`
}

func (e KeyEnvelope) Valid() bool {
	if e.Version != 1 || len(e.Nonce) != 12 || len(e.Ciphertext) != 3*32+16 {
		return false
	}
	switch e.Method {
	case BrowserPassphrase:
		return len(e.Salt) == 16 && e.Ring == "" && e.KeyVersion == 0
	case BrowserSuiteKeyring:
		return len(e.Salt) == 0 && e.Ring.Valid() && e.Ring[14] == '4' && e.KeyVersion > 0 && e.KeyVersion <= 2147483647
	default:
		return false
	}
}
