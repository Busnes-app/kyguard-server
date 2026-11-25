package pqcrypto

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCounterMarshalRefusesAboveCap(t *testing.T) {
	if _, err := json.Marshal(Counter(MaxCounter + 1)); !errors.Is(err, ErrCounter) {
		t.Fatalf("err %v, want ErrCounter", err)
	}
	if b, err := json.Marshal(Counter(MaxCounter)); err != nil || string(b) != `"9223372036854775807"` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestTimeStrict(t *testing.T) {
	var ts Time
	if err := json.Unmarshal([]byte(`"2026-11-25T01:02:03Z"`), &ts); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"2026-11-25T01:02:03.000Z"`, `"2026-11-25T01:02:03+00:00"`, `"2026-11-25T01:02:03z"`, `"2026-11-25 01:02:03Z"`} {
		if err := json.Unmarshal([]byte(s), &ts); !errors.Is(err, ErrTime) {
			t.Errorf("%s: err %v, want ErrTime", s, err)
		}
	}
	if _, err := json.Marshal(Time{time.Date(2026, 1, 1, 0, 0, 0, 5, time.UTC)}); err == nil {
		t.Error("sub-second time marshalled")
	}
}

func TestWrapDEKRequiresMatchingKeyID(t *testing.T) {
	sk, other := mustXWing(t, "broker-a"), mustXWing(t, "recovery")
	f := RecipientAADFields{"managed", vEnvelope, vAccount, 7, vBroker, "broker", HexID(other.Public().ID())}
	if _, _, err := WrapDEK(sk.Public().Bytes(), f, seed("dek")); !errors.Is(err, ErrAAD) {
		t.Fatalf("wrap to a key the AAD does not name: err %v, want ErrAAD", err)
	}
	f.KeyID = HexID(sk.Public().ID())
	enc, w, err := WrapDEK(sk.Public().Bytes(), f, seed("dek"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(other, f, enc, w); !errors.Is(err, ErrAAD) {
		t.Fatalf("unwrap with a key the AAD does not name: err %v, want ErrAAD", err)
	}
}
