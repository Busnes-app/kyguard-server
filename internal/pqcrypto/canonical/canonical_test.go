package canonical

import (
	"encoding/json"
	"errors"
	"testing"
)

type obj struct {
	Type  string `json:"type"`
	Epoch string `json:"epoch"`
	Note  string `json:"note,omitempty"`
}

func TestDecodeStrict(t *testing.T) {
	var o obj
	if _, err := Decode([]byte(`{"epoch":"1","type":"x"}`), &o); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"unknown field":     `{"epoch":"1","type":"x","extra":1}`,
		"case-folded key":   `{"epoch":"1","Type":"x"}`,
		"case-folded twice": `{"epoch":"1","type":"x","TYPE":"y"}`,
		"empty omitempty":   `{"epoch":"1","type":"x","note":""}`,
		"missing field":     `{"type":"x"}`,
		"null for string":   `{"epoch":"1","type":null}`,
	} {
		var o obj
		if _, err := Decode([]byte(in), &o); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%s: err %v, want ErrNotCanonical", name, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{`{"a":[1,"é",null,true]}`, `{"a":1,"a":2}`, `"\ud800"`, `-0`, `[[[]]]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Parse(b)
		if err != nil {
			return
		}
		if !json.Valid(b) {
			t.Fatalf("accepted invalid JSON %q", b)
		}
		c := Encode(v)
		v2, err := Parse(c)
		if err != nil {
			t.Fatalf("canonical output does not parse: %q: %v", c, err)
		}
		if string(Encode(v2)) != string(c) {
			t.Fatalf("encoding not idempotent: %q", c)
		}
	})
}
