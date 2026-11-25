// Package canonical is KyGuard's RFC 8785 (JCS) encoder and its strict JSON parser.
//
// Parse rejects what JCS leaves ambiguous: duplicate keys, malformed UTF-8, lone UTF-16
// surrogates, non-integer numbers, trailing data and nesting past MaxDepth. Numbers are
// limited to integers in the IEEE-754 safe range, where JCS number serialization is plain
// decimal. Decode adds the typed check: the struct must re-encode to the same canonical
// bytes as the input, so unknown, case-folded or defaulted fields are rejected.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth bounds object and array nesting.
const MaxDepth = 32

// maxSafeInt is 2^53-1, the largest integer every JCS implementation encodes exactly.
const maxSafeInt = 1<<53 - 1

// Error is a stable, comparable error code; vectors name it.
type Error string

func (e Error) Error() string { return "canonical: " + string(e) }

// Errors returned by Parse and Decode.
const (
	ErrSyntax       Error = "syntax"
	ErrDuplicateKey Error = "duplicate_key"
	ErrUTF8         Error = "invalid_utf8"
	ErrNumber       Error = "number_out_of_profile"
	ErrDepth        Error = "too_deep"
	ErrNotCanonical Error = "fields_not_canonical"
)

// Value is a parsed JSON value: nil, bool, int64, string, []Value or Object.
type Value any

// Member is one object member.
type Member struct {
	Key   string
	Value Value
}

// Object keeps members in input order; Encode sorts them.
type Object []Member

// Without returns o minus the named top-level members.
func (o Object) Without(keys ...string) Object {
	out := make(Object, 0, len(o))
next:
	for _, m := range o {
		for _, k := range keys {
			if m.Key == k {
				continue next
			}
		}
		out = append(out, m)
	}
	return out
}

// Parse parses one JSON value under the strict profile.
func Parse(b []byte) (Value, error) {
	if !utf8.Valid(b) {
		return nil, ErrUTF8
	}
	p := parser{b: b}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, ErrSyntax
	}
	return v, nil
}

// Canonicalize returns the JCS form of the JSON in b.
func Canonicalize(b []byte) ([]byte, error) {
	v, err := Parse(b)
	if err != nil {
		return nil, err
	}
	return Encode(v), nil
}

// Marshal returns the JCS form of v, which must marshal with encoding/json.
func Marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	return Canonicalize(b)
}

// Decode parses b strictly into v and requires v to re-encode to the same canonical bytes.
// It returns the canonical bytes of the input.
func Decode(b []byte, v any) ([]byte, error) {
	tree, err := Parse(b)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var ce Error
		if errors.As(err, &ce) {
			return nil, ce
		}
		return nil, fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	want := Encode(tree)
	got, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, got) {
		return nil, ErrNotCanonical
	}
	return want, nil
}

// Encode serializes v per RFC 8785.
func Encode(v Value) []byte {
	var buf bytes.Buffer
	encode(&buf, v)
	return buf.Bytes()
}

func encode(buf *bytes.Buffer, v Value) {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case string:
		encodeString(buf, x)
	case []Value:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			encode(buf, e)
		}
		buf.WriteByte(']')
	case Object:
		ms := append(Object(nil), x...)
		// RFC 8785 §3.2.3: sort by UTF-16 code units.
		sort.Slice(ms, func(i, j int) bool { return lessUTF16(ms[i].Key, ms[j].Key) })
		buf.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, m.Key)
			buf.WriteByte(':')
			encode(buf, m.Value)
		}
		buf.WriteByte('}')
	default:
		panic(fmt.Sprintf("canonical: unsupported value %T", v))
	}
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// encodeString escapes only what RFC 8785 §3.2.2.2 requires.
func encodeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[c>>4])
				buf.WriteByte(hex[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

type parser struct {
	b []byte
	i int
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) lit(s string, v Value) (Value, error) {
	if !bytes.HasPrefix(p.b[p.i:], []byte(s)) {
		return nil, ErrSyntax
	}
	p.i += len(s)
	return v, nil
}

func (p *parser) value(depth int) (Value, error) {
	if p.i >= len(p.b) {
		return nil, ErrSyntax
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == 't':
		return p.lit("true", true)
	case c == 'f':
		return p.lit("false", false)
	case c == 'n':
		return p.lit("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, ErrSyntax
	}
}

func (p *parser) object(depth int) (Value, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	p.i++
	obj := Object{}
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, ErrSyntax
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if seen[k] {
			return nil, ErrDuplicateKey
		}
		seen[k] = true
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, ErrSyntax
		}
		p.i++
		p.ws()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		obj = append(obj, Member{k, v})
		p.ws()
		if p.i >= len(p.b) {
			return nil, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return obj, nil
		default:
			return nil, ErrSyntax
		}
	}
}

func (p *parser) array(depth int) (Value, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	p.i++
	arr := []Value{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		p.ws()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.ws()
		if p.i >= len(p.b) {
			return nil, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, ErrSyntax
		}
	}
}

// number accepts only integers in [-(2^53-1), 2^53-1] without fraction or exponent.
func (p *parser) number() (Value, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	digits := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	if p.i == digits {
		return nil, ErrSyntax
	}
	if p.i < len(p.b) && (p.b[p.i] == '.' || p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		return nil, ErrNumber
	}
	if p.b[digits] == '0' && p.i-digits > 1 {
		return nil, ErrSyntax
	}
	n, err := strconv.ParseInt(string(p.b[start:p.i]), 10, 64)
	if err != nil || n > maxSafeInt || n < -maxSafeInt {
		return nil, ErrNumber
	}
	if n == 0 && p.b[start] == '-' {
		return nil, ErrNumber // -0
	}
	return n, nil
}

func (p *parser) str() (string, error) {
	p.i++
	var out []byte
	for {
		if p.i >= len(p.b) {
			return "", ErrSyntax
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return "", ErrSyntax
		case c == '\\':
			p.i++
			if p.i >= len(p.b) {
				return "", ErrSyntax
			}
			e := p.b[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xdc00 || !bytes.HasPrefix(p.b[p.i:], []byte(`\u`)) {
						return "", ErrUTF8
					}
					p.i += 2
					r2, err := p.hex4()
					if err != nil {
						return "", err
					}
					r = utf16.DecodeRune(r, r2)
					if r == utf8.RuneError {
						return "", ErrUTF8
					}
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", ErrSyntax
			}
		default:
			out = append(out, c)
			p.i++
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.b) {
		return 0, ErrSyntax
	}
	n, err := strconv.ParseUint(string(p.b[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, ErrSyntax
	}
	p.i += 4
	return rune(n), nil
}
