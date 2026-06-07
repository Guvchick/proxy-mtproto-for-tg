package secret

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

type Type int

const (
	TypeSimple  Type = iota // raw 32-hex (16 bytes)
	TypePadded              // "dd" prefix  – padded intermediate
	TypeFakeTLS             // "ee" prefix  – masquerade as TLS
)

type Secret struct {
	Type   Type
	Key    []byte // always 16 bytes
	Domain string // non-empty only for TypeFakeTLS
	Raw    string // original string as supplied
}

func Parse(raw string) (*Secret, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	out := &Secret{Raw: s}

	switch {
	case strings.HasPrefix(s, "ee"):
		out.Type = TypeFakeTLS
		rest := s[2:]
		if len(rest) < 32 {
			return nil, fmt.Errorf("fake-tls secret: key part must be 32 hex chars")
		}
		key, err := hex.DecodeString(rest[:32])
		if err != nil {
			return nil, fmt.Errorf("fake-tls secret key: %w", err)
		}
		out.Key = key
		if len(rest) > 32 {
			domainBytes, err := hex.DecodeString(rest[32:])
			if err != nil {
				return nil, fmt.Errorf("fake-tls secret domain: %w", err)
			}
			out.Domain = string(domainBytes)
		}

	case strings.HasPrefix(s, "dd"):
		out.Type = TypePadded
		key, err := hex.DecodeString(s[2:])
		if err != nil {
			return nil, fmt.Errorf("padded secret: %w", err)
		}
		out.Key = key

	default:
		out.Type = TypeSimple
		key, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("simple secret: %w", err)
		}
		out.Key = key
	}

	if len(out.Key) != 16 {
		return nil, fmt.Errorf("secret key must be 16 bytes, got %d", len(out.Key))
	}
	return out, nil
}

// Generate creates a random 16-byte secret and returns its hex representation.
func Generate() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FakeTLSString builds the "ee<key_hex><domain_hex>" string for a fake-TLS secret.
func FakeTLSString(keyHex, domain string) string {
	return "ee" + strings.ToLower(keyHex) + hex.EncodeToString([]byte(domain))
}

func (s *Secret) String() string {
	return s.Raw
}
