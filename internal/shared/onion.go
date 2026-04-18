package shared

import (
	"encoding/base32"
	"errors"
	"strings"

	"golang.org/x/crypto/sha3"
)

var (
	ErrOnionEmpty           = errors.New("onion address is empty")
	ErrOnionSuffix          = errors.New("onion address must end with .onion")
	ErrOnionLength          = errors.New("onion v3 address must be 56 base32 characters before .onion suffix")
	ErrOnionNotLowercase    = errors.New("onion address must be lowercase")
	ErrOnionBadBase32       = errors.New("onion address contains invalid base32 characters")
	ErrOnionV2Deprecated    = errors.New("onion v2 addresses are not supported (deprecated)")
	ErrOnionVersion         = errors.New("onion address version byte must be 0x03")
	ErrOnionChecksum        = errors.New("onion address checksum mismatch")
)

const onionSuffix = ".onion"

var onionB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ValidateOnionV3 enforces the tor v3 hidden-service address rules.
// The address must be lowercase, end with ".onion", and the 56-character
// prefix must decode to 35 bytes (32-byte ed25519 pubkey, 2-byte checksum,
// 1-byte version 0x03) with a matching SHA3-256 checksum.
func ValidateOnionV3(addr string) error {
	if addr == "" {
		return ErrOnionEmpty
	}
	if !strings.HasSuffix(addr, onionSuffix) {
		return ErrOnionSuffix
	}
	prefix := addr[:len(addr)-len(onionSuffix)]
	if prefix == "" {
		return ErrOnionLength
	}
	if len(prefix) == 16 || len(prefix) == 22 {
		return ErrOnionV2Deprecated
	}
	if len(prefix) != 56 {
		return ErrOnionLength
	}
	if strings.ToLower(prefix) != prefix {
		return ErrOnionNotLowercase
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return ErrOnionBadBase32
		}
	}
	decoded, err := onionB32.DecodeString(strings.ToUpper(prefix))
	if err != nil {
		return ErrOnionBadBase32
	}
	if len(decoded) != 35 {
		return ErrOnionLength
	}
	if decoded[34] != 0x03 {
		return ErrOnionVersion
	}
	pubkey := decoded[:32]
	gotChecksum := decoded[32:34]
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pubkey)
	h.Write([]byte{0x03})
	sum := h.Sum(nil)
	if sum[0] != gotChecksum[0] || sum[1] != gotChecksum[1] {
		return ErrOnionChecksum
	}
	return nil
}

// BuildOnionV3 is a test/helper that computes a correct v3 .onion string
// for the supplied 32-byte ed25519 public key. It is intentionally exported
// so other packages (and tests) can construct valid addresses without
// rolling their own checksum.
func BuildOnionV3(pubkey []byte) (string, error) {
	if len(pubkey) != 32 {
		return "", errors.New("onion v3 pubkey must be 32 bytes")
	}
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pubkey)
	h.Write([]byte{0x03})
	sum := h.Sum(nil)
	payload := make([]byte, 0, 35)
	payload = append(payload, pubkey...)
	payload = append(payload, sum[0], sum[1], 0x03)
	return strings.ToLower(onionB32.EncodeToString(payload)) + onionSuffix, nil
}
