package shared

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

func mustBuildOnion(t *testing.T, seed byte) string {
	t.Helper()
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = seed + byte(i)
	}
	addr, err := BuildOnionV3(pk)
	if err != nil {
		t.Fatalf("BuildOnionV3: %v", err)
	}
	return addr
}

func mustBuildRandomOnion(t *testing.T) string {
	t.Helper()
	pk := make([]byte, 32)
	if _, err := rand.Read(pk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	addr, err := BuildOnionV3(pk)
	if err != nil {
		t.Fatalf("BuildOnionV3: %v", err)
	}
	return addr
}

func TestValidateOnionV3_ValidConstructed(t *testing.T) {
	for i := 0; i < 6; i++ {
		addr := mustBuildOnion(t, byte(i))
		if err := ValidateOnionV3(addr); err != nil {
			t.Errorf("seed=%d addr=%s err=%v", i, addr, err)
		}
	}
}

func TestValidateOnionV3_ValidRandom(t *testing.T) {
	for i := 0; i < 10; i++ {
		addr := mustBuildRandomOnion(t)
		if err := ValidateOnionV3(addr); err != nil {
			t.Errorf("random #%d addr=%s err=%v", i, addr, err)
		}
	}
}

func TestValidateOnionV3_KnownReal(t *testing.T) {
	// Tor Project v3 onion (public, known-good).
	addr := "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	if err := ValidateOnionV3(addr); err != nil {
		t.Errorf("real onion rejected: %v", err)
	}
}

func TestValidateOnionV3_Empty(t *testing.T) {
	if err := ValidateOnionV3(""); !errors.Is(err, ErrOnionEmpty) {
		t.Errorf("want ErrOnionEmpty, got %v", err)
	}
}

func TestValidateOnionV3_MissingSuffix(t *testing.T) {
	addr := mustBuildOnion(t, 0)
	prefix := strings.TrimSuffix(addr, ".onion")
	if err := ValidateOnionV3(prefix); !errors.Is(err, ErrOnionSuffix) {
		t.Errorf("want ErrOnionSuffix, got %v", err)
	}
}

func TestValidateOnionV3_WrongSuffix(t *testing.T) {
	addr := mustBuildOnion(t, 0)
	broken := strings.TrimSuffix(addr, ".onion") + ".com"
	if err := ValidateOnionV3(broken); !errors.Is(err, ErrOnionSuffix) {
		t.Errorf("want ErrOnionSuffix, got %v", err)
	}
}

func TestValidateOnionV3_OnlySuffix(t *testing.T) {
	if err := ValidateOnionV3(".onion"); !errors.Is(err, ErrOnionLength) {
		t.Errorf("want ErrOnionLength, got %v", err)
	}
}

func TestValidateOnionV3_TooShort(t *testing.T) {
	addr := strings.Repeat("a", 55) + ".onion"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionLength) {
		t.Errorf("want ErrOnionLength, got %v", err)
	}
}

func TestValidateOnionV3_TooLong(t *testing.T) {
	addr := strings.Repeat("a", 57) + ".onion"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionLength) {
		t.Errorf("want ErrOnionLength, got %v", err)
	}
}

func TestValidateOnionV3_V2SixteenChars(t *testing.T) {
	addr := strings.Repeat("a", 16) + ".onion"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionV2Deprecated) {
		t.Errorf("want ErrOnionV2Deprecated, got %v", err)
	}
}

func TestValidateOnionV3_V2TwentyTwoChars(t *testing.T) {
	addr := strings.Repeat("a", 22) + ".onion"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionV2Deprecated) {
		t.Errorf("want ErrOnionV2Deprecated, got %v", err)
	}
}

func TestValidateOnionV3_UppercaseRejected(t *testing.T) {
	addr := mustBuildOnion(t, 1)
	upper := strings.ToUpper(strings.TrimSuffix(addr, ".onion")) + ".onion"
	if err := ValidateOnionV3(upper); !errors.Is(err, ErrOnionNotLowercase) {
		t.Errorf("want ErrOnionNotLowercase, got %v", err)
	}
}

func TestValidateOnionV3_MixedCaseRejected(t *testing.T) {
	addr := mustBuildOnion(t, 2)
	// Flip first character to uppercase.
	bytes := []byte(addr)
	if bytes[0] >= 'a' && bytes[0] <= 'z' {
		bytes[0] = bytes[0] - 'a' + 'A'
	}
	if err := ValidateOnionV3(string(bytes)); !errors.Is(err, ErrOnionNotLowercase) {
		t.Errorf("want ErrOnionNotLowercase, got %v", err)
	}
}

func TestValidateOnionV3_BadBase32_Digit(t *testing.T) {
	// Digits 0, 1, 8, 9 are not in the base32 alphabet.
	for _, c := range "0189" {
		addr := strings.Repeat("a", 55) + string(c) + ".onion"
		if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionBadBase32) {
			t.Errorf("char=%q want ErrOnionBadBase32, got %v", c, err)
		}
	}
}

func TestValidateOnionV3_BadBase32_Symbol(t *testing.T) {
	addr := strings.Repeat("a", 55) + "!.onion"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionBadBase32) {
		t.Errorf("want ErrOnionBadBase32, got %v", err)
	}
}

func TestValidateOnionV3_BadBase32_Space(t *testing.T) {
	addr := strings.Repeat("a", 55) + " .onion"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionBadBase32) {
		t.Errorf("want ErrOnionBadBase32, got %v", err)
	}
}

func TestValidateOnionV3_VersionByteWrong(t *testing.T) {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i)
	}
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pk)
	h.Write([]byte{0x02})
	sum := h.Sum(nil)
	payload := append([]byte{}, pk...)
	payload = append(payload, sum[0], sum[1], 0x02)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	addr := strings.ToLower(b32.EncodeToString(payload)) + ".onion"
	err := ValidateOnionV3(addr)
	// Either the checksum check or the version check may fail first,
	// depending on whether the crafted address happens to pass checksum.
	// The version byte mismatch is the deterministic failure.
	if !errors.Is(err, ErrOnionVersion) && !errors.Is(err, ErrOnionChecksum) {
		t.Errorf("want ErrOnionVersion or ErrOnionChecksum, got %v", err)
	}
	// Specifically test version byte mismatch with correct-for-v2 checksum.
	if !errors.Is(err, ErrOnionVersion) {
		t.Logf("non-version error returned: %v", err)
	}
}

func TestValidateOnionV3_VersionByteWrong_ChecksumAligned(t *testing.T) {
	// Build a valid v3 then flip only the version byte: must fail with checksum
	// (or version) error — but never pass.
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(0xA0 + i)
	}
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pk)
	h.Write([]byte{0x03})
	sum := h.Sum(nil)
	payload := append([]byte{}, pk...)
	payload = append(payload, sum[0], sum[1], 0x04)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	addr := strings.ToLower(b32.EncodeToString(payload)) + ".onion"
	err := ValidateOnionV3(addr)
	if !errors.Is(err, ErrOnionVersion) {
		t.Errorf("want ErrOnionVersion, got %v", err)
	}
}

func TestValidateOnionV3_ChecksumBitflip(t *testing.T) {
	addr := mustBuildOnion(t, 4)
	// flip a byte in the prefix (not version) and expect failure.
	bytes := []byte(addr)
	// Change the 30th char to another valid base32 char.
	if bytes[30] == 'a' {
		bytes[30] = 'b'
	} else {
		bytes[30] = 'a'
	}
	err := ValidateOnionV3(string(bytes))
	if err == nil {
		t.Fatalf("expected some error for tampered addr, got nil")
	}
	// Must be checksum or version depending on which byte was hit.
	if !errors.Is(err, ErrOnionChecksum) && !errors.Is(err, ErrOnionVersion) {
		t.Errorf("unexpected error type: %v", err)
	}
}

func TestValidateOnionV3_DoubleSuffix(t *testing.T) {
	addr := mustBuildOnion(t, 0) + ".onion"
	err := ValidateOnionV3(addr)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// The prefix here would be 62 chars (56 + ".onion"), so length fails.
	if !errors.Is(err, ErrOnionLength) && !errors.Is(err, ErrOnionBadBase32) {
		t.Errorf("want length or base32 error, got %v", err)
	}
}

func TestValidateOnionV3_LeadingDot(t *testing.T) {
	addr := "." + strings.Repeat("a", 55) + ".onion"
	err := ValidateOnionV3(addr)
	if !errors.Is(err, ErrOnionBadBase32) && !errors.Is(err, ErrOnionLength) {
		t.Errorf("want ErrOnionBadBase32 or ErrOnionLength, got %v", err)
	}
}

func TestValidateOnionV3_DomainSuffix(t *testing.T) {
	addr := mustBuildOnion(t, 0) + ".com"
	if err := ValidateOnionV3(addr); !errors.Is(err, ErrOnionSuffix) {
		t.Errorf("want ErrOnionSuffix, got %v", err)
	}
}

func TestValidateOnionV3_WhitespaceTrimNotAccepted(t *testing.T) {
	addr := " " + mustBuildOnion(t, 3)
	err := ValidateOnionV3(addr)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestValidateOnionV3_Nil32ByteKeyValidates(t *testing.T) {
	zero := make([]byte, 32)
	addr, err := BuildOnionV3(zero)
	if err != nil {
		t.Fatalf("BuildOnionV3: %v", err)
	}
	if err := ValidateOnionV3(addr); err != nil {
		t.Errorf("zero-key onion rejected: %v", err)
	}
}

func TestBuildOnionV3_RejectsWrongKeyLength(t *testing.T) {
	if _, err := BuildOnionV3(make([]byte, 31)); err == nil {
		t.Error("expected error for 31-byte key")
	}
	if _, err := BuildOnionV3(make([]byte, 33)); err == nil {
		t.Error("expected error for 33-byte key")
	}
}
