package iboot

import (
	"encoding/binary"
	"testing"
)

func TestParseFindsShiftedMetadata(t *testing.T) {
	data := make([]byte, 0x480)
	writeCString(data, 0x280, "iBoot for v53 Copyright 2007-2026, Apple Inc.")
	writeCString(data, 0x2c0, "RELEASE")
	writeCString(data, 0x300, "mBoot-20356.0.0.502.1")
	binary.LittleEndian.PutUint64(data[0x380:], 0x1fc08c000)

	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if got.Copyright != "iBoot for v53 Copyright 2007-2026, Apple Inc." {
		t.Fatalf("Copyright = %q", got.Copyright)
	}
	if got.Release != "RELEASE" {
		t.Fatalf("Release = %q", got.Release)
	}
	if got.Version != "mBoot-20356.0.0.502.1" {
		t.Fatalf("Version = %q", got.Version)
	}
	if got.BaseAddress != 0x1fc08c000 {
		t.Fatalf("BaseAddress = %#x", got.BaseAddress)
	}
}

func TestParseKeepsLegacyMetadataOffset(t *testing.T) {
	data := make([]byte, 0x400)
	writeCString(data, 0x200, "SecureROM for t9999")
	writeCString(data, 0x240, "RELEASE")
	writeCString(data, 0x280, "iBoot-12345.0.0")
	binary.LittleEndian.PutUint64(data[0x300:], 0x180000000)

	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if got.Version != "iBoot-12345.0.0" {
		t.Fatalf("Version = %q", got.Version)
	}
	if got.BaseAddress != 0x180000000 {
		t.Fatalf("BaseAddress = %#x", got.BaseAddress)
	}
}

func TestParseKeepsLegacyEmptyReleaseAndVersion(t *testing.T) {
	data := make([]byte, 0x400)
	writeCString(data, 0x200, "iBoot")
	binary.LittleEndian.PutUint64(data[0x300:], 0x180000000)

	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if got.Release != "" {
		t.Fatalf("Release = %q", got.Release)
	}
	if got.Version != "" {
		t.Fatalf("Version = %q", got.Version)
	}
	if got.BaseAddress != 0x180000000 {
		t.Fatalf("BaseAddress = %#x", got.BaseAddress)
	}
}

// TestParseSkipsStrayLZFSEEndBeforeStart is a regression for the iOS 27 iBoot
// panic "slice bounds out of range [383:193]": an lzfse end marker ("bvx$")
// occurring before the start marker ("bvx2") must not be paired with that
// start (which would slice data[start:end+4] with end < start). The end marker
// is now searched from the start marker, so a stray earlier end is ignored.
func TestParseSkipsStrayLZFSEEndBeforeStart(t *testing.T) {
	data := make([]byte, 0x400)
	writeCString(data, 0x200, "iBoot")
	binary.LittleEndian.PutUint64(data[0x300:], 0x180000000)

	copy(data[0x40:], lzfseEnd)   // stray end, before any start
	copy(data[0x80:], lzfseStart) // start
	copy(data[0xc0:], lzfseEnd)   // matching end, after the start

	if _, err := Parse(data); err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
}

func writeCString(data []byte, offset int, value string) {
	copy(data[offset:], value)
}
