//go:build cgo

package codec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testDecode compares named compressed fixtures with their paired plaintext.
func testDecode(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", "apple", name))
			if err != nil {
				t.Fatal(err)
			}
			plainPath := filepath.Join(
				"testdata",
				"apple",
				strings.TrimSuffix(name, ".rav")+".raw",
			)
			want, err := os.ReadFile(plainPath)
			if err != nil {
				t.Fatal(err)
			}
			dst := make([]byte, len(want))
			if err := Decode(dst, src); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dst, want) {
				t.Fatalf("decoded output differs from %s", plainPath)
			}
		})
	}
}

// TestDecodeSmallStoredFrames covers empty and short stored frames.
func TestDecodeSmallStoredFrames(t *testing.T) {
	testDecode(t, "empty.rav", "one_byte.rav", "eight_bytes.rav")
}

// TestDecodeUncompressedBlocks checks stored data at different block sizes.
func TestDecodeUncompressedBlocks(t *testing.T) {
	testDecode(t, "random_1k.rav", "random_4k.rav")
}

// TestDecodeLiteralPayloads checks literal-heavy and mixed payloads.
func TestDecodeLiteralPayloads(t *testing.T) {
	testDecode(t, "counter_le.rav", "text.rav", "plist.rav", "mixed_8k.rav")
}

// TestDecodeRepeatedBytes checks compression of repeated byte values.
func TestDecodeRepeatedBytes(t *testing.T) {
	testDecode(t, "zeros_4k.rav", "ones_1k.rav")
}

// TestDecodeShortRepeatLengths covers short repeat-length classes.
func TestDecodeShortRepeatLengths(t *testing.T) {
	testDecode(t, "rep_len_64.rav", "rep_len_80.rav", "rep_len_112.rav", "rep_len_128.rav")
}

// TestDecodeExtendedRepeatLengths covers extended repeat-length classes.
func TestDecodeExtendedRepeatLengths(t *testing.T) {
	testDecode(t, "rep_len_150.rav", "rep_len_420.rav", "repeat_short.rav", "repeat_long.rav")
}

// TestDecodeRecentDistances exercises recent-distance slots and reuse.
func TestDecodeRecentDistances(t *testing.T) {
	testDecode(t, "rep_short_mix.rav", "rep_slots.rav", "rep_deep_a.rav", "rep_deep_b.rav")
}

// TestDecodeDistanceClasses covers distance classes and multiblock frames.
func TestDecodeDistanceClasses(t *testing.T) {
	testDecode(
		t,
		"dist_class0.rav",
		"dist_class1.rav",
		"dist_class2.rav",
		"dist_class3.rav",
		"dist_class4_multiblock.rav",
	)
}

// TestDecodeMatchedLiterals covers prediction hits and mismatches.
func TestDecodeMatchedLiterals(t *testing.T) {
	testDecode(t, "lam_hit.rav", "lam_mismatch.rav")
}

// TestDecodeExecutableFilters covers executable-filter fixtures.
func TestDecodeExecutableFilters(t *testing.T) {
	testDecode(t, "bcj_arm64.rav", "bcj_x86.rav", "macho_header_like.rav")
}

// TestDecodeRejectsEveryStrictPrefix rejects incomplete stored and compressed
// frames.
func TestDecodeRejectsEveryStrictPrefix(t *testing.T) {
	for _, fixture := range []struct {
		name string
		size int
	}{{"one_byte.rav", 1}, {"random_1k.rav", 1024}, {"zeros_4k.rav", 4096}} {
		t.Run(fixture.name, func(t *testing.T) {
			compressed, err := os.ReadFile(
				filepath.Join("testdata", "apple", fixture.name),
			)
			if err != nil {
				t.Fatal(err)
			}
			for end := 0; end < len(compressed); end++ {
				if err := Decode(
					make([]byte, fixture.size),
					compressed[:end],
				); err == nil {
					t.Fatalf("Decode accepted strict prefix of length %d", end)
				}
			}
		})
	}
}

// TestDecodeRejectsWrongDestinationSize enforces the exact output-size
// contract.
func TestDecodeRejectsWrongDestinationSize(t *testing.T) {
	for _, fixture := range []struct {
		name string
		size int
	}{
		{"one_byte.rav", 1},
		{"zeros_4k.rav", 4096},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			compressed, err := os.ReadFile(
				filepath.Join("testdata", "apple", fixture.name),
			)
			if err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{fixture.size - 1, fixture.size + 1} {
				if err := Decode(make([]byte, size), compressed); err == nil {
					t.Errorf(
						"Decode accepted destination size %d, want %d",
						size,
						fixture.size,
					)
				}
			}
		})
	}

	empty, err := os.ReadFile(filepath.Join("testdata", "apple", "empty.rav"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Decode(make([]byte, 1), empty); err == nil {
		t.Error("Decode accepted a one-byte destination for the empty fixture")
	}
}

// TestDecodeRejectsInvalidHeader rejects bad magic and reserved header bits.
func TestDecodeRejectsInvalidHeader(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "apple", "one_byte.rav"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name string
		byte int
		mask byte
	}{
		{"magic", 0, 1},
		{"reserved bit", 4, 1},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			corrupt := append([]byte(nil), fixture...)
			corrupt[mutation.byte] ^= mutation.mask
			if err := Decode(make([]byte, 1), corrupt); err == nil {
				t.Error("Decode accepted invalid header")
			}
		})
	}
}
