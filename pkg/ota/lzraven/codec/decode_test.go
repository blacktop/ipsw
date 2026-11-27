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
