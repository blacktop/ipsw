//go:build cgo

package codec

import (
	"bytes"
	"strconv"
	"testing"
)

// checkEncodeRoundTrips compares decoded output with a repeating input pattern
// at each requested size.
func checkEncodeRoundTrips(t *testing.T, sizes ...int) {
	for _, size := range sizes {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			src := make([]byte, size)
			for i := range src {
				src[i] = byte(i % 7)
			}
			encoded, err := Encode(src)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			decoded := make([]byte, size)
			if err := Decode(decoded, encoded); err != nil {
				t.Fatalf("Decode(encoded): %v", err)
			}
			if !bytes.Equal(decoded, src) {
				t.Fatal("decoded output differs from input")
			}
		})
	}
}

// TestEncodeSmallInputs covers empty input and both sides of the codec's
// 64-byte minimum compressed block size.
func TestEncodeSmallInputs(t *testing.T) {
	checkEncodeRoundTrips(t, 0, 1, 63, 64)
}

// TestEncodeBlockBoundaries covers inputs immediately below, at, and above
// the codec's 512 KiB block boundary.
func TestEncodeBlockBoundaries(t *testing.T) {
	checkEncodeRoundTrips(t, 524287, 524288, 524289)
}

// TestEncodeBound checks empty-input overhead, the largest supported input,
// and rejection of sizes outside the encoder's range.
func TestEncodeBound(t *testing.T) {
	if got, err := EncodeBound(0); err != nil || got <= 0 {
		t.Fatalf("EncodeBound(0) = %d, %v; want positive bound", got, err)
	}
	if got, err := EncodeBound(0xe0000000); err != nil || got != 3758125068 {
		t.Fatalf("EncodeBound(0xe0000000) = %d, %v; want 3758125068", got, err)
	}
	for _, size := range []int{-1, 0xe0000001} {
		if got, err := EncodeBound(size); err == nil {
			t.Errorf("EncodeBound(%d) = %d, nil error; want rejection", size, got)
		}
	}
}
