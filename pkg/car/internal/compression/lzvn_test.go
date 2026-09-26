package compression

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"

	"github.com/blacktop/lzfse-cgo"
)

func TestLZVNInstructionSizes(t *testing.T) {
	// Establish previous distance 1 using a one-byte literal and a match.
	prefix := []byte{0x40, 1, 'a'}
	for _, tc := range []struct {
		name string
		op   []byte
		size int
	}{
		{"small distance", []byte{0x80, 2, 'b', 'c'}, 5},
		{"large distance", []byte{0x47, 1, 0, 'b'}, 4},
		{"medium distance", []byte{0xa8, 4, 0, 'b'}, 4},
		{"previous distance", []byte{0x46, 'b'}, 4},
		{"short literal", []byte{0xe2, 'b', 'c'}, 2},
		{"long literal", append([]byte{0xe0, 0}, bytes.Repeat([]byte{'b'}, 16)...), 16},
		{"short match", []byte{0xf2}, 2},
		{"long match", []byte{0xf0, 1}, 17},
		{"nop", []byte{0x0e, 0x16}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append(bytes.Clone(prefix), tc.op...)
			data = append(data, 6, 0, 0, 0, 0, 0, 0, 0)
			want := 4 + tc.size
			size, err := lzvnSize(data, want)
			if err != nil || size != want {
				t.Fatalf("size = %d, %v; want %d", size, err, want)
			}
			got, err := Decode(data, maxStreamBytes, true)
			if err != nil || len(got) != want || cap(got) > want+1 {
				t.Fatalf("decoded length/capacity = %d/%d, %v", len(got), cap(got), err)
			}
			// An independent native framed decode checks instruction accounting.
			framed := binary.LittleEndian.AppendUint32([]byte("bvxn"), uint32(want))
			framed = binary.LittleEndian.AppendUint32(framed, uint32(len(data)))
			framed = append(framed, data...)
			framed = append(framed, "bvx$"...)
			native := make([]byte, want+1)
			if n := lzfse.DecodeBufferInto(framed, native); n != want || !bytes.Equal(native[:want], got) {
				t.Fatalf("native decode disagrees: length %d", n)
			}
			if _, err := Decode(data, want-1, true); err == nil {
				t.Fatal("accepted output beyond the limit")
			}
		})
	}
}

func TestLZVNCompressorRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{128, 1024, 4095} {
		for _, alphabet := range []int{1, 4} {
			original := make([]byte, size)
			for i := range original {
				original[i] = byte(rng.IntN(alphabet))
			}
			// The framed encoder chooses LZVN for these small inputs and owns
			// its scratch allocation. Extract its raw block for our decoder.
			encoded := lzfse.EncodeBuffer(original)
			if len(encoded) < 16 || string(encoded[:4]) != "bvxn" {
				t.Fatal("native compressor did not produce LZVN")
			}
			length := int(binary.LittleEndian.Uint32(encoded[8:]))
			if length != len(encoded)-16 {
				t.Fatal("unexpected native block framing")
			}
			got, err := Decode(encoded[12:12+length], size, true)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("round trip %d bytes/%d symbols: %v", size, alphabet, err)
			}
		}
	}
}

func TestLZVNRejectsInvalidInstructions(t *testing.T) {
	for _, op := range [][]byte{{0x1e}, {0x70}, {0xd0}, {0xf1}, {0x40, 0, 'a'}, {0, 1}, {0xe0, 255}} {
		data := append(bytes.Clone(op), 6, 0, 0, 0, 0, 0, 0, 0)
		if _, err := Decode(data, 1024, true); err == nil {
			t.Fatalf("accepted malformed instructions %x", data)
		}
	}
}

func BenchmarkDecodeRawLZVN(b *testing.B) {
	data := []byte{0xe2, 7, 8, 6, 0, 0, 0, 0, 0, 0, 0}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(data, maxStreamBytes, true); err != nil {
			b.Fatal(err)
		}
	}
}
