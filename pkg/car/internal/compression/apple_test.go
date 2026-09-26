package compression

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDeepmap2CompressionStreams(t *testing.T) {
	// EOS bytes in a raw block must remain pixels, not terminate the frame.
	first := deepmap2TestStream([]byte("bvx$"))
	second := deepmap2TestStream([]byte{1, 2})
	data := append(append(first, 0, 0, 0, 0), second...)
	want := []byte{'b', 'v', 'x', '$', 1, 2}
	got, err := Decode(data, len(want), false)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("concatenated streams = %v, %v", got, err)
	}
	// A raw LZVN literal followed by its eight-byte end marker.
	lzvn := []byte{0xe2, 7, 8, 6, 0, 0, 0, 0, 0, 0, 0}
	got, err = Decode(lzvn, 2, true)
	if err != nil || !bytes.Equal(got, []byte{7, 8}) {
		t.Fatalf("raw LZVN = %v, %v", got, err)
	}
	for _, bad := range [][]byte{data[:len(data)-1], append(second, 1), lzvn[:len(lzvn)-1], append(append([]byte(nil), lzvn...), lzvn...)} {
		if _, err := Decode(bad, 6, true); err == nil {
			t.Fatalf("accepted truncated or trailing data: %x", bad)
		}
	}
	if _, err := Decode(second, 1, false); err == nil {
		t.Fatal("accepted expansion beyond limit")
	}
}

func deepmap2TestStream(data []byte) []byte {
	stream := binary.LittleEndian.AppendUint32([]byte("bvx-"), uint32(len(data)))
	stream = append(stream, data...)
	return append(stream, "bvx$"...)
}
