//go:build cgo

package pbzx

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/ulikunitz/xz"
)

// TestExtractChecksMagicBeforeBlockSize rejects an unknown signature without
// reading further and reports a truncated header after a recognized signature.
func TestExtractChecksMagicBeforeBlockSize(t *testing.T) {
	src := bytes.NewReader([]byte("nope12345678"))
	if err := Extract(t.Context(), src, io.Discard, 1); err == nil {
		t.Fatal("accepted invalid magic")
	}
	if src.Len() != 8 {
		t.Fatalf("invalid magic consumed %d bytes beyond the signature", 8-src.Len())
	}
	if err := Extract(t.Context(), bytes.NewBufferString(MagicPBZM), io.Discard, 1); !errors.Is(
		err,
		io.ErrUnexpectedEOF,
	) {
		t.Fatalf("missing block size: got %v, want unexpected EOF", err)
	}
}

// TestExtractEmptyXZChunkWithDeclaredOutput rejects an empty XZ stream when
// the chunk header promises decoded bytes.
func TestExtractEmptyXZChunkWithDeclaredOutput(t *testing.T) {
	var compressed bytes.Buffer
	xw, err := xz.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	const size = 4096
	stream := binary.BigEndian.AppendUint64([]byte(Magic), size)
	stream = binary.BigEndian.AppendUint64(stream, size)
	stream = binary.BigEndian.AppendUint64(stream, uint64(compressed.Len()))
	stream = append(stream, compressed.Bytes()...)
	err = Extract(t.Context(), bytes.NewReader(stream), io.Discard, 1)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("missing XZ output: got %v, want unexpected EOF", err)
	}
}

// TestHeapReleasesPoppedChunk checks chunk ordering and clearing of the
// removed element in the heap's backing array.
func TestHeapReleasesPoppedChunk(t *testing.T) {
	h := _Heap{{idx: 2, data: []byte("two")}, {idx: 3, data: []byte("three")}}
	chunk := heap.Pop(&h).(_Chunk)
	if chunk.idx != 2 || string(chunk.data) != "two" || h[0].idx != 3 {
		t.Fatalf("unexpected pop %v, remaining heap %v", chunk, h)
	}
	if h[:cap(h)][len(h)].data != nil {
		t.Fatal("heap retained the popped chunk")
	}
}

// TestReaderReleasesConsumedChunk checks that a chunk read in separate pieces
// is released as soon as its final byte is consumed.
func TestReaderReleasesConsumedChunk(t *testing.T) {
	const payload = "raw"
	stream := binary.BigEndian.AppendUint64([]byte(MagicPBZM), uint64(len(payload)))
	stream = binary.BigEndian.AppendUint64(stream, uint64(len(payload)))
	stream = binary.BigEndian.AppendUint64(stream, uint64(len(payload)))
	r, err := NewReader(bytes.NewReader(append(stream, payload...)), 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf [len(payload)]byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, buf[1:]); err != nil {
		t.Fatal(err)
	}
	if string(buf[:]) != payload {
		t.Fatalf("read %q, want %q", buf, payload)
	}
	if r.data != nil {
		t.Fatal("reader retained the consumed chunk")
	}
}

// TestReaderReleasesSourceAtEnd checks stable terminal errors and source
// release after both clean EOF and a truncated chunk header.
func TestReaderReleasesSourceAtEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		tail []byte
		want error
	}{{"eof", nil, io.EOF}, {"truncated", []byte{0}, io.ErrUnexpectedEOF}} {
		t.Run(tc.name, func(t *testing.T) {
			stream := binary.BigEndian.AppendUint64([]byte(MagicPBZM), 1)
			r, err := NewReader(bytes.NewReader(append(stream, tc.tail...)), 0)
			if err != nil {
				t.Fatal(err)
			}
			var buf [1]byte
			for i := 0; i < 2; i++ {
				if n, err := r.Read(buf[:]); n != 0 || !errors.Is(err, tc.want) {
					t.Fatalf("read = %d, %v, want 0, %v", n, err, tc.want)
				}
			}
			if r.stream != nil {
				t.Fatal("reader retained its source after terminal error")
			}
		})
	}
}
