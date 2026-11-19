package remote

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestAPFSPartition(t *testing.T) {
	le := binary.LittleEndian
	image := make([]byte, 64*512)
	if source, size, err := APFSPartition(bytes.NewReader(image), int64(len(image))); err != nil || size != int64(len(image)) || source == nil {
		t.Fatalf("naked container: %d %v", size, err)
	}
	copy(image[512:], "EFI PART")
	le.PutUint64(image[512+72:], 2)   // entries start LBA
	le.PutUint32(image[512+80:], 4)   // entry count
	le.PutUint32(image[512+84:], 128) // entry size
	if _, _, err := APFSPartition(bytes.NewReader(image), int64(len(image))); err == nil || !strings.Contains(err.Error(), "no APFS partition") {
		t.Fatalf("empty table: %v", err)
	}
	entry := image[2*512+128:] // second entry; the first stays unused
	copy(entry, []byte{0xef, 0x57, 0x34, 0x7c, 0, 0, 0xaa, 0x11, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac})
	le.PutUint64(entry[32:], 8)
	le.PutUint64(entry[40:], 15)
	copy(image[8*512:], "partition")
	source, size, err := APFSPartition(bytes.NewReader(image), int64(len(image)))
	if err != nil || size != 8*512 {
		t.Fatalf("partition: %d %v", size, err)
	}
	got := make([]byte, 9)
	if _, err := source.ReadAt(got, 0); err != nil || string(got) != "partition" {
		t.Fatalf("partition data: %q %v", got, err)
	}
	le.PutUint64(entry[40:], 64) // ends past the image
	if _, _, err := APFSPartition(bytes.NewReader(image), int64(len(image))); err == nil {
		t.Fatal("accepted out-of-bounds partition")
	}
}

// FuzzAPFSPartition feeds arbitrary images to the GPT parser. A returned
// partition must lie inside the image.
func FuzzAPFSPartition(f *testing.F) {
	le := binary.LittleEndian
	image := make([]byte, 4*512) // small seeds keep input minimization fast
	f.Add(bytes.Clone(image))
	copy(image[512:], "EFI PART")
	le.PutUint64(image[512+72:], 2)
	le.PutUint32(image[512+80:], 2)
	le.PutUint32(image[512+84:], 128)
	f.Add(bytes.Clone(image))
	copy(image[2*512:], []byte{0xef, 0x57, 0x34, 0x7c, 0, 0, 0xaa, 0x11, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac})
	le.PutUint64(image[2*512+32:], 3)
	le.PutUint64(image[2*512+40:], 3)
	f.Add(image)
	f.Fuzz(func(t *testing.T, data []byte) {
		source, size, err := APFSPartition(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		if size <= 0 || size > int64(len(data)) {
			t.Fatalf("partition of %d bytes in an image of %d", size, len(data))
		}
		if _, err := source.ReadAt(make([]byte, 1), size-1); err != nil {
			t.Fatalf("partition end unreadable: %v", err)
		}
	})
}
