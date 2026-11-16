package aea

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// FuzzNewReader feeds arbitrary archives to the prologue parser and, when one
// opens, reads from it.
func FuzzNewReader(f *testing.F) {
	key := bytes.Repeat([]byte{7}, 32)
	dir := f.TempDir()
	input := filepath.Join(dir, "payload")
	if err := os.WriteFile(input, bytes.Repeat([]byte("fuzz"), 64), 0600); err != nil {
		f.Fatal(err)
	}
	if err := Encrypt(input, &EncryptConfig{Output: dir, SymmetricKey: key}); err != nil {
		f.Fatal(err)
	}
	encoded, err := os.ReadFile(input + ".aea")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add(encoded[:len(encoded)/2])
	f.Add([]byte(Magic))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReader(bytes.NewReader(data), int64(len(data)), key)
		if err != nil {
			return
		}
		buf := make([]byte, 64)
		for _, off := range []int64{0, r.Size() / 2, r.Size() - 1} {
			if n, _ := r.ReadAt(buf, off); int64(n) > max(0, r.Size()-off) {
				t.Fatalf("read %d bytes at %d of %d", n, off, r.Size())
			}
		}
	})
}

// FuzzWalkSegments authenticates one cluster header whose segment entries are
// the fuzz input, so the walk's bounds checks are reached rather than stopped
// at the HMAC.
func FuzzWalkSegments(f *testing.F) {
	entries := make([]byte, 2*(8+32))
	binary.LittleEndian.PutUint32(entries, 64)
	binary.LittleEndian.PutUint32(entries[4:], 50)
	binary.LittleEndian.PutUint32(entries[40:], 36)
	binary.LittleEndian.PutUint32(entries[44:], 36)
	f.Add(uint64(100), uint32(64), uint16(4), uint8(Sha256), uint16(200), entries)
	f.Add(uint64(0), uint32(1), uint16(1), uint8(None), uint16(0), []byte{})
	f.Add(uint64(1<<40), uint32(1<<20), uint16(256), uint8(Murmur), uint16(0), entries)
	mainKey := bytes.Repeat([]byte{9}, 32)
	f.Fuzz(func(t *testing.T, fileSize uint64, segmentSize uint32, segments uint16, checksum uint8, padding uint16, entries []byte) {
		root := RootHeader{FileSize: fileSize, SegmentSize: segmentSize, SegmentsPerCluster: uint32(segments), Checksum: checksumType(checksum)}
		headers := make([]byte, (int(checksumSize[root.Checksum])+8)*int(segments))
		copy(headers, entries)
		macs := make([]byte, 32+32*int(segments))
		_, material, err := clusterKeyMaterial(mainKey, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := decryptCTRInPlace(headers, material.Key[:], material.IV[:]); err != nil {
			t.Fatal(err)
		}
		clusterMAC := getHMAC(material.MAC[:], headers, macs)
		payload := int64(len(headers) + len(macs))
		archive := append(append(headers, macs...), make([]byte, padding)...)
		size := int64(len(archive))
		root.EncyptedSize = uint64(size)
		checksumBytes, err := validateRoot(root, size)
		if err != nil {
			return
		}
		var output int64
		end, _, err := walkSegments(context.Background(), bytes.NewReader(archive), 0, size, mainKey, clusterMAC, root, checksumBytes, func(job decryptSegment) error {
			if job.input < payload || job.input+int64(job.header.CompressedSize) > size {
				t.Fatalf("segment input %d+%d outside payload [%d, %d)", job.input, job.header.CompressedSize, payload, size)
			}
			if job.output != output {
				t.Fatalf("segment output %d; expected %d", job.output, output)
			}
			output += int64(job.header.DecompressedSize)
			return nil
		})
		if err == nil && (uint64(output) != root.FileSize || end > size) {
			t.Fatalf("walk covered %d of %d bytes and ended at %d of %d", output, root.FileSize, end, size)
		}
	})
}
