package dyld

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"testing"
)

func openSlideDigestCache(t testing.TB) *File {
	t.Helper()
	path := os.Getenv("DSC")
	if path == "" {
		t.Skip("set DSC to a cache path")
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// TestSlideDigest compares the observable image maps and complete mapping dumps.
// The sinfo map is keyed by raw pointer value; sorting those keys makes its
// address/value serialization independent of Go map iteration order.
func TestSlideDigest(t *testing.T) {
	if os.Getenv("DIGEST_OUT") == "" {
		t.Skip("set DIGEST_OUT to the digest output path")
	}
	f := openSlideDigestCache(t)
	out, err := os.Create(os.Getenv("DIGEST_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	for _, img := range f.Images {
		if err := img.ParseSlideInfo(); err != nil {
			t.Fatalf("%s: %v", img.Name, err)
		}
		keys := make([]uint64, 0, len(img.sinfo))
		for addr := range img.sinfo {
			keys = append(keys, addr)
		}
		slices.Sort(keys)
		h := sha256.New()
		var entry [16]byte
		for _, addr := range keys {
			binary.LittleEndian.PutUint64(entry[:8], addr)
			binary.LittleEndian.PutUint64(entry[8:], img.sinfo[addr])
			h.Write(entry[:])
		}
		if _, err := fmt.Fprintf(w, "%s\t%d\t%x\n", img.Name, len(keys), h.Sum(nil)); err != nil {
			t.Fatal(err)
		}
	}
	// Drain stdout concurrently so even multi-gigabyte dumps stay bounded.
	r, pipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = pipe
	defer func() { os.Stdout = original; pipe.Close(); r.Close() }()
	h := sha256.New()
	drained := make(chan error, 1)
	go func() { _, err := io.Copy(h, r); drained <- err }()
	uuids := make([]string, 0, len(f.MappingsWithSlideInfo))
	for uuid := range f.MappingsWithSlideInfo {
		uuids = append(uuids, uuid.String())
	}
	sort.Strings(uuids)
	var dumpErr error
	for _, name := range uuids {
		for uuid, mappings := range f.MappingsWithSlideInfo {
			if uuid.String() != name {
				continue
			}
			for _, mapping := range mappings {
				if mapping.SlideInfoSize == 0 {
					continue
				}
				if err := f.DumpSlideInfo(uuid, mapping); err != nil {
					dumpErr = err
					break
				}
			}
		}
	}
	os.Stdout = original
	if err := pipe.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
	if dumpErr != nil {
		t.Fatal(dumpErr)
	}
	if _, err := fmt.Fprintf(w, "dump\t%x\n", h.Sum(nil)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkParseSlideInfo(b *testing.B) {
	f := openSlideDigestCache(b)
	if len(f.Images) < 32 {
		b.Fatal("cache has fewer than 32 images")
	}
	images := f.Images[:32]
	for _, img := range images {
		if err := img.ParseSlideInfo(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, img := range images {
			if err := img.ParseSlideInfo(); err != nil {
				b.Fatal(err)
			}
		}
	}
}
