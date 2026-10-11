package dyld

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

// syntheticLayout selects which header shape syntheticPrimaryBytes produces.
type syntheticLayout int

const (
	layoutSelfContained     syntheticLayout = iota
	layoutOneSubcache                       // declares ".01" with UUID 2
	layoutCountWithoutArray                 // declares a subcache but no array
	layoutWithSymbols                       // references a .symbols file with UUID 3
	layoutOneOldSubcache                    // declares UUID 2 without a suffix
)

// fakeCodeSignature is the smallest blob codesign.ParseCodeSignature accepts.
var fakeCodeSignature = []uint32{0xfade0cc0, 12, 0}

// syntheticPrimaryBytes builds a minimal arm64e x1 primary with no mappings or
// images. It contains no real device data.
func syntheticPrimaryBytes(t *testing.T, layout syntheticLayout, mutate ...func(*CacheHeader)) []byte {
	t.Helper()
	var header CacheHeader
	copy(header.Magic[:], "dyld_v1arm64ex1")
	header.UUID[0] = 1
	header.MappingOffset = uint32(binary.Size(header))
	header.CodeSignatureOffset = uint64(binary.Size(header))
	header.CodeSignatureSize = 12
	var entry subcacheEntry
	entry.UUID[0] = 2
	copy(entry.FileSuffix[:], ".01")
	switch layout {
	case layoutSelfContained:
	case layoutOneSubcache, layoutOneOldSubcache:
		header.SubCacheArrayCount = 1
		header.SubCacheArrayOffset = uint32(binary.Size(header)) + 12
		if layout == layoutOneOldSubcache {
			header.MappingOffset = 0x1ff
		}
	case layoutCountWithoutArray:
		header.SubCacheArrayCount = 1
	case layoutWithSymbols:
		header.SymbolFileUUID[0] = 3
	}
	for _, fn := range mutate {
		fn(&header)
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&data, binary.BigEndian, fakeCodeSignature); err != nil {
		t.Fatal(err)
	}
	if layout == layoutOneSubcache {
		if err := binary.Write(&data, binary.LittleEndian, entry); err != nil {
			t.Fatal(err)
		}
	}
	if layout == layoutOneOldSubcache {
		if err := binary.Write(&data, binary.LittleEndian, subcacheEntryV1{UUID: entry.UUID}); err != nil {
			t.Fatal(err)
		}
	}
	return data.Bytes()
}

func writeSyntheticUniversalFamily(t *testing.T, dir string) []string {
	t.Helper()
	base := filepath.Join(dir, "dyld_shared_cache_arm64e")
	mains := []string{base, base + ".development"}
	for i, name := range mains {
		data := syntheticPrimaryBytes(t, layoutOneSubcache, func(h *CacheHeader) {
			h.UUID[0] = byte(i + 4)
			h.CacheType = CacheTypeUniversal
			h.CacheSubType = uint32(1 - i)
			h.Platform = types.Platform_macOS
			h.ImagesOffset = h.MappingOffset
			h.DylibsTrieAddr = 0x1000
			h.SymbolFileUUID[0] = 3
		})
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSyntheticMember(t, base+".01", 2, nil)
	writeSyntheticMember(t, base+".symbols", 3, nil)
	return mains
}

func TestOpenUniversalCacheFamily(t *testing.T) {
	for _, main := range writeSyntheticUniversalFamily(t, t.TempDir()) {
		f, err := Open(main)
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Headers) != 3 || f.symUUID != (types.UUID{3}) {
			t.Errorf("Open(%s) loaded wrong resources: headers=%v symbols=%s", main, f.Headers, f.symUUID)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenOldNumberedDevelopmentCache(t *testing.T) {
	main := filepath.Join(t.TempDir(), "dyld_shared_cache_arm64e.development")
	data := syntheticPrimaryBytes(t, layoutOneOldSubcache, func(h *CacheHeader) {
		h.CacheType = CacheTypeUniversal
	})
	if err := os.WriteFile(main, data, 0o600); err != nil {
		t.Fatal(err)
	}
	writeSyntheticMember(t, main+".1", 2, nil)
	f, err := Open(main)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeSyntheticPrimary(t *testing.T, dir string, layout syntheticLayout) string {
	t.Helper()
	path := filepath.Join(dir, "dyld_shared_cache_arm64e_x1")
	if err := os.WriteFile(path, syntheticPrimaryBytes(t, layout), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeSyntheticMember writes a member with a complete header, UUID byte 0 set
// to id, and a fake code signature, after letting mutate adjust the header.
func writeSyntheticMember(t *testing.T, path string, id byte, mutate func(*CacheHeader)) {
	t.Helper()
	var header CacheHeader
	copy(header.Magic[:], "dyld_v1arm64ex1")
	header.UUID[0] = id
	header.MappingOffset = uint32(binary.Size(header))
	header.CodeSignatureOffset = uint64(binary.Size(header))
	header.CodeSignatureSize = 12
	if mutate != nil {
		mutate(&header)
	}
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&data, binary.BigEndian, fakeCodeSignature); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// declareMissingMapping makes a member header point at a mapping that lies
// past the end of the file so parseCache fails on it.
func declareMissingMapping(h *CacheHeader) { h.MappingCount = 1 }

func mustFailOpen(t *testing.T, primary, want string) {
	t.Helper()
	f, err := Open(primary)
	if err == nil {
		_ = f.Close() // the test fails regardless; nothing to report about Close
		t.Fatalf("Open accepted %s, want error containing %q", primary, want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want it to contain %q", err, want)
	}
}

func TestOpenRejectsDeclaredSubcachesWithoutArray(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutCountWithoutArray)
	mustFailOpen(t, primary, "declares 1 subcaches but no subcache array")
}

func TestOpenSurfacesTruncatedSubcache(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutOneSubcache)
	// The subcache header is complete and its UUID matches, but it declares a
	// mapping that lies past the end of the file. Before the fix parseCache's
	// error was discarded and the family opened as if it were intact.
	writeSyntheticMember(t, primary+".01", 2, declareMissingMapping)
	mustFailOpen(t, primary, "failed to parse cache "+primary+".01")
}

func TestOpenReportsMissingSubcache(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutOneSubcache)
	mustFailOpen(t, primary, primary+".01")
}

func TestOpenMissingSubcacheIsNotExist(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutOneSubcache)
	_, err := Open(primary)
	if !os.IsNotExist(err) {
		t.Fatalf("os.IsNotExist(%v) = false, want the bare missing-file error", err)
	}
}

func TestOpenRejectsSubcacheUUIDMismatchBeforeParsing(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutOneSubcache)
	// Wrong UUID and an unparsable body: the mismatch must win.
	writeSyntheticMember(t, primary+".01", 9, declareMissingMapping)
	mustFailOpen(t, primary, "did NOT match expected UUID")
}

func TestOpenRejectsStaleSymbolsFile(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutWithSymbols)
	writeSyntheticMember(t, primary+".symbols", 9, declareMissingMapping)
	mustFailOpen(t, primary, ".symbols UUID")
}

func TestOpenIgnoresSubcacheArrayDeclaredByMember(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutOneSubcache)
	// dyld zeroes the array count in members; one that carries a bogus array
	// must not replace the primary's SubCacheInfo mid-open.
	writeSyntheticMember(t, primary+".01", 2, func(h *CacheHeader) {
		h.SubCacheArrayCount = 7
		h.SubCacheArrayOffset = 1
	})
	f, err := Open(primary)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if len(f.SubCacheInfo) != 1 || f.SubCacheInfo[0].UUID[0] != 2 {
		t.Fatalf("SubCacheInfo = %+v, want the primary's single entry", f.SubCacheInfo)
	}
}

func TestOpenSelfContainedCache(t *testing.T) {
	primary := writeSyntheticPrimary(t, t.TempDir(), layoutSelfContained)
	f, err := Open(primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

func TestGetSubCacheExtensionDefaultsToOneBasedNumbering(t *testing.T) {
	f := &File{SubCacheInfo: make([]SubcacheEntry, 2)}
	f.SubCacheInfo[0].UUID[0] = 1
	f.SubCacheInfo[1].UUID[0] = 2
	f.SubCacheInfo[1].Extention = ".02"
	for _, tt := range []struct {
		id   byte
		want string
	}{{1, ".1"}, {2, ".02"}} {
		var uuid [16]byte
		uuid[0] = tt.id
		got, err := f.GetSubCacheExtensionFromUUID(uuid)
		if err != nil || got != tt.want {
			t.Fatalf("extension(%d) = %q, %v; want %q", tt.id, got, err, tt.want)
		}
	}
}
