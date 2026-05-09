package dyld

import (
	"strings"
	"testing"
	"unsafe"

	mtypes "github.com/blacktop/go-macho/types"
)

func TestDylibsTrieInfoRejectsOldHeader(t *testing.T) {
	f := fileWithHeader(CacheHeader{
		MappingOffset:    dylibsTrieFieldEnd() - 1,
		DylibsTrieAddr:   0x180000000,
		DylibsTrieSize:   0x180028000,
		SharedRegionSize: 0x100000,
	}, 0x100000)

	_, _, err := f.dylibsTrieInfo()
	if err == nil {
		t.Fatal("expected old header error")
	}
	if !strings.Contains(err.Error(), "does not contain dylibs trie info") {
		t.Fatalf("expected missing trie error, got %v", err)
	}
}

func TestDylibsTrieInfoRejectsImpossibleSize(t *testing.T) {
	f := fileWithHeader(CacheHeader{
		MappingOffset:  dylibsTrieFieldEnd(),
		DylibsTrieAddr: 0x180000000,
		DylibsTrieSize: 0x1001,
	}, 0x1000)

	_, _, err := f.dylibsTrieInfo()
	if err == nil {
		t.Fatal("expected oversized trie error")
	}
	if !strings.Contains(err.Error(), "exceeds cache size") {
		t.Fatalf("expected size guard error, got %v", err)
	}
}

func TestDylibsTrieInfoAcceptsPresentFields(t *testing.T) {
	f := fileWithHeader(CacheHeader{
		MappingOffset:  dylibsTrieFieldEnd(),
		DylibsTrieAddr: 0x180000000,
		DylibsTrieSize: 0x20,
	}, 0x1000)

	addr, size, err := f.dylibsTrieInfo()
	if err != nil {
		t.Fatalf("dylibsTrieInfo returned error: %v", err)
	}
	if addr != 0x180000000 {
		t.Fatalf("expected trie addr 0x180000000, got %#x", addr)
	}
	if size != 0x20 {
		t.Fatalf("expected trie size 0x20, got %#x", size)
	}
}

func dylibsTrieFieldEnd() uint32 {
	return uint32(unsafe.Offsetof(CacheHeader{}.DylibsTrieSize) + unsafe.Sizeof(CacheHeader{}.DylibsTrieSize))
}

func fileWithHeader(header CacheHeader, size int64) *File {
	var uuid mtypes.UUID
	return &File{
		UUID: uuid,
		Headers: map[mtypes.UUID]CacheHeader{
			uuid: header,
		},
		size: size,
	}
}
