package dyld

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"testing"
	"unsafe"

	mtypes "github.com/blacktop/go-macho/types"
)

// Keep benchmark fixtures independent of ordinary tests for base overlays.
func BenchmarkGetDylibPrebuiltLoader(b *testing.B) {
	f, _, _ := benchPrebuiltTestFile(b, 4096, 4095)
	for b.Loop() {
		if _, err := f.GetDylibPrebuiltLoader("/lib/test"); err != nil {
			b.Fatal(err)
		}
	}
}

func benchPrebuiltTestFile(t testing.TB, count uint32, index uint64) (*File, *benchCountingReaderAt, prebuiltLoaderSetHeader) {
	t.Helper()
	f, r := benchTrieTestFile(t, map[string]uint64{"/lib/test": index})
	const setOff = 0x400
	header := prebuiltLoaderSetHeader{Magic: PrebuiltLoaderSetMagic, LoadersArrayCount: count}
	header.LoadersArrayOffset = uint32(binary.Size(header))
	loaderOff := header.LoadersArrayOffset + count*4 + 4
	loader := Loader{Magic: LoaderMagic}
	body := prebuiltLoaderHeader{IndexOfTwin: NoUnzipperedTwin}
	header.Length = loaderOff + uint32(binary.Size(loader)+binary.Size(body))
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	for range count {
		if err := binary.Write(&buf, binary.LittleEndian, loaderOff); err != nil {
			t.Fatal(err)
		}
	}
	// A valid-looking offset just beyond the array must never be selected.
	if err := binary.Write(&buf, binary.LittleEndian, loaderOff); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{loader, body} {
		if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	r.data = append(r.data, make([]byte, setOff+buf.Len()-len(r.data))...)
	copy(r.data[setOff:], buf.Bytes())
	r.watchOff, r.watchEnd = setOff+int64(header.LoadersArrayOffset), setOff+int64(header.LoadersArrayOffset)+int64(count)*4
	f.Mappings[f.UUID][0].Size = uint64(len(r.data))
	f.size = int64(len(r.data))
	h := f.Headers[f.UUID]
	h.MappingOffset = uint32(unsafe.Offsetof(h.ProgramTrieSize) + unsafe.Sizeof(h.ProgramTrieSize))
	h.DylibsPblSetAddr = f.Mappings[f.UUID][0].Address + setOff
	f.Headers[f.UUID] = h
	return f, r, header
}

func benchTrieTestFile(t testing.TB, paths map[string]uint64) (*File, *benchCountingReaderAt) {
	t.Helper()
	const base, trieOff = 0x180000000, 0x100
	trie := benchDylibsTrieBytes(t, paths)
	data := make([]byte, trieOff+len(trie)+0x10)
	copy(data[trieOff:], trie)
	uuid := mtypes.UUID{1}
	r := &benchCountingReaderAt{data: data, watchOff: trieOff, watchEnd: trieOff + int64(len(trie))}
	f := &File{
		UUID: uuid,
		Headers: map[mtypes.UUID]CacheHeader{uuid: {
			MappingOffset:  benchDylibsTrieFieldEnd(),
			DylibsTrieAddr: base + trieOff,
			DylibsTrieSize: uint64(len(trie)),
		}},
		Mappings: map[mtypes.UUID]cacheMappings{uuid: {
			{CacheMappingInfo: CacheMappingInfo{Address: base, Size: uint64(len(data))}},
		}},
		r:    map[mtypes.UUID]io.ReaderAt{uuid: r},
		size: int64(len(data)),
	}
	return f, r
}

func benchDylibsTrieBytes(t testing.TB, paths map[string]uint64) []byte {
	t.Helper()
	names := slices.Sorted(func(yield func(string) bool) {
		for name := range paths {
			if !yield(name) {
				return
			}
		}
	})
	rootSize := 2
	for _, name := range names {
		rootSize += len(name) + 2 // NUL + one-byte child offset
	}
	trie := []byte{0, byte(len(names))}
	child := rootSize
	for _, name := range names {
		if child > 0x7f {
			t.Fatal("synthetic trie needs multi-byte ULEBs")
		}
		trie = append(trie, name...)
		trie = append(trie, 0, byte(child))
		child += len(binary.AppendUvarint(nil, paths[name])) + 2
	}
	for _, name := range names {
		index := binary.AppendUvarint(nil, paths[name])
		trie = append(trie, byte(len(index)))
		trie = append(trie, index...)
		trie = append(trie, 0) // no children
	}
	return trie
}

func benchDylibsTrieFieldEnd() uint32 {
	return uint32(unsafe.Offsetof(CacheHeader{}.DylibsTrieSize) + unsafe.Sizeof(CacheHeader{}.DylibsTrieSize))
}

type benchCountingReaderAt struct {
	data               []byte
	watchOff, watchEnd int64
	reads              int
	bytesRead          int64
}

func (c *benchCountingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < c.watchEnd && off+int64(len(p)) > c.watchOff {
		c.reads++
		c.bytesRead += min(off+int64(len(p)), c.watchEnd) - max(off, c.watchOff)
	}
	return bytes.NewReader(c.data).ReadAt(p, off)
}
