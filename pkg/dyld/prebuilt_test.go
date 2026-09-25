package dyld

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"unsafe"
)

func prebuiltTestFile(t testing.TB, count uint32, index uint64) (*File, *countingReaderAt, prebuiltLoaderSetHeader) {
	t.Helper()
	f, r := trieTestFile(t, map[string]uint64{"/lib/test": index})
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

func TestGetDylibPrebuiltLoaderIndex(t *testing.T) {
	for _, index := range []uint64{0, 1, 2, 1 << 63, ^uint64(0)} {
		f, _, _ := prebuiltTestFile(t, 2, index)
		got, err := f.GetDylibPrebuiltLoader("/lib/test")
		if index < 2 {
			if err != nil || got.Loader.Magic != LoaderMagic {
				t.Fatalf("index %d: %v", index, err)
			}
		} else if err == nil {
			t.Fatalf("index %d accepted", index)
		}
	}
}

func TestPrebuiltLoaderSetBounds(t *testing.T) {
	for _, edit := range []struct {
		name   string
		change func(*prebuiltLoaderSetHeader)
	}{
		{"short header", func(h *prebuiltLoaderSetHeader) { h.Length = 8 }},
		{"oversized set", func(h *prebuiltLoaderSetHeader) { h.Length++ }},
		{"array starts past set", func(h *prebuiltLoaderSetHeader) { h.LoadersArrayOffset = h.Length + 1 }},
		{"array crosses end", func(h *prebuiltLoaderSetHeader) { h.LoadersArrayOffset = h.Length - 1 }},
		{"oversized array", func(h *prebuiltLoaderSetHeader) { h.LoadersArrayCount = 1 << 22 }},
	} {
		t.Run(edit.name, func(t *testing.T) {
			f, r, header := prebuiltTestFile(t, 2, 0)
			edit.change(&header)
			var b bytes.Buffer
			if err := binary.Write(&b, binary.LittleEndian, header); err != nil {
				t.Fatal(err)
			}
			copy(r.data[0x400:], b.Bytes())
			if _, err := f.GetDylibPrebuiltLoader("/lib/test"); err == nil {
				t.Fatal("malformed set accepted by lookup")
			}
			if _, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(bytes.NewReader(r.data), 0x400, 1<<63-1)); err == nil {
				t.Fatal("malformed set accepted by full parser")
			}
		})
	}
}

func BenchmarkGetDylibPrebuiltLoader(b *testing.B) {
	f, _, _ := prebuiltTestFile(b, 4096, 4095)
	for b.Loop() {
		if _, err := f.GetDylibPrebuiltLoader("/lib/test"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestGetDylibPrebuiltLoaderReadsOnlySelectedOffset(t *testing.T) {
	f, r, _ := prebuiltTestFile(t, 4096, 4095)
	if _, err := f.GetDylibPrebuiltLoader("/lib/test"); err != nil {
		t.Fatal(err)
	}
	if r.bytesRead != 4 {
		t.Fatalf("offset array bytes read=%d, want 4", r.bytesRead)
	}
}

func TestPrebuiltLoaderSetRejectsLoaderOffsetAtEnd(t *testing.T) {
	f, r, header := prebuiltTestFile(t, 1, 0)
	binary.LittleEndian.PutUint32(r.data[0x400+header.LoadersArrayOffset:], header.Length)
	if _, err := f.GetDylibPrebuiltLoader("/lib/test"); err == nil {
		t.Fatal("loader at set end accepted")
	}
	if _, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(bytes.NewReader(r.data), 0x400, 1<<63-1)); err == nil {
		t.Fatal("full parser accepted loader at set end")
	}
}

type prebuiltEOFReader struct{ io.ReaderAt }

func (r prebuiltEOFReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, off)
	if n == len(p) {
		err = io.EOF
	}
	return n, err
}

func TestPrebuiltLoaderSetAcceptsCompleteEOFReads(t *testing.T) {
	f, r, _ := prebuiltTestFile(t, 1, 0)
	f.r[f.UUID] = prebuiltEOFReader{r}
	if _, err := f.GetDylibPrebuiltLoader("/lib/test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(prebuiltEOFReader{bytes.NewReader(r.data)}, 0x400, 1<<63-1)); err != nil {
		t.Fatal(err)
	}
}
