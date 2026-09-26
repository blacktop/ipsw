package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
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

func TestPrebuiltMalformedArrayCounts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*prebuiltLoaderSetHeader, *bytes.Buffer)
	}{
		{"LoadersArrayCount", func(h *prebuiltLoaderSetHeader, b *bytes.Buffer) { h.LoadersArrayCount = ^uint32(0) }},
		{"objc selector Mask+1", func(h *prebuiltLoaderSetHeader, b *bytes.Buffer) {
			h.ObjcSelectorHashTableOffset = uint32(b.Len())
			binary.Write(b, binary.LittleEndian, objCStringTable{Mask: ^uint32(0)})
		}},
		{"objc selector Capacity", func(h *prebuiltLoaderSetHeader, b *bytes.Buffer) {
			h.ObjcSelectorHashTableOffset = uint32(b.Len())
			binary.Write(b, binary.LittleEndian, objCStringTable{Capacity: ^uint32(0)})
			b.WriteByte(0) // One valid tab byte precedes the absent checkbytes.
		}},
		{"swift type nodeBufferCount", func(h *prebuiltLoaderSetHeader, b *bytes.Buffer) {
			h.SwiftTypeConformanceTableOffset = uint32(b.Len())
			binary.Write(b, binary.LittleEndian, SwiftConformanceMultiMap{})
			binary.Write(b, binary.LittleEndian, uint64(0)) // Empty hash buffer.
			binary.Write(b, binary.LittleEndian, uint64(1<<32))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, source, h := prebuiltTestFile(t, 1, 0)
			f.ByteOrder = binary.LittleEndian
			b := bytes.NewBuffer(append([]byte(nil), source.data[0x400:]...))
			tc.setup(&h, b)
			var header bytes.Buffer
			if err := binary.Write(&header, binary.LittleEndian, h); err != nil {
				t.Fatal(err)
			}
			copy(b.Bytes(), header.Bytes())
			// Watch all attempted reads beyond the real data, including failed probes.
			r := &countingReaderAt{data: b.Bytes(), watchOff: int64(b.Len()), watchEnd: 1<<63 - 1}
			_, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(r, 0, 1<<63-1))
			if err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("want %s error, got %v", tc.name, err)
			}
			if r.reads != 1 || r.bytesRead != 1 {
				t.Fatalf("out-of-data reads=%d bytes=%d, want one final-byte probe", r.reads, r.bytesRead)
			}
		})
	}
}

func TestPrebuiltArrayExtent(t *testing.T) {
	for _, tc := range []struct {
		name        string
		offset      int64
		size, count uint64
		wantError   bool
		wantReads   int
	}{
		{"empty", 8, 8, 0, false, 0},
		{"exact end", 0, 4, 2, false, 1},
		{"past end", 0, 4, 3, true, 1},
		{"product overflow", 0, 8, ^uint64(0), true, 0},
		{"int overflow", 0, 1, uint64(^uint(0)>>1) + 1, true, 0},
		{"offset overflow", 1<<63 - 2, 4, 1, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReaderAt{data: make([]byte, 8), watchEnd: 1<<63 - 1}
			sr := io.NewSectionReader(r, 0, 1<<63-1)
			if _, err := sr.Seek(tc.offset, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			err := checkPrebuiltArray(sr, tc.size, tc.count, "testCount")
			if (err != nil) != tc.wantError || (err != nil && !strings.Contains(err.Error(), "testCount")) {
				t.Fatalf("unexpected error: %v", err)
			}
			if r.reads != tc.wantReads || r.bytesRead != int64(tc.wantReads) {
				t.Fatalf("reads=%d bytes=%d, want %d single-byte probes", r.reads, r.bytesRead, tc.wantReads)
			}
			if pos, _ := sr.Seek(0, io.SeekCurrent); pos != tc.offset {
				t.Fatalf("probe moved position to %d", pos)
			}
		})
	}
}

func TestPrebuiltNestedArrayBeyondSetLength(t *testing.T) {
	f, r, h := prebuiltTestFile(t, 1, 0)
	loaderOffset := binary.LittleEndian.Uint32(r.data[0x400+h.LoadersArrayOffset:])
	bodyOffset := int(0x400+loaderOffset) + binary.Size(Loader{})
	var body prebuiltLoaderHeader
	if err := binary.Read(bytes.NewReader(r.data[bodyOffset:]), binary.LittleEndian, &body); err != nil {
		t.Fatal(err)
	}
	body.BindTargetRefsOffset = uint16(h.Length - loaderOffset)
	body.BindTargetRefsCount = 1
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, body); err != nil {
		t.Fatal(err)
	}
	copy(r.data[bodyOffset:], encoded.Bytes())
	// The payload starts exactly outside the declared set, but is readable from
	// the nested loader reader. Length must not become a nested payload limit.
	r.data = append(r.data, make([]byte, 8)...)
	got, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(r, 0x400, 1<<63-1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Loaders) != 1 || len(got.Loaders[0].BindTargets) != 1 {
		t.Fatalf("nested bind targets not parsed: %+v", got.Loaders)
	}
}

func TestPrebuiltSelectorTableRequiresLoader(t *testing.T) {
	testPrebuiltEmptyLoaders(t, "selector")
}

func TestPrebuiltClassTableRequiresLoader(t *testing.T) {
	testPrebuiltEmptyLoaders(t, "class")
}

func TestPrebuiltProtocolTableRequiresLoader(t *testing.T) {
	testPrebuiltEmptyLoaders(t, "protocol")
}

func TestPrebuiltEmptySetWithoutObjCTables(t *testing.T) {
	testPrebuiltEmptyLoaders(t, "")
}

func testPrebuiltEmptyLoaders(t *testing.T, table string) {
	t.Helper()
	f, r, h := prebuiltTestFile(t, 0, 0)
	switch table {
	case "selector":
		h.ObjcSelectorHashTableOffset = h.LoadersArrayOffset
	case "class":
		h.ObjcClassHashTableOffset = h.LoadersArrayOffset
	case "protocol":
		h.ObjcProtocolHashTableOffset = h.LoadersArrayOffset
	}
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, h); err != nil {
		t.Fatal(err)
	}
	copy(r.data[0x400:], encoded.Bytes())
	got, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(r, 0x400, 1<<63-1))
	if table == "" {
		if err != nil {
			t.Fatalf("empty set without ObjC tables: %v", err)
		}
		if got == nil || len(got.Loaders) != 0 || got.SelectorTable != nil || got.ClassTable != nil || got.ProtocolTable != nil {
			t.Fatalf("want empty set without ObjC tables, got %+v", got)
		}
		return
	}
	if got != nil || err == nil {
		t.Fatalf("want missing loader error and nil set, got %+v, %v", got, err)
	}
	for _, want := range []string{
		"requires at least one loader (LoadersArrayCount=0)",
		fmt.Sprintf("ObjcSelectorHashTableOffset=%#x", h.ObjcSelectorHashTableOffset),
		fmt.Sprintf("ObjcClassHashTableOffset=%#x", h.ObjcClassHashTableOffset),
		fmt.Sprintf("ObjcProtocolHashTableOffset=%#x", h.ObjcProtocolHashTableOffset),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in missing loader error, got %v", want, err)
		}
	}
	if table == "selector" && !strings.Contains(err.Error(), "prebuilt objc selector table requires at least one loader (LoadersArrayCount=0)") {
		t.Errorf("selector error text changed: %v", err)
	}
}

func TestPrebuiltTwinIndex(t *testing.T) {
	for _, tc := range []struct {
		name  string
		index uint16
		count int
		want  string
	}{
		{"first", 0, 2, "first"},
		{"last", 1, 2, "last"},
		{"at end", 2, 2, ""},
		{"large index", NoUnzipperedTwin - 1, 2, ""},
		{"empty images", 0, 0, ""},
		{"no twin", NoUnzipperedTwin, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, r, h := prebuiltTestFile(t, 1, 0)
			f.Images = cacheImages{&CacheImage{Name: "first"}, &CacheImage{Name: "last"}}[:tc.count]
			loaderOffset := binary.LittleEndian.Uint32(r.data[0x400+h.LoadersArrayOffset:])
			bodyOffset := int(0x400+loaderOffset) + binary.Size(Loader{})
			var body prebuiltLoaderHeader
			if err := binary.Read(bytes.NewReader(r.data[bodyOffset:]), binary.LittleEndian, &body); err != nil {
				t.Fatal(err)
			}
			body.IndexOfTwin = tc.index
			var encoded bytes.Buffer
			if err := binary.Write(&encoded, binary.LittleEndian, body); err != nil {
				t.Fatal(err)
			}
			copy(r.data[bodyOffset:], encoded.Bytes())
			got, err := f.GetDylibPrebuiltLoader("/lib/test")
			if tc.index != NoUnzipperedTwin && int(tc.index) >= tc.count {
				want := fmt.Sprintf("prebuilt loader IndexOfTwin %d out of range for %d images", tc.index, tc.count)
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("want %q, got %v", want, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Twin != tc.want {
				t.Fatalf("twin = %q, want %q", got.Twin, tc.want)
			}
		})
	}
}
