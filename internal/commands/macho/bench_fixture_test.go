package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// benchFixture is a little-endian arm64 executable, independent of the host
// executable, linker, firmware and filesystem. All offsets are file-relative.
func benchFixture(t testing.TB) []byte {
	t.Helper()
	const (
		base       = 0x100000000
		textOff    = 0x1000
		textSize   = 300 * 16
		cstringOff = 0x3000
		dataOff    = 0x8000
		linkOff    = 0x9000
		symOff     = 0x9200
		strOff     = symOff + 2000*16
		cmdSize    = (72 + 2*80) + (72 + 80) + 72 + 24 + 16
	)
	name := func(s string) (n [16]byte) { copy(n[:], s); return }
	var strings, symbols, cstrings bytes.Buffer
	strings.WriteByte(0)
	for i := range 2000 {
		n := fmt.Sprintf("_fixture_symbol_%04d", i)
		if i%3 == 0 {
			n = fmt.Sprintf("___block_invoke.%d.cold.1", i)
		}
		var entry [16]byte
		binary.LittleEndian.PutUint32(entry[:], uint32(strings.Len()))
		entry[4], entry[5] = 0x0f, 1 // N_SECT | N_EXT, __text
		binary.LittleEndian.PutUint64(entry[8:], base+textOff+uint64(i%300)*16)
		symbols.Write(entry[:])
		strings.WriteString(n)
		strings.WriteByte(0)
	}
	for i := range 500 {
		fmt.Fprintf(&cstrings, "fixture string %04d\x00", i)
	}
	starts := binary.AppendUvarint(nil, textOff)
	for range 299 {
		starts = binary.AppendUvarint(starts, 16)
	}
	starts = append(starts, 0)
	raw := make([]byte, strOff+strings.Len())
	var header bytes.Buffer
	write := func(v any) {
		if err := binary.Write(&header, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	// mach_header_64 (including the reserved word).
	write([8]uint32{0xfeedfacf, 0x0100000c, 0, 2, 5, cmdSize, 0, 0})
	write(types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 232, Name: name("__TEXT"), Addr: base, Memsz: dataOff, Filesz: dataOff, Maxprot: 5, Prot: 5, Nsect: 2})
	write(types.Section64{Name: name("__text"), Seg: name("__TEXT"), Addr: base + textOff, Size: textSize, Offset: textOff, Align: 2, Flags: 0x80000400})
	write(types.Section64{Name: name("__cstring"), Seg: name("__TEXT"), Addr: base + cstringOff, Size: uint64(cstrings.Len()), Offset: cstringOff, Flags: 2})
	write(types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 152, Name: name("__DATA"), Addr: base + dataOff, Memsz: 0x1000, Offset: dataOff, Filesz: 0x1000, Maxprot: 3, Prot: 3, Nsect: 1})
	write(types.Section64{Name: name("__data"), Seg: name("__DATA"), Addr: base + dataOff, Size: 0x1000, Offset: dataOff, Align: 3})
	write(types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 72, Name: name("__LINKEDIT"), Addr: base + linkOff, Memsz: uint64(len(raw) - linkOff), Offset: linkOff, Filesz: uint64(len(raw) - linkOff), Maxprot: 1, Prot: 1})
	write(types.SymtabCmd{LoadCmd: types.LC_SYMTAB, Len: 24, Symoff: symOff, Nsyms: 2000, Stroff: strOff, Strsize: uint32(strings.Len())})
	write(types.LinkEditDataCmd{LoadCmd: types.LC_FUNCTION_STARTS, Len: 16, Offset: linkOff, Size: uint32(len(starts))})
	copy(raw, header.Bytes())
	// Each synthetic function consists of three NOPs followed by RET.
	for off := textOff; off < textOff+textSize; off += 4 {
		instruction := uint32(0xd503201f)
		if (off-textOff)%16 == 12 {
			instruction = 0xd65f03c0
		}
		binary.LittleEndian.PutUint32(raw[off:], instruction)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for off := dataOff; off < linkOff; off += 8 {
		binary.LittleEndian.PutUint64(raw[off:], rng.Uint64())
	}
	copy(raw[cstringOff:], cstrings.Bytes())
	copy(raw[linkOff:], starts)
	copy(raw[symOff:], symbols.Bytes())
	copy(raw[strOff:], strings.Bytes())
	return raw
}

func openBenchFixture(t testing.TB) *macho.File {
	t.Helper()
	m, err := macho.NewFile(bytes.NewReader(benchFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestBenchFixture(t *testing.T) {
	if !bytes.Equal(benchFixture(t), benchFixture(t)) {
		t.Fatal("fixture is not deterministic")
	}
	m := openBenchFixture(t)
	if m.Symtab == nil || len(m.Symtab.Syms) != 2000 {
		t.Fatal("expected 2000 symbols")
	}
	if got := len(m.GetFunctions()); got != 300 {
		t.Fatalf("functions: got %d, want 300", got)
	}
	strs, err := m.GetCStrings()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, section := range strs {
		count += len(section)
	}
	if count != 500 {
		t.Fatalf("C strings: got %d, want 500", count)
	}
	if m.Section("__TEXT", "__text") == nil || m.Section("__TEXT", "__cstring") == nil || m.Segment("__DATA") == nil {
		t.Fatal("missing fixture sections or segments")
	}
}
