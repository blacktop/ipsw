package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func fixupFilesetFixture(t testing.TB, count int) (*macho.File, []uint64) {
	t.Helper()
	const base = uint64(0x100000000)
	const entrySize = 64
	commandSize := 152 + count*entrySize
	firstEntry := (32 + commandSize + 0xfff) &^ 0xfff
	rootSection := firstEntry + count*0x200
	data := make([]byte, rootSection+0x1000)
	name := func(value string) (out [16]byte) { copy(out[:], value); return }
	write := func(dst *bytes.Buffer, value any) {
		t.Helper()
		if err := binary.Write(dst, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	var outer bytes.Buffer
	write(&outer, types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64,
		Type: types.MH_FILESET, NCommands: uint32(count + 1), SizeCommands: uint32(commandSize)})
	write(&outer, types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 152, Name: name("__TEXT"),
		Addr: base, Memsz: uint64(len(data)), Filesz: uint64(len(data)), Nsect: 1})
	write(&outer, types.Section64{Name: name("__root"), Seg: name("__TEXT"),
		Addr: base + uint64(rootSection), Size: 0x20, Offset: uint32(rootSection)})
	addresses := make([]uint64, 0, count+2)
	for i := range count {
		offset := firstEntry + i*0x200
		id := fmt.Sprintf("com.example.fixture.%03d", i)
		write(&outer, types.FilesetEntryCmd{LoadCmd: types.LC_FILESET_ENTRY, Len: entrySize,
			Addr: base + uint64(offset), FileOffset: uint64(offset), EntryIdOffset: 32})
		var entryName [entrySize - 32]byte
		copy(entryName[:], id)
		write(&outer, entryName)
		var child bytes.Buffer
		write(&child, types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64,
			Type: types.MH_DYLIB, NCommands: 1, SizeCommands: 152})
		write(&child, types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 152, Name: name("__DATA"),
			Addr: base + uint64(offset), Memsz: 0x200, Offset: uint64(offset), Filesz: 0x200, Nsect: 1})
		write(&child, types.Section64{Name: name("__data"), Seg: name("__DATA"),
			Addr: base + uint64(offset) + 0x180, Size: 0x40, Offset: uint32(offset + 0x180)})
		copy(data[offset:], child.Bytes())
		addresses = append(addresses, base+uint64(offset)+0x188)
	}
	copy(data, outer.Bytes())
	addresses = append(addresses, base+uint64(rootSection)+8, base+uint64(len(data))+0x1000)
	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, addresses
}

func TestFixupSectionFinder(t *testing.T) {
	m, addresses := fixupFilesetFixture(t, 3)
	find := newFixupSectionFinder(m)
	section := m.FindSectionForVMAddr(addresses[0])
	addresses = append(addresses, section.Addr-1, section.Addr, section.Addr+section.Size-1, section.Addr+section.Size)
	for _, address := range addresses {
		want := m.FindSectionForVMAddr(address)
		got := find(address)
		if want == nil {
			if got != nil {
				t.Errorf("address %#x: unexpected section %s", address, got.Name)
			}
			continue
		}
		if got == nil || got.SectionHeader != want.SectionHeader {
			t.Errorf("address %#x: got %v, want %v", address, got, want)
		}
	}
	first, second := find(addresses[0]), find(addresses[0])
	if first == nil || second == nil || first == second || first.Name != second.Name {
		t.Fatal("fileset lookups must retain their fresh section identity and stable name")
	}
	root := m.Section("__TEXT", "__root")
	if got := find(root.Addr); got != root {
		t.Fatal("root section identity changed")
	}

	t.Run("lookup order", func(t *testing.T) {
		m, addresses := fixupFilesetFixture(t, 2)
		entries := m.FileSets()
		entries[1].FileOffset = entries[0].FileOffset
		root := m.Section("__TEXT", "__root")
		root.Addr, root.Size = addresses[0], 1
		got := newFixupSectionFinder(m)(addresses[0])
		if got == nil || got.Name != entries[0].EntryID+".__data" {
			t.Fatalf("first child must win over later children and the root: %v", got)
		}
	})

	t.Run("name selection", func(t *testing.T) {
		m, addresses := fixupFilesetFixture(t, 2)
		entries := m.FileSets()
		entries[0].EntryID, entries[1].EntryID = "com.example.TAIL", "tail"
		// The library's case-insensitive suffix selection resolves both IDs to
		// the first image. Keep that behavior even when caching parsed images.
		if got := newFixupSectionFinder(m)(addresses[1]); got != nil {
			t.Fatalf("unexpected section from the second image: %v", got)
		}
	})

	t.Run("retry failed parse", func(t *testing.T) {
		m, addresses := fixupFilesetFixture(t, 1)
		entry := m.FileSets()[0]
		offset := entry.FileOffset
		entry.FileOffset = 1
		find := newFixupSectionFinder(m)
		if got := find(addresses[0]); got != nil {
			t.Fatalf("invalid image unexpectedly parsed: %v", got)
		}
		entry.FileOffset = offset
		if got := find(addresses[0]); got == nil || got.Name != entry.EntryID+".__data" {
			t.Fatalf("failed image was not retried: %v", got)
		}
	})
}

func BenchmarkFixupSectionLookup(b *testing.B) {
	b.Run("warm", func(b *testing.B) {
		m, addresses := fixupFilesetFixture(b, 64)
		find := newFixupSectionFinder(m)
		for _, address := range addresses {
			_ = find(address)
		}
		index := 0
		b.ReportAllocs()
		for b.Loop() {
			_ = find(addresses[index])
			index++
			if index == len(addresses) {
				index = 0
			}
		}
	})
	b.Run("scan", func(b *testing.B) {
		m, addresses := fixupFilesetFixture(b, 64)
		b.ReportAllocs()
		for b.Loop() {
			find := newFixupSectionFinder(m)
			for _, address := range addresses {
				_ = find(address)
			}
		}
		b.ReportMetric(float64(len(addresses)), "lookups/op")
	})
}
