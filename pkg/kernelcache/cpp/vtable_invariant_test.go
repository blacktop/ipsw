package cpp

import (
	"encoding/binary"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// vtableInvariantFixture builds a synthetic non-fileset kernelcache Mach-O with
// a single __DATA_CONST section holding one C++ vtable. The two Itanium ABI
// header slots (offset-to-top at addr-16, RTTI at addr-8) are zeroed and the
// first vmethod pointer lives at the vtable base, mirroring how
// findVtableBySymbol reports VtableAddr = __ZTV + 16.
type vtableInvariantFixture struct {
	scanner    *Scanner
	owner      *macho.File
	sectionVM  uint64
	vtableAddr uint64
	data       []byte
	vmethods   []uint64
}

func newVtableInvariantFixture(t *testing.T) *vtableInvariantFixture {
	t.Helper()

	const sectionVM = uint64(0xfffffe0007000000)
	const sectionSize = uint64(0x1000)
	vtableAddr := sectionVM + 16 // skip offset-to-top + RTTI header slots

	owner := &macho.File{}
	owner.Sections = []*types.Section{
		{SectionHeader: types.SectionHeader{
			Name: "__const", Seg: "__DATA_CONST", Addr: sectionVM, Size: sectionSize,
		}},
	}

	data := make([]byte, sectionSize)
	vmethods := []uint64{0xfffffe0000010000, 0xfffffe0000010100, 0xfffffe0000010200}

	s := NewScanner(owner, Config{})
	s.sectionData[sectionKey{file: owner, addr: sectionVM}] = data
	fwd := make(map[uint64]uint64, len(vmethods))
	for i, ptr := range vmethods {
		fwd[vtableAddr+uint64(i*8)] = ptr
	}
	s.forwardPointers[owner] = fwd

	return &vtableInvariantFixture{
		scanner:    s,
		owner:      owner,
		sectionVM:  sectionVM,
		vtableAddr: vtableAddr,
		data:       data,
		vmethods:   vmethods,
	}
}

func TestLooksLikeVtableStartRequiresZeroHeaderSlots(t *testing.T) {
	t.Parallel()

	f := newVtableInvariantFixture(t)

	if !f.scanner.looksLikeVtableStart(f.owner, f.vtableAddr) {
		t.Fatal("vtable start with zero header slots and a valid first vmethod should be accepted")
	}

	// Offset-to-top header slot at addr-16 is non-zero → reject.
	binary.LittleEndian.PutUint64(f.data[0:8], 0x8)
	if f.scanner.looksLikeVtableStart(f.owner, f.vtableAddr) {
		t.Fatal("non-zero offset-to-top header slot must reject the vtable start")
	}
	binary.LittleEndian.PutUint64(f.data[0:8], 0)

	// RTTI header slot at addr-8 is non-zero → reject.
	binary.LittleEndian.PutUint64(f.data[8:16], 0xfffffe0000abcdef)
	if f.scanner.looksLikeVtableStart(f.owner, f.vtableAddr) {
		t.Fatal("non-zero RTTI header slot must reject the vtable start")
	}
	binary.LittleEndian.PutUint64(f.data[8:16], 0)

	if !f.scanner.looksLikeVtableStart(f.owner, f.vtableAddr) {
		t.Fatal("vtable start should be accepted again after restoring zero header slots")
	}
}

func TestVtableSlotOffsetsAreIndexTimesEightFromFirstVmethod(t *testing.T) {
	t.Parallel()

	f := newVtableInvariantFixture(t)
	class := Class{Name: "SyntheticClass", VtableAddr: f.vtableAddr, MetaPtr: f.vtableAddr}

	for idx := range f.vmethods {
		addr, ok := f.scanner.VtableSlotAddress(class, idx)
		if !ok {
			t.Fatalf("slot %d address unavailable", idx)
		}
		if want := f.vtableAddr + uint64(idx*8); addr != want {
			t.Fatalf("slot %d addr = %#x, want %#x (slotOffset must equal index*8)", idx, addr, want)
		}
	}

	// VtableAddr points at the first vmethod, 16 bytes past the __ZTV base, so
	// slot 0 is never the offset-to-top/RTTI header.
	if got := f.vtableAddr - f.sectionVM; got != 16 {
		t.Fatalf("vtable base offset from __ZTV = %d, want 16", got)
	}

	entries := f.scanner.VtableEntries(class, len(f.vmethods))
	if len(entries) != len(f.vmethods) {
		t.Fatalf("decoded %d vtable entries, want %d", len(entries), len(f.vmethods))
	}
	for idx, entry := range entries {
		if entry.Index != idx {
			t.Fatalf("entry %d has Index %d", idx, entry.Index)
		}
		if entry.SlotAddress != f.vtableAddr+uint64(idx*8) {
			t.Fatalf("entry %d slot addr = %#x, want %#x", idx, entry.SlotAddress, f.vtableAddr+uint64(idx*8))
		}
		if entry.SlotAddress < f.vtableAddr {
			t.Fatalf("entry %d addresses a header slot at %#x below the vtable base", idx, entry.SlotAddress)
		}
		if entry.Address != f.vmethods[idx] {
			t.Fatalf("entry %d target = %#x, want vmethod %#x", idx, entry.Address, f.vmethods[idx])
		}
	}
}
