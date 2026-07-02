package cpp

import (
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

func TestDecodeSlotAuthKernelCacheAuth(t *testing.T) {
	t.Parallel()

	fx := fixupchains.DyldChainedPtr64KernelCacheRebase{
		Fixup: 0x100,
		Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0x1234, cacheLevel: 0, diversity: 0xabcd, addrDiv: 1, key: 2, next: 1, auth: true,
		}),
	}

	sa, ok := decodeSlotAuth(fx)
	if !ok {
		t.Fatal("decodeSlotAuth should recognize a kernelcache rebase slot")
	}
	if !sa.auth {
		t.Fatal("auth kcache slot must report auth=true")
	}
	if sa.pac != 0xabcd {
		t.Fatalf("pac = %#x, want 0xabcd", sa.pac)
	}
	if sa.key != 2 {
		t.Fatalf("key = %d, want 2 (DA)", sa.key)
	}
	if !sa.addrDiv {
		t.Fatal("addrDiv should be true")
	}
	if sa.cacheLevel != 0 {
		t.Fatalf("cacheLevel = %d, want 0", sa.cacheLevel)
	}
	if sa.bind {
		t.Fatal("a rebase slot must not report bind")
	}
}

func TestDecodeSlotAuthKernelCacheUnsignedReportsNonAuth(t *testing.T) {
	t.Parallel()

	// An unsigned kcache slot still carries non-zero diversity bits. decodeSlotAuth
	// must NOT surface them: auth=false with pac/key/addrDiv all zero.
	fx := fixupchains.DyldChainedPtr64KernelCacheRebase{
		Fixup: 0x108,
		Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0x5678, cacheLevel: 1, diversity: 0x9999, addrDiv: 1, key: 3, next: 1, auth: false,
		}),
	}

	sa, ok := decodeSlotAuth(fx)
	if !ok {
		t.Fatal("decodeSlotAuth should recognize an unsigned kernelcache rebase slot")
	}
	if sa.auth {
		t.Fatal("unsigned kcache slot must report auth=false")
	}
	if sa.pac != 0 {
		t.Fatalf("pac = %#x, want 0 (garbage diversity must be discarded)", sa.pac)
	}
	if sa.key != 0 {
		t.Fatalf("key = %d, want 0 for an unsigned slot", sa.key)
	}
	if sa.addrDiv {
		t.Fatal("addrDiv must be false for an unsigned slot")
	}
	if sa.cacheLevel != 1 {
		t.Fatalf("cacheLevel = %d, want 1", sa.cacheLevel)
	}
}

func TestDecodeSlotAuthArm64e(t *testing.T) {
	t.Parallel()

	fx := fixupchains.DyldChainedPtrArm64eAuthRebase{
		Fixup: 0x200,
		Pointer: encArm64eAuthRebaseSlot(arm64eAuthRebaseSlot{
			target: 0xdead, diversity: 0x1357, addrDiv: 1, key: 1, next: 2,
		}),
	}

	sa, ok := decodeSlotAuth(fx)
	if !ok {
		t.Fatal("decodeSlotAuth should recognize an arm64e auth-rebase slot")
	}
	if !sa.auth {
		t.Fatal("arm64e auth-rebase slot must report auth=true")
	}
	if sa.pac != 0x1357 {
		t.Fatalf("pac = %#x, want 0x1357", sa.pac)
	}
	if sa.key != 1 {
		t.Fatalf("key = %d, want 1 (IB)", sa.key)
	}
	if !sa.addrDiv {
		t.Fatal("addrDiv should be true")
	}
}

func TestDecodeSlotAuthPlainRebaseHasNoAuthInfo(t *testing.T) {
	t.Parallel()

	// A plain (non-auth) arm64e rebase carries no per-slot PAC information.
	fx := fixupchains.DyldChainedPtrArm64eRebase{Fixup: 0x300, Pointer: 0}
	if _, ok := decodeSlotAuth(fx); ok {
		t.Fatal("a plain arm64e rebase must not report PAC metadata")
	}
}

// pacFixture is a synthetic non-fileset kernelcache with one PAC-annotated
// vtable. It mirrors vtableInvariantFixture but also seeds slotAuthByVMAddr so
// the raw-fixup accessors can be exercised without a real chained-fixup blob.
type pacFixture struct {
	scanner        *Scanner
	owner          *macho.File
	class          Class
	vtableAddr     uint64
	cxaPureVirtual uint64
	targets        []uint64
}

func newPACFixture(t *testing.T) *pacFixture {
	t.Helper()

	const sectionVM = uint64(0xfffffe0007000000)
	const sectionSize = uint64(0x1000)
	vtableAddr := sectionVM + 16
	cxaPureVirtual := uint64(0xfffffe00000abcde)

	owner := &macho.File{}
	owner.Sections = []*types.Section{
		{SectionHeader: types.SectionHeader{
			Name: "__const", Seg: "__DATA_CONST", Addr: sectionVM, Size: sectionSize,
		}},
	}

	targets := []uint64{
		0xfffffe0000010000, // slot 0: auth
		0xfffffe0000010100, // slot 1: unsigned
		cxaPureVirtual,     // slot 2: pure virtual
		0xfffffe0000010300, // slot 3: arm64e auth
	}

	s := NewScanner(owner, Config{})
	s.cxaPureVirtual = cxaPureVirtual
	s.rootFixupsSeeded = true // absent slots resolve to "no fixup"
	s.sectionData[sectionKey{file: owner, addr: sectionVM}] = make([]byte, sectionSize)

	fwd := make(map[uint64]uint64, len(targets))
	for i, ptr := range targets {
		fwd[vtableAddr+uint64(i*8)] = ptr
	}
	s.forwardPointers[owner] = fwd

	auths := []fixupchains.Fixup{
		fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0x10000, diversity: 0xabcd, addrDiv: 1, key: 2, auth: true,
		})},
		fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0x10100, cacheLevel: 1, diversity: 0x9999, key: 3, auth: false,
		})},
		fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: encKCRebaseSlot(kcRebaseSlot{
			target: 0xabcde, diversity: 0x1111, key: 0, auth: true,
		})},
		fixupchains.DyldChainedPtrArm64eAuthRebase{Pointer: encArm64eAuthRebaseSlot(arm64eAuthRebaseSlot{
			target: 0x10300, diversity: 0x1357, addrDiv: 1, key: 1,
		})},
	}
	s.slotAuthByVMAddr = make(map[uint64]slotAuth, len(auths))
	for i, fx := range auths {
		sa, ok := decodeSlotAuth(fx)
		if !ok {
			t.Fatalf("decodeSlotAuth failed for slot %d", i)
		}
		s.slotAuthByVMAddr[vtableAddr+uint64(i*8)] = sa
	}

	return &pacFixture{
		scanner:        s,
		owner:          owner,
		class:          Class{Name: "SyntheticClass", VtableAddr: vtableAddr, MetaPtr: vtableAddr},
		vtableAddr:     vtableAddr,
		cxaPureVirtual: cxaPureVirtual,
		targets:        targets,
	}
}

func TestVtableSlotsPACReadsPerSlotAuth(t *testing.T) {
	t.Parallel()

	f := newPACFixture(t)
	slots := f.scanner.VtableSlotsPAC(f.class, 8)
	if len(slots) != len(f.targets) {
		t.Fatalf("decoded %d slots, want %d", len(slots), len(f.targets))
	}

	for i, slot := range slots {
		if slot.Index != i {
			t.Fatalf("slot %d has Index %d", i, slot.Index)
		}
		if want := uint64(i * 8); slot.Offset != want {
			t.Fatalf("slot %d offset = %#x, want %#x", i, slot.Offset, want)
		}
		if want := f.vtableAddr + uint64(i*8); slot.SlotAddress != want {
			t.Fatalf("slot %d addr = %#x, want %#x", i, slot.SlotAddress, want)
		}
		if slot.Address != f.targets[i] {
			t.Fatalf("slot %d target = %#x, want %#x", i, slot.Address, f.targets[i])
		}
	}

	// Slot 0: authenticated (DA key, addrDiv, pac 0xabcd).
	if s := slots[0]; !s.Auth || s.PAC != 0xabcd || s.Key != 2 || !s.AddrDiv {
		t.Fatalf("slot 0 auth = %+v, want Auth=true PAC=0xabcd Key=2 AddrDiv=true", s)
	}
	if slots[0].PureVirtual {
		t.Fatal("slot 0 must not be pure virtual")
	}

	// Slot 1: unsigned kernelcache slot -> Auth false, PAC/Key/AddrDiv zero,
	// but the cache level is still read (not a fabricated diversifier).
	if s := slots[1]; s.Auth || s.PAC != 0 || s.Key != 0 || s.AddrDiv {
		t.Fatalf("slot 1 = %+v, want Auth=false PAC=0 Key=0 AddrDiv=false", s)
	}
	if slots[1].CacheLevel != 1 {
		t.Fatalf("slot 1 cacheLevel = %d, want 1", slots[1].CacheLevel)
	}

	// Slot 2: authenticated and pointing at __cxa_pure_virtual.
	if s := slots[2]; !s.Auth || s.PAC != 0x1111 || !s.PureVirtual {
		t.Fatalf("slot 2 = %+v, want Auth=true PAC=0x1111 PureVirtual=true", s)
	}

	// Slot 3: arm64e auth rebase (IB key, addrDiv, pac 0x1357).
	if s := slots[3]; !s.Auth || s.PAC != 0x1357 || s.Key != 1 || !s.AddrDiv {
		t.Fatalf("slot 3 = %+v, want Auth=true PAC=0x1357 Key=1 AddrDiv=true", s)
	}
}

func TestMethodTableNumMethodsBound(t *testing.T) {
	t.Parallel()

	f := newPACFixture(t)
	mt := f.scanner.BuildMethodTable(f.class)

	if mt.Class != "SyntheticClass" || mt.VtableAddr != f.vtableAddr {
		t.Fatalf("method table header = %+v", mt)
	}
	if mt.NumMethods() != len(f.targets) {
		t.Fatalf("NumMethods() = %d, want %d (bound must stop at the first slot without a fixup)", mt.NumMethods(), len(f.targets))
	}
	if len(mt.Methods) != len(f.targets) {
		t.Fatalf("len(Methods) = %d, want %d", len(mt.Methods), len(f.targets))
	}

	tables := f.scanner.BuildMethodTables([]Class{f.class})
	if len(tables) != 1 || tables[0].NumMethods() != len(f.targets) {
		t.Fatalf("BuildMethodTables mismatch: %+v", tables)
	}
}

func TestBuildMethodTableEmptyForNoVtable(t *testing.T) {
	t.Parallel()

	f := newPACFixture(t)
	mt := f.scanner.BuildMethodTable(Class{Name: "NoVtable"})
	if mt.NumMethods() != 0 {
		t.Fatalf("NumMethods() = %d, want 0 for a class with no vtable", mt.NumMethods())
	}
}
