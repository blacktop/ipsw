package cpp

import (
	"github.com/blacktop/go-macho/pkg/fixupchains"
)

// MaxMethods caps the number of vtable slots inspected when bounding a method
// table. Real IOKit vtables stay well under this ceiling; it exists to keep a
// malformed or unterminated slot run from scanning an entire section.
const MaxMethods = 512

// slotAuth holds the pointer-authentication metadata decoded from a single
// chained-fixup slot. Diversity/Key/AddrDiv are only meaningful when auth is
// true; unsigned rebase slots leave them zero so callers never surface the
// garbage diversity bits a non-auth fixup word exposes.
type slotAuth struct {
	pac        uint16
	key        uint8
	addrDiv    bool
	auth       bool
	bind       bool
	cacheLevel uint8
}

// decodeSlotAuth extracts PAC metadata from a chained-fixup slot.
//
// It gates on the CONCRETE fixup type, never the fixupchains.Auth interface:
// that interface has no IsAuth and returns garbage Diversity on non-auth
// kernelcache slots. The second return value is false for fixup types that
// carry no per-slot information (e.g. plain arm64e rebases).
func decodeSlotAuth(fx fixupchains.Fixup) (slotAuth, bool) {
	switch f := fx.(type) {
	case fixupchains.DyldChainedPtr64KernelCacheRebase:
		sa := slotAuth{cacheLevel: uint8(f.CacheLevel())}
		if f.IsAuth() == 1 {
			sa.auth = true
			sa.pac = uint16(f.Diversity())
			sa.key = uint8(f.Key())
			sa.addrDiv = f.AddrDiv() == 1
		}
		return sa, true
	case fixupchains.DyldChainedPtrArm64eAuthRebase:
		// The concrete type is already the auth-rebase form (Auth() == 1).
		return slotAuth{
			auth:    true,
			pac:     uint16(f.Diversity()),
			key:     uint8(f.Key()),
			addrDiv: f.AddrDiv() == 1,
		}, true
	default:
		if fx != nil && fx.IsBind() {
			return slotAuth{bind: true}, true
		}
		return slotAuth{}, false
	}
}

// captureSlotAuth records the PAC metadata for slotAddr as a side effect of the
// root fixup walks. The first write wins so an already-captured slot is not
// overwritten.
func (s *Scanner) captureSlotAuth(slotAddr uint64, fx fixupchains.Fixup) {
	sa, ok := decodeSlotAuth(fx)
	if !ok {
		return
	}
	if s.slotAuthByVMAddr == nil {
		s.slotAuthByVMAddr = make(map[uint64]slotAuth)
	}
	if _, seen := s.slotAuthByVMAddr[slotAddr]; seen {
		return
	}
	s.slotAuthByVMAddr[slotAddr] = sa
}

// slotAuthAt returns the PAC metadata for the fixup slot at slotAddr. It prefers
// the map seeded during the root fixup walk and falls back to an on-demand read
// via the root chained-fixups. For a fileset kernelcache the chains live on the
// root Mach-O, so the on-demand path converts the slot VM address to a root file
// offset before calling GetFixupAtOffset.
func (s *Scanner) slotAuthAt(slotAddr uint64) (slotAuth, bool) {
	if sa, ok := s.slotAuthByVMAddr[slotAddr]; ok {
		return sa, true
	}
	if s.root == nil || !s.root.HasDyldChainedFixups() {
		return slotAuth{}, false
	}
	dcf, err := s.root.DyldChainedFixups()
	if err != nil {
		return slotAuth{}, false
	}
	fileOff, err := s.root.GetOffset(slotAddr)
	if err != nil {
		return slotAuth{}, false
	}
	fx, err := dcf.GetFixupAtOffset(fileOff)
	if err != nil {
		return slotAuth{}, false
	}
	sa, ok := decodeSlotAuth(fx)
	if !ok {
		return slotAuth{}, false
	}
	if s.slotAuthByVMAddr == nil {
		s.slotAuthByVMAddr = make(map[uint64]slotAuth)
	}
	s.slotAuthByVMAddr[slotAddr] = sa
	return sa, true
}

// VtableSlotPAC returns a single decoded vtable slot for class with its per-slot
// PAC metadata. The decoded target address comes from the existing decoded-
// pointer path (fallbackPointerAt), while PAC/Key/AddrDiv/Auth come from the raw
// chained fixup so the diversifier the pointer-decode path discards is retained.
func (s *Scanner) VtableSlotPAC(class Class, index int) (VtableEntry, bool) {
	if index < 0 || class.VtableAddr == 0 {
		return VtableEntry{}, false
	}
	owner := s.ClassOwner(class)
	if owner == nil {
		return VtableEntry{}, false
	}
	slotAddr := class.VtableAddr + uint64(index*8)
	target, ok := s.fallbackPointerAt(owner, slotAddr)
	if !ok || !validKernelPointer(target) {
		return VtableEntry{}, false
	}
	entry := VtableEntry{
		Index:       index,
		Offset:      uint64(index * 8),
		SlotAddress: slotAddr,
		Address:     target,
		Symbol:      s.SymbolName(target),
	}
	if sa, ok := s.slotAuthAt(slotAddr); ok {
		entry.Auth = sa.auth
		entry.PAC = sa.pac
		entry.Key = sa.key
		entry.AddrDiv = sa.addrDiv
		entry.CacheLevel = sa.cacheLevel
		entry.ExternalReloc = sa.bind
	}
	if s.cxaPureVirtual != 0 && target == s.cxaPureVirtual {
		entry.PureVirtual = true
	}
	return entry, true
}

// VtableSlotsPAC returns up to max decoded vtable slots for class with per-slot
// PAC metadata. It stops at the first slot without a resolvable pointer.
func (s *Scanner) VtableSlotsPAC(class Class, max int) []VtableEntry {
	if max <= 0 || class.VtableAddr == 0 {
		return nil
	}
	out := make([]VtableEntry, 0, max)
	for idx := range max {
		entry, ok := s.VtableSlotPAC(class, idx)
		if !ok {
			break
		}
		out = append(out, entry)
	}
	return out
}

// MethodTable is the per-class, PAC-annotated vtable for a discovered class,
// bounded to its true method count. It is index-aligned with the []Class input
// to BuildMethodTables.
type MethodTable struct {
	Class      string
	Bundle     string
	VtableAddr uint64
	Methods    []VtableEntry
}

// NumMethods returns the true number of virtual methods in the table.
func (mt MethodTable) NumMethods() int {
	return len(mt.Methods)
}

// BuildMethodTables returns one MethodTable per input class, index-aligned with
// classes.
func (s *Scanner) BuildMethodTables(classes []Class) []MethodTable {
	out := make([]MethodTable, len(classes))
	for i, class := range classes {
		out[i] = s.BuildMethodTable(class)
	}
	return out
}

// BuildMethodTable returns the PAC-annotated, end-bounded method table for
// class.
func (s *Scanner) BuildMethodTable(class Class) MethodTable {
	mt := MethodTable{Class: class.Name, Bundle: class.Bundle, VtableAddr: class.VtableAddr}
	if class.VtableAddr == 0 {
		return mt
	}
	mt.Methods = s.VtableSlotsPAC(class, s.vtableMethodCount(class))
	return mt
}

// vtableMethodCount bounds the vtable at its real end. A slot ends the table
// when it falls past the owning section, lacks a resolvable fixup pointer (the
// zero terminator or the header of the next vtable), or the MaxMethods ceiling
// is hit. In a kernelcache the forward-pointer cache is populated exclusively
// from chained fixups, so a resolvable pointer implies fixup presence.
func (s *Scanner) vtableMethodCount(class Class) int {
	owner := s.ClassOwner(class)
	if owner == nil || class.VtableAddr == 0 {
		return 0
	}
	var secEnd uint64
	if sec := owner.FindSectionForVMAddr(class.VtableAddr); sec != nil {
		secEnd = sec.Addr + sec.Size
	}
	count := 0
	for idx := range MaxMethods {
		slotAddr := class.VtableAddr + uint64(idx*8)
		if secEnd != 0 && slotAddr+8 > secEnd {
			break
		}
		ptr, ok := s.fallbackPointerAt(owner, slotAddr)
		if !ok || ptr == 0 || ptr == 0xffffffffffffffff || !validKernelPointer(ptr) {
			break
		}
		count++
	}
	return count
}
