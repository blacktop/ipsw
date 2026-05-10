package cpp

import (
	"fmt"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/symbols"
)

// VtableEntry is a decoded function pointer from a recovered C++ vtable.
type VtableEntry struct {
	Index   int
	Address uint64
	Symbol  string
}

// FunctionBody is the bounded analysis input for a recovered function.
type FunctionBody struct {
	Function types.Function
	Owner    *macho.File
	Data     []byte
}

// OwnerForVMAddr returns the fileset entry that owns addr, if known.
func (s *Scanner) OwnerForVMAddr(addr uint64) *macho.File {
	return s.fileForVMAddr(addr)
}

// ClassOwner returns the fileset entry that owns the strongest address
// associated with class.
func (s *Scanner) ClassOwner(class Class) *macho.File {
	for _, addr := range []uint64{class.MetaPtr, class.VtableAddr, class.Ctor, class.MetaVtableAddr} {
		if addr == 0 {
			continue
		}
		if owner := s.fileForVMAddr(addr); owner != nil {
			return owner
		}
	}
	return nil
}

// EntryForOwner returns the bundle/fileset identifier associated with owner.
func (s *Scanner) EntryForOwner(owner *macho.File) string {
	return s.entryForFile(owner)
}

// VtableEntries returns up to max decoded vtable entries for class.
func (s *Scanner) VtableEntries(class Class, max int) []VtableEntry {
	if max <= 0 || class.VtableAddr == 0 {
		return nil
	}
	owner := s.ClassOwner(class)
	if owner == nil {
		return nil
	}
	out := make([]VtableEntry, 0, max)
	for idx := range max {
		addr := class.VtableAddr + uint64(idx*8)
		ptr, ok := s.fallbackPointerAt(owner, addr)
		if !ok || !validKernelPointer(ptr) {
			break
		}
		out = append(out, VtableEntry{
			Index:   idx,
			Address: ptr,
			Symbol:  s.SymbolName(ptr),
		})
	}
	return out
}

// VtableEntry returns a single decoded vtable entry for class.
func (s *Scanner) VtableEntry(class Class, index int) (VtableEntry, bool) {
	if index < 0 || class.VtableAddr == 0 {
		return VtableEntry{}, false
	}
	owner := s.ClassOwner(class)
	if owner == nil {
		return VtableEntry{}, false
	}
	addr := class.VtableAddr + uint64(index*8)
	ptr, ok := s.fallbackPointerAt(owner, addr)
	if !ok || !validKernelPointer(ptr) {
		return VtableEntry{}, false
	}
	return VtableEntry{
		Index:   index,
		Address: ptr,
		Symbol:  s.SymbolName(ptr),
	}, true
}

// FunctionBodyAt returns function bounds, owner, and bytes for addr.
func (s *Scanner) FunctionBodyAt(addr uint64) (FunctionBody, error) {
	owner := s.fileForVMAddr(addr)
	fn, fnOwner, err := s.functionForAddrInAnyFile(owner, addr)
	if err != nil {
		return FunctionBody{}, err
	}
	data, err := s.functionDataFor(fnOwner, fn)
	if err != nil {
		return FunctionBody{}, err
	}
	return FunctionBody{Function: fn, Owner: fnOwner, Data: data}, nil
}

// ReadPointerAt resolves a kernel pointer from addr using the scanner's
// warmed fixup and section pointer caches.
func (s *Scanner) ReadPointerAt(owner *macho.File, addr uint64) (uint64, bool) {
	return s.fallbackPointerAt(owner, addr)
}

// ReadUint32At reads a little-endian uint32 from addr.
func (s *Scanner) ReadUint32At(owner *macho.File, addr uint64) (uint32, error) {
	lookupOwner, _ := s.pointerLookupOwner(owner, addr)
	if lookupOwner == nil {
		return 0, fmt.Errorf("no owner for %#x", addr)
	}
	var buf [4]byte
	if _, err := lookupOwner.ReadAtAddr(buf[:], addr); err != nil {
		return 0, err
	}
	return lookupOwner.ByteOrder.Uint32(buf[:]), nil
}

// ReadUint64At reads a little-endian uint64 from addr.
func (s *Scanner) ReadUint64At(owner *macho.File, addr uint64) (uint64, error) {
	lookupOwner, _ := s.pointerLookupOwner(owner, addr)
	if lookupOwner == nil {
		return 0, fmt.Errorf("no owner for %#x", addr)
	}
	var buf [8]byte
	if _, err := lookupOwner.ReadAtAddr(buf[:], addr); err != nil {
		return 0, err
	}
	return lookupOwner.ByteOrder.Uint64(buf[:]), nil
}

// ReadCStringAt reads a C string from addr from the owning fileset entry.
func (s *Scanner) ReadCStringAt(owner *macho.File, addr uint64) (string, error) {
	return getCStringFromAny(s.root, owner, addr)
}

// SymbolName returns a demangled function symbol at addr when the Mach-O has
// one. It returns an empty string for stripped addresses.
func (s *Scanner) SymbolName(addr uint64) string {
	if addr == 0 {
		return ""
	}
	owner := s.fileForVMAddr(addr)
	for _, file := range []*macho.File{owner, s.root} {
		if file == nil {
			continue
		}
		syms, err := file.FindAddressSymbols(addr)
		if err != nil {
			continue
		}
		for _, sym := range syms {
			name := strings.TrimSpace(sym.Name)
			if name == "" || name == "<redacted>" {
				continue
			}
			return symbols.DemangleSymbolName(name)
		}
	}
	return ""
}
