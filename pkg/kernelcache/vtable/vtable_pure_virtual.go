package vtable

import (
	"fmt"
	"strings"

	"github.com/apex/log"
)

// VtableSymbolicator fields and methods for deterministic ___cxa_pure_virtual index detection
// Following iometa's proven algorithm to find the alloc function index

// Cache for the alloc index - computed once and reused
var cachedAllocIndex *int

// findAllocIndexFromPureVirtual implements iometa's deterministic approach to find the alloc function index
// by locating ___cxa_pure_virtual in the base OSObject vtable
func (vs *VtableSymbolicator) findAllocIndexFromPureVirtual() (int, error) {
	// Use cached result if available
	if cachedAllocIndex != nil {
		return *cachedAllocIndex, nil
	}

	log.Debugf("Using deterministic ___cxa_pure_virtual method to find alloc index")

	// Step 1: Find ___cxa_pure_virtual symbol or address
	pureVirtualAddr, err := vs.findPureVirtualAddress()
	if err != nil {
		return 0, fmt.Errorf("failed to find ___cxa_pure_virtual: %v", err)
	}

	log.Debugf("Found ___cxa_pure_virtual at %#x", pureVirtualAddr)

	// Step 2: Find OSObject's vtable
	osObjectVtableAddr, err := vs.findOSObjectVtable()
	if err != nil {
		return 0, fmt.Errorf("failed to find OSObject vtable: %v", err)
	}

	log.Debugf("Found OSObject vtable at %#x", osObjectVtableAddr)

	// Step 3: Find the index where ___cxa_pure_virtual appears in OSObject's vtable
	allocIndex, err := vs.findPureVirtualIndexInVtable(osObjectVtableAddr, pureVirtualAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to find ___cxa_pure_virtual index in OSObject vtable: %v", err)
	}

	// Cache the result for future use
	cachedAllocIndex = &allocIndex

	log.Debugf("Deterministically found alloc index: %d", allocIndex)

	return allocIndex, nil
}

// findPureVirtualAddress locates the ___cxa_pure_virtual function address
func (vs *VtableSymbolicator) findPureVirtualAddress() (uint64, error) {
	// First try to find it in the symbol table
	addr, err := vs.file.FindSymbolAddress("___cxa_pure_virtual")
	if err == nil {
		log.Debugf("Found ___cxa_pure_virtual symbol at %#x", addr)
		return addr, nil
	}
	// If not found in symbols, search for the string "__cxa_pure_virtual" and find references
	// This follows iometa's approach when symbols are not available
	for _, sec := range vs.stringMap {
		if addr, found := sec["__cxa_pure_virtual"]; found {
			return addr, nil
		}
	}
	// Find functions that reference this string - this is complex and would require
	// implementing the full pattern matching from iometa's pure_virtual_cb
	// For now, return an error to fall back to legacy approach
	return 0, fmt.Errorf("___cxa_pure_virtual symbol not found, string-based detection not yet implemented")
}

// findOSObjectVtable locates OSObject's vtable
func (vs *VtableSymbolicator) findOSObjectVtable() (uint64, error) {
	// First try to find OSObject vtable symbol
	if vs.file.Symtab != nil {
		for _, sym := range vs.file.Symtab.Syms {
			// Look for OSObject vtable symbol - it might be mangled
			if strings.Contains(sym.Name, "OSObject") && strings.Contains(sym.Name, "vtab") {
				log.Debugf("Found OSObject vtable symbol: %s at %#x", sym.Name, sym.Value)
				// Vtables typically have 2 pointer-sized entries before the actual function pointers
				return sym.Value + 2*8, nil
			}
		}
	}

	// Try to find OSObject class and extract its vtable
	if osObject, exists := vs.classByName["OSObject"]; exists {
		if osObject.VtableAddr != 0 {
			return osObject.VtableAddr, nil
		}
	}

	return 0, fmt.Errorf("OSObject vtable not found")
}

// findPureVirtualIndexInVtable finds the index where ___cxa_pure_virtual appears in the given vtable
func (vs *VtableSymbolicator) findPureVirtualIndexInVtable(vtableAddr, pureVirtualAddr uint64) (int, error) {
	// Scan through the vtable looking for ___cxa_pure_virtual
	maxEntries := 20 // Reasonable limit to avoid infinite loops

	for i := 0; i < maxEntries; i++ {
		entryAddr, err := vs.ReadUint64AtAddr(vtableAddr + uint64(i*8))
		if err != nil {
			return 0, fmt.Errorf("failed to read vtable entry %d: %v", i, err)
		}

		// Check if this entry points to ___cxa_pure_virtual
		if entryAddr == pureVirtualAddr {
			log.Debugf("Found ___cxa_pure_virtual at vtable index %d", i)
			return i, nil
		}

		// Stop if we hit a null pointer (end of vtable)
		if entryAddr == 0 {
			break
		}
	}

	return 0, fmt.Errorf("___cxa_pure_virtual not found in vtable")
}

// isPureVirtual checks if an address points to the ___cxa_pure_virtual function
func (vs *VtableSymbolicator) isPureVirtual(addr uint64) bool {
	pureVirtualAddr, err := vs.findPureVirtualAddress()
	if err != nil {
		return false
	}
	return addr == pureVirtualAddr
}
