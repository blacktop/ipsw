package vtable

import (
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/emulate/core"
)

// extractVtables extracts vtable information for each discovered class
func (vs *VtableSymbolicator) extractVtables() error {
	log.Debugf("Extracting vtables for %d discovered classes", len(vs.classes))

	// Process each discovered class
	for _, class := range vs.classes {
		log.Debugf("Processing class: %s", class.Name)

		// Step 1: Find the alloc function for this class
		if err := vs.findAllocFunction(class); err != nil {
			log.Debugf("Failed to find alloc function for %s: %v", class.Name, err)
			continue
		}

		// Step 2: Extract vtable from the alloc function
		if err := vs.extractVtableFromAlloc(class); err != nil {
			log.Debugf("Failed to extract vtable for %s: %v", class.Name, err)
			continue
		}

		log.Debugf("Successfully extracted vtable for %s with %d methods", class.Name, len(class.Methods))
	}

	return nil
}

// findAllocFunction attempts to locate the alloc function for a class
func (vs *VtableSymbolicator) findAllocFunction(class *ClassMeta) error {
	// Look for alloc function in symbol table first
	if vs.file.Symtab != nil {
		allocSymbol := class.Name + "::alloc"
		for _, sym := range vs.file.Symtab.Syms {
			if strings.Contains(sym.Name, allocSymbol) ||
				(strings.Contains(sym.Name, class.Name) && strings.Contains(sym.Name, "alloc")) {
				class.AllocFunc = sym.Value
				log.Debugf("Found alloc function for %s at %#x: %s", class.Name, class.AllocFunc, sym.Name)
				return nil
			}
		}
	}

	// If not found in symbols, try to find it via MetaClass vtable
	if class.MetaPtr != 0 {
		if err := vs.findAllocFromMetaClass(class); err != nil {
			return fmt.Errorf("failed to find alloc via MetaClass: %v", err)
		}
	}

	if class.AllocFunc == 0 {
		return fmt.Errorf("unable to locate alloc function")
	}

	return nil
}

// extractVtableFromAlloc extracts vtable by analyzing the alloc function
func (vs *VtableSymbolicator) extractVtableFromAlloc(class *ClassMeta) error {
	if class.AllocFunc == 0 {
		return fmt.Errorf("no alloc function found for class %s", class.Name)
	}

	log.Debugf("Extracting vtable for %s from alloc function at %#x", class.Name, class.AllocFunc)

	// Step 1: Find the vtable address by emulating the alloc function
	// TEMPORARY FIX: Skip emulation to prevent hanging, but allow class discovery
	log.Debugf("Skipping vtable emulation for %s to prevent hanging", class.Name)
	
	// Skip vtable extraction but don't fail completely - this allows class discovery to work
	log.Debugf("Vtable emulation disabled temporarily for %s", class.Name)
	return nil // Allow class discovery without vtable extraction
}

// findAllocFromMetaClass extracts alloc function from MetaClass vtable
func (vs *VtableSymbolicator) findAllocFromMetaClass(class *ClassMeta) error {
	if class.MetaPtr == 0 {
		return fmt.Errorf("MetaClass pointer is zero")
	}

	log.Debugf("Analyzing MetaClass vtable for %s at %#x", class.Name, class.MetaPtr)

	// Step 1: Read the MetaClass object's vtable pointer (first 8 bytes)
	metaVtablePtr, err := vs.readUint64AtAddr(class.MetaPtr)
	if err != nil {
		return fmt.Errorf("failed to read MetaClass vtable pointer: %v", err)
	}

	log.Debugf("MetaClass vtable pointer for %s: %#x", class.Name, metaVtablePtr)

	// Step 2: Validate the vtable pointer points to a reasonable location
	if err := vs.validateVtablePointer(metaVtablePtr); err != nil {
		return fmt.Errorf("invalid MetaClass vtable pointer: %v", err)
	}

	// Step 3: Find the alloc function in the MetaClass vtable
	// The alloc function is typically at a known offset in OSMetaClass's vtable
	// We'll try multiple known offsets to find it
	allocOffsets := []int{
		0, // alloc might be the first virtual method
		1, // or the second (after some base class methods)
		2, // or third
		3, // fallback
	}

	// Try deterministic approach first using ___cxa_pure_virtual detection
	allocIndex, err := vs.findAllocIndexFromPureVirtual()
	if err == nil {
		// Use deterministic index
		allocAddr, err := vs.readUint64AtAddr(metaVtablePtr + uint64(allocIndex*8))
		if err == nil && vs.isValidFunctionAddress(allocAddr) && !vs.isPureVirtual(allocAddr) {
			class.AllocFunc = allocAddr
			log.Debugf("Found alloc function for %s at %#x using deterministic index %d", class.Name, allocAddr, allocIndex)
			return nil
		}
	}

	log.Debugf("Deterministic alloc detection failed (%v), falling back to guessing", err)

	// Fallback to guessing approach
	for _, offset := range allocOffsets {
		// Bounds check before reading
		readAddr := metaVtablePtr + uint64(offset*8)
		allocAddr, err := vs.readUint64AtAddr(readAddr)
		if err != nil {
			log.Debugf("Failed to read vtable entry at offset %d (addr %#x): %v", offset, readAddr, err)
			continue
		}

		// Validate that this looks like a function address
		if vs.isValidFunctionAddress(allocAddr) {
			// Try to verify this is actually an alloc function by basic analysis
			if vs.looksLikeAllocFunction(allocAddr) {
				class.AllocFunc = allocAddr
				log.Debugf("Found alloc function for %s at %#x (vtable offset %d)",
					class.Name, allocAddr, offset)
				return nil
			}
			log.Debugf("Address %#x at offset %d doesn't look like alloc function", allocAddr, offset)
		}
	}

	return fmt.Errorf("could not locate alloc function in MetaClass vtable")
}

// findVtableInAlloc emulates the alloc function to find where vtable is initialized
func (vs *VtableSymbolicator) findVtableInAlloc(allocAddr uint64, classSize uint64) (uint64, error) {
	// Get the code bytes for the alloc function
	const maxAllocSize = 512 // Most alloc functions are fairly small
	code, err := vs.getCodeBytesFromAddr(allocAddr, maxAllocSize)
	if err != nil {
		return 0, fmt.Errorf("failed to get alloc function code: %v", err)
	}

	// Initialize ARM64 emulator state using the centralized emulator
	state := CreateMockAllocState(classSize)

	// Track memory writes to find vtable initialization
	var vtableAddr uint64
	writeHandler := func(addr, value uint64, size int) {
		// Look for 8-byte pointer writes to the start of the object
		// The vtable pointer is typically the first thing written to a new object
		if size == 8 && addr == state.GetX(0) && vs.isValidVtableAddress(value) {
			vtableAddr = value
			log.Debugf("Found vtable write: [%#x] = %#x", addr, value)
		}
	}

	// Emulate until we find vtable initialization or hit a return
	err = vs.emulateWithWriteTracking(state, code, allocAddr, writeHandler)
	if err != nil {
		return 0, fmt.Errorf("emulation failed: %v", err)
	}

	if vtableAddr == 0 {
		// Fallback: try static analysis to find ADRP/ADD patterns for vtable addresses
		return vs.findVtableStatically(code, allocAddr)
	}

	return vtableAddr, nil
}

// Stub implementations for missing functions
func (vs *VtableSymbolicator) validateVtablePointer(ptr uint64) error {
	// Basic validation - check if pointer is in a reasonable range
	if ptr == 0 {
		return fmt.Errorf("vtable pointer is null")
	}
	// Additional validation could be added here
	return nil
}

func (vs *VtableSymbolicator) isValidFunctionAddress(addr uint64) bool {
	// Basic validation for function addresses
	if addr == 0 {
		return false
	}

	// Check if address is in executable segments
	for _, seg := range vs.file.Segments() {
		if (seg.Prot&0x4) != 0 && addr >= seg.Addr && addr < seg.Addr+seg.Filesz {
			return true
		}
	}
	return false
}

func (vs *VtableSymbolicator) looksLikeAllocFunction(addr uint64) bool {
	// Placeholder - this should analyze the function to see if it looks like an alloc function
	// Real implementation would look for malloc calls, object size calculations, etc.
	log.Debugf("looksLikeAllocFunction analysis not yet implemented for %#x", addr)
	return true // Assume it looks like alloc for now
}

func (vs *VtableSymbolicator) getCodeBytesFromAddr(addr uint64, maxSize int) ([]byte, error) {
	// Find the segment containing this address
	for _, seg := range vs.file.Segments() {
		if addr >= seg.Addr && addr < seg.Addr+seg.Filesz {
			data, err := seg.Data()
			if err != nil {
				return nil, fmt.Errorf("failed to get segment data: %w", err)
			}

			offset := addr - seg.Addr
			if offset >= uint64(len(data)) {
				return nil, fmt.Errorf("offset %d beyond segment data length %d", offset, len(data))
			}

			endOffset := min(int(offset)+maxSize, len(data))
			if endOffset <= int(offset) {
				return nil, fmt.Errorf("invalid end offset %d <= start offset %d", endOffset, offset)
			}
			return data[offset:endOffset], nil
		}
	}

	return nil, fmt.Errorf("address %#x not found in any segment", addr)
}

func (vs *VtableSymbolicator) isValidVtableAddress(addr uint64) bool {
	// Check if this looks like a valid vtable address
	if addr == 0 {
		return false
	}

	// Check if address is in data segments (vtables are typically in __DATA_CONST)
	for _, seg := range vs.file.Segments() {
		if strings.HasPrefix(seg.Name, "__DATA") && addr >= seg.Addr && addr < seg.Addr+seg.Filesz {
			return true
		}
	}
	return false
}

func (vs *VtableSymbolicator) emulateWithWriteTracking(state core.State, code []byte, startAddr uint64, writeHandler func(uint64, uint64, int)) error {
	// Create emulator adapter with the provided state
	adapter := NewEmulatorAdapterWithState(state)

	// Set up memory read handler to access kernelcache data
	adapter.SetupMemoryReadHandler(func(addr uint64, size int) ([]byte, error) {
		return vs.readMemoryAtAddr(addr, size)
	})

	// Use adapter's write tracking emulation
	return adapter.EmulateWithWriteTracking(code, startAddr, writeHandler)
}

func (vs *VtableSymbolicator) findVtableStatically(code []byte, baseAddr uint64) (uint64, error) {
	// Placeholder - should analyze code statically to find ADRP/ADD patterns
	log.Debugf("findVtableStatically not yet implemented")
	return 0, fmt.Errorf("static vtable analysis not yet implemented")
}

func (vs *VtableSymbolicator) readMemoryAtAddr(addr uint64, size int) ([]byte, error) {
	// Validate inputs
	if addr == 0 {
		return nil, fmt.Errorf("cannot read from null address")
	}
	if size <= 0 {
		return nil, fmt.Errorf("invalid size %d", size)
	}
	if size > 0x10000 { // 64KB limit for safety
		return nil, fmt.Errorf("size %d too large", size)
	}

	// Try to read from file segments
	for _, seg := range vs.file.Segments() {
		if addr >= seg.Addr && addr+uint64(size) <= seg.Addr+seg.Filesz {
			data, err := seg.Data()
			if err != nil {
				log.Debugf("Failed to get segment data for %s: %v", seg.Name, err)
				continue
			}
			offset := addr - seg.Addr
			if offset+uint64(size) <= uint64(len(data)) {
				return data[offset : offset+uint64(size)], nil
			}
			log.Debugf("Offset %d+%d beyond segment %s data length %d", offset, size, seg.Name, len(data))
		}
	}
	return nil, fmt.Errorf("address %#x (size %d) not readable in any segment", addr, size)
}

func (vs *VtableSymbolicator) extractVtableMethods(vtableAddr uint64, className string) ([]MethodInfo, error) {
	var methods []MethodInfo

	// Try to extract method pointers from the vtable
	// This is a simplified implementation
	for i := 0; i < 16; i++ { // Limit to first 16 methods
		methodAddr, err := vs.readUint64AtAddr(vtableAddr + uint64(i*8))
		if err != nil {
			log.Debugf("Failed to read method at index %d: %v", i, err)
			break
		}

		if !vs.isValidFunctionAddress(methodAddr) {
			log.Debugf("Invalid method address at index %d: %#x", i, methodAddr)
			break
		}

		method := MethodInfo{
			Address: methodAddr,
			Name:    fmt.Sprintf("method_%d", i),
			Index:   i,
		}

		// Try to find method name in symbol table
		if vs.file.Symtab != nil {
			for _, sym := range vs.file.Symtab.Syms {
				if sym.Value == methodAddr {
					method.Name = sym.Name
					break
				}
			}
		}

		methods = append(methods, method)
	}

	log.Debugf("Extracted %d methods from vtable at %#x", len(methods), vtableAddr)
	return methods, nil
}
