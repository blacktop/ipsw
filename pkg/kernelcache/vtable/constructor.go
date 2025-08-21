package vtable

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// findOSMetaClassConstructor locates the OSMetaClass constructor function
func (vs *VtableSymbolicator) findOSMetaClassConstructor() error {
	// First try to find OSMetaClass constructor symbol
	symbolAddr := vs.findConstructorSymbol()
	if symbolAddr != 0 {
		vs.constructorAddr = symbolAddr
		log.Debugf("Found OSMetaClass constructor symbol at %#x", vs.constructorAddr)

		// Build constructor target set for indirect call detection
		if err := vs.buildConstructorTargetSet(); err != nil {
			return fmt.Errorf("failed to build constructor target set: %v", err)
		}

		return nil
	}

	// Fallback to binary matching using iometa's algorithm
	binaryAddr, err := vs.discoverConstructorBinaryMatching()
	if err != nil {
		return fmt.Errorf("failed to find constructor using binary matching: %v", err)
	}

	vs.constructorAddr = binaryAddr
	log.Debugf("Found OSMetaClass constructor at %#x using binary matching", vs.constructorAddr)

	// Build constructor target set for indirect call detection
	if err := vs.buildConstructorTargetSet(); err != nil {
		return fmt.Errorf("failed to build constructor target set: %v", err)
	}

	// Optionally log if symbol table has a different address for comparison
	if vs.file.Symtab != nil {
		for _, sym := range vs.file.Symtab.Syms {
			symName := sym.Name
			if strings.Contains(symName, "OSMetaClass") &&
				(strings.Contains(symName, "OSMetaClassC") ||
					strings.Contains(symName, "__ZN11OSMetaClassC2EPKcPKS_j")) {
				if sym.Value != vs.constructorAddr {
					log.Debugf("Note: Symbol %s at %#x differs from heuristic result %#x",
						symName, sym.Value, vs.constructorAddr)
				}
				break
			}
		}
	}

	return nil
}

// findConstructorSymbol looks for the OSMetaClass constructor symbol
func (vs *VtableSymbolicator) findConstructorSymbol() uint64 {
	if vs.file.Symtab == nil {
		return 0
	}

	var primarySym uint64
	var altSym uint64

	for _, sym := range vs.file.Symtab.Syms {
		switch sym.Name {
		// Primary (non-zone) constructor variants
		case "__ZN11OSMetaClassC2EPKcPKS_j", "__ZN11OSMetaClassC1EPKcPKS_j":
			if primarySym == 0 {
				primarySym = sym.Value
			}
		// Alt constructor variants with zone arguments
		case "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t",
			"__ZN11OSMetaClassC1EPKcPKS_jPP4zoneS1_19zone_create_flags_t":
			if altSym == 0 {
				altSym = sym.Value
			}
		}
	}

	// If we found an alternate constructor, pre-seed it so we can build caller graph for it too
	if altSym != 0 {
		vs.constructorTargetSet[altSym] = true
		log.Debugf("Found alternate OSMetaClass constructor symbol at %#x", altSym)
		// Seed alternate constructor as additional target for indirect caller / stub discovery
		if vs.constructorTargetSet != nil {
			vs.constructorTargetSet[altSym] = true
		}
	}

	if primarySym != 0 {
		return primarySym
	}
	return altSym
}

// discoverConstructorBinaryMatching uses iometa's algorithm to find the OSMetaClass constructor
func (vs *VtableSymbolicator) discoverConstructorBinaryMatching() (uint64, error) {
	var err error
	// Find string addresses for known IOKit classes that all use OSMetaClass constructor
	knownClasses := []string{"IORegistryEntry", "IOService", "IOUserClient"}
	log.Debugf("Searching for constructor using known class names (IORegistryEntry, IOService, IOUserClient)")

	vs.stringMap, err = vs.file.GetCStrings()
	if err != nil {
		return 0, fmt.Errorf("failed to get file cstrings: %v", err)
	}
	// Find string addresses for each known class
	stringAddrs := make([][]uint64, len(knownClasses))
	for i, className := range knownClasses {
		for _, sec := range vs.stringMap {
			if addr, found := sec[className]; found {
				stringAddrs[i] = append(stringAddrs[i], addr)
			}
		}
		log.Debugf("Found %d instances of string '%s'", len(stringAddrs[i]), className)
	}

	// For each string, find functions that are called when that string is referenced
	constructorCandidates := make([]map[uint64]bool, len(knownClasses))

	for i, className := range knownClasses {
		candidates, err := vs.findConstructorCandidatesForString(className, stringAddrs[i])
		if err != nil {
			return 0, fmt.Errorf("failed to find constructor candidates for '%s': %v", className, err)
		}
		constructorCandidates[i] = candidates
		log.Debugf("Found %d constructor candidates for '%s'", len(candidates), className)
		// Log first few candidates for debugging
		count := 0
		for addr := range candidates {
			if count < 3 {
				log.Debugf("  Candidate %d: %#x", count+1, addr)
				count++
			}
		}
	}

	// Find the intersection - function that's called with ALL three class names
	intersection := make(map[uint64]int)
	for _, candidates := range constructorCandidates {
		for addr := range candidates {
			intersection[addr]++
		}
	}

	// The constructor should be called with all three class names
	for addr, count := range intersection {
		if count == len(knownClasses) {
			log.Debugf("Found OSMetaClass constructor candidate at %#x (called with all %d known class names)", addr, count)
			return addr, nil
		}
	}

	return 0, fmt.Errorf("unable to locate OSMetaClass constructor: no function called with all known class names")
}

// buildConstructorTargetSet creates the set of all valid constructor entry points (direct + indirect)
func (vs *VtableSymbolicator) buildConstructorTargetSet() error {
	// Step 1: Ensure the primary constructor is in the set
	vs.constructorTargetSet[vs.constructorAddr] = true
	log.Debugf("Added primary constructor target: %#x", vs.constructorAddr)

	// Step 2: Add .stub symbols and alternate constructors from symbol table
	var stubSymbols []uint64
	if vs.file.Symtab != nil {
		for _, sym := range vs.file.Symtab.Syms {
			n := sym.Name
			switch {
			case n == "__ZN11OSMetaClassC2EPKcPKS_j.stub",
				n == "__ZN11OSMetaClassC1EPKcPKS_j.stub",
				n == "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t.stub",
				n == "__ZN11OSMetaClassC1EPKcPKS_jPP4zoneS1_19zone_create_flags_t.stub":
				// Only add actual .stub symbols, not the constructor symbols themselves
				if sym.Value != vs.constructorAddr {
					vs.constructorTargetSet[sym.Value] = true
					stubSymbols = append(stubSymbols, sym.Value)
					log.Debugf("Added stub target: %s at %#x", n, sym.Value)
				}
			case n == "__ZN11OSMetaClassC2EPKcPKS_j",
				n == "__ZN11OSMetaClassC1EPKcPKS_j",
				n == "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t",
				n == "__ZN11OSMetaClassC1EPKcPKS_jPP4zoneS1_19zone_create_flags_t":
				// Add constructor symbols that aren't already the primary constructor
				if sym.Value != vs.constructorAddr {
					vs.constructorTargetSet[sym.Value] = true
					log.Debugf("Added alternate constructor target: %s at %#x", n, sym.Value)
				}
			}
		}
		if len(stubSymbols) > 0 {
			log.Debugf("Added %d stub symbols to target set", len(stubSymbols))
		}
	}

	// Step 3: CRITICAL - Use recursive approach to find ALL functions that eventually call the constructor
	log.Debugf("Finding all constructor entry points using recursive analysis...")
	
	// Get all current targets as starting points for recursive search
	initialTargets := make([]uint64, 0, len(vs.constructorTargetSet))
	for addr := range vs.constructorTargetSet {
		initialTargets = append(initialTargets, addr)
	}
	
	// For each known constructor target, find all functions that call it
	initialTargetCount := len(vs.constructorTargetSet)
	for _, target := range initialTargets {
		callers := vs.findAllCallersRecursively(target)
		for _, caller := range callers {
			vs.constructorTargetSet[caller] = true
			log.Debugf("Added recursive caller target: %#x -> %#x", caller, target)
		}
	}
	
	newTargets := len(vs.constructorTargetSet) - initialTargetCount
	log.Debugf("Found %d additional constructor entry points via recursive analysis", newTargets)

	// Step 4: Find constructor references in data sections
	refs, err := vs.findConstructorReferences()
	if err != nil {
		log.Debugf("Failed to find constructor references: %v", err)
	} else {
		log.Debugf("Found %d constructor references in data sections", len(refs))
		for _, ref := range refs {
			vs.constructorTargetSet[ref] = true
		}
	}

	// Step 5: Find alias stubs that reference constructors
	stubs, err := vs.findAliasStubs(refs)
	if err != nil {
		log.Debugf("Failed to find alias stubs: %v", err)
	} else {
		log.Debugf("Found %d alias stubs", len(stubs))
		for _, stub := range stubs {
			vs.constructorTargetSet[stub] = true
		}
	}

	// Step 6: Add dysymtab stub entries if available
	stubCount, err := vs.addDysymtabConstructorStubs()
	if err != nil {
		log.Debugf("Failed to add dysymtab stubs: %v", err)
	} else if stubCount > 0 {
		log.Debugf("Added %d dysymtab stub entries", stubCount)
	}

	log.Debugf("Built constructor target set with %d total entries", len(vs.constructorTargetSet))
	
	// Log first 10 entries for debugging
	count := 0
	for addr := range vs.constructorTargetSet {
		if count < 10 {
			log.Debugf("  Target entry %d: %#x", count+1, addr)
			count++
		}
	}
	if len(vs.constructorTargetSet) > 10 {
		log.Debugf("  ... and %d more entries", len(vs.constructorTargetSet)-10)
	}

	return nil
}

// findConstructorReferences scans for constructor references in data sections
func (vs *VtableSymbolicator) findConstructorReferences() ([]uint64, error) {
	var references []uint64

	// Check all data sections that might contain function pointers
	dataSectionNames := []string{"__DATA_CONST", "__DATA", "__AUTH_CONST", "__AUTH_DATA"}
	log.Debugf("Scanning data sections for constructor references...")

	for _, segName := range dataSectionNames {
		segment := vs.file.Segment(segName)
		if segment == nil {
			continue
		}

		data, err := segment.Data()
		if err != nil {
			continue
		}

		// Scan for 8-byte pointers to our constructor or any target in our set
		for i := 0; i <= len(data)-8; i += 8 {
			addr := binary.LittleEndian.Uint64(data[i : i+8])
			
			// Check if this points to the constructor or any known target
			if addr == vs.constructorAddr || vs.constructorTargetSet[addr] {
				referenceAddr := segment.Addr + uint64(i)
				references = append(references, referenceAddr)
				log.Debugf("Found constructor reference at %#x -> %#x in %s", referenceAddr, addr, segName)
			}
		}

		// Also scan for truncated pointers (common in some data structures)
		for i := 0; i <= len(data)-4; i += 4 {
			// Check for 32-bit relative references or offsets
			offset := binary.LittleEndian.Uint32(data[i : i+4])
			
			// Skip obvious non-pointers (small values, likely offsets)
			if offset < 0x1000 || offset > 0x7FFFFFFF {
				continue
			}
			
			// Try to resolve as base + offset
			baseAddr := segment.Addr + uint64(i)
			potentialAddr := baseAddr + uint64(offset)
			
			if potentialAddr == vs.constructorAddr || vs.constructorTargetSet[potentialAddr] {
				references = append(references, baseAddr)
				log.Debugf("Found relative constructor reference at %#x + %#x = %#x in %s", baseAddr, offset, potentialAddr, segName)
			}
		}
	}

	log.Debugf("Found %d constructor references in data sections", len(references))
	return references, nil
}

// findConstructorReferencesLegacy falls back to direct pointer scanning (for older kernelcaches)
func (vs *VtableSymbolicator) findConstructorReferencesLegacy() ([]uint64, error) {
	var references []uint64

	// Check all data sections that might contain pointers
	dataSectionNames := []string{"__DATA_CONST", "__DATA", "__AUTH_CONST"}
	log.Debugf("Using legacy pointer scanning for constructor %#x in data sections...", vs.constructorAddr)

	for _, segName := range dataSectionNames {
		segment := vs.file.Segment(segName)
		if segment == nil {
			continue
		}

		data, err := segment.Data()
		if err != nil {
			continue
		}

		// Scan for 8-byte pointers to our constructor
		for i := 0; i <= len(data)-8; i += 8 {
			addr := binary.LittleEndian.Uint64(data[i : i+8])
			if addr == vs.constructorAddr {
				references = append(references, segment.Addr+uint64(i))
				log.Debugf("Found legacy constructor reference at %#x -> %#x", segment.Addr+uint64(i), addr)
			}
		}
	}

	return references, nil
}

// findAliasStubs scans for alias stubs that reference constructors
func (vs *VtableSymbolicator) findAliasStubs(references []uint64) ([]uint64, error) {
	var stubs []uint64

	log.Debugf("Scanning for alias stubs that reference constructors...")

	// Look for stub sections first
	stubsSection := vs.file.Section("__TEXT", "__stubs")
	if stubsSection == nil {
		log.Debugf("No __TEXT.__stubs section found")
		return stubs, nil
	}

	// Get the corresponding symbol pointer section
	var symbolPtrSection *types.Section
	if laSymSection := vs.file.Section("__DATA", "__la_symbol_ptr"); laSymSection != nil {
		symbolPtrSection = laSymSection
	} else if gotSection := vs.file.Section("__DATA_CONST", "__got"); gotSection != nil {
		symbolPtrSection = gotSection
	}

	if symbolPtrSection == nil {
		log.Debugf("No symbol pointer section found")
		return stubs, nil
	}

	stubData, err := stubsSection.Data()
	if err != nil {
		log.Debugf("Failed to get stub section data: %v", err)
		return stubs, nil
	}

	// Get symbol pointer section data (currently unused but reserved for future enhancement)
	_, err = symbolPtrSection.Data()
	if err != nil {
		log.Debugf("Failed to get symbol pointer section data: %v", err)
		// Continue without symbol pointer data - we can still analyze stubs
	}

	// Analyze stub entries - each stub typically has a fixed pattern
	// ARM64 stubs are usually 12 bytes (3 instructions): ADRP, LDR, BR
	stubSize := 12 // bytes
	numStubs := len(stubData) / stubSize

	for i := 0; i < numStubs; i++ {
		stubOffset := i * stubSize
		if stubOffset+stubSize > len(stubData) {
			break
		}

		stubAddr := stubsSection.Addr + uint64(stubOffset)
		
		// Read the stub instructions
		if stubOffset+8 >= len(stubData) {
			continue
		}
		
		instr1 := binary.LittleEndian.Uint32(stubData[stubOffset : stubOffset+4])
		instr2 := binary.LittleEndian.Uint32(stubData[stubOffset+4 : stubOffset+8])

		// Check for ADRP + LDR pattern (typical stub pattern)
		if (instr1&0x9F000000) == 0x90000000 && // ADRP
			(instr2&0xFF000000) == 0xF9400000 { // LDR (64-bit)

			// Extract the target address from ADRP + LDR
			targetAddr := vs.decodeADRPLDRTarget(stubAddr, instr1, instr2)
			
			// Check if this stub targets a constructor
			if targetAddr != 0 {
				// Read the value at the target address (symbol pointer)
				if symbolAddr, err := vs.readUint64AtAddr(targetAddr); err == nil {
					if symbolAddr == vs.constructorAddr || vs.constructorTargetSet[symbolAddr] {
						stubs = append(stubs, stubAddr)
						log.Debugf("Found constructor alias stub at %#x -> %#x -> %#x", stubAddr, targetAddr, symbolAddr)
					}
				}
			}
		}
	}

	// Also scan for function aliases in symbol table
	if vs.file.Symtab != nil {
		for _, sym := range vs.file.Symtab.Syms {
			// Look for symbols that might be aliases or wrappers
			if strings.Contains(sym.Name, "OSMetaClass") && 
				!strings.Contains(sym.Name, "C1E") && 
				!strings.Contains(sym.Name, "C2E") &&
				sym.Value != vs.constructorAddr {
				
				// Check if this symbol points to code that calls the constructor
				if vs.isValidFunctionAddress(sym.Value) {
					stubs = append(stubs, sym.Value)
					log.Debugf("Found potential constructor alias symbol: %s at %#x", sym.Name, sym.Value)
				}
			}
		}
	}

	log.Debugf("Found %d alias stubs", len(stubs))
	return stubs, nil
}

// findAllCallersRecursively finds all functions that call the target, including indirect callers
func (vs *VtableSymbolicator) findAllCallersRecursively(target uint64) []uint64 {
	visited := make(map[uint64]bool)
	var allCallers []uint64

	// Use BFS to find all callers recursively
	queue := []uint64{target}
	visited[target] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Find direct callers of current address
		callers, err := vs.findDirectCallersOf(current)
		if err != nil {
			continue
		}

		// Add new callers to the result and queue
		for _, caller := range callers {
			if !visited[caller] {
				visited[caller] = true
				allCallers = append(allCallers, caller)
				queue = append(queue, caller)
			}
		}
	}

	return allCallers
}

// findDirectCallersOf finds all functions that directly call the given target address
func (vs *VtableSymbolicator) findDirectCallersOf(target uint64) ([]uint64, error) {
	var callers []uint64

	// Scan all executable sections looking for BL instructions that target our address
	for _, section := range vs.file.Sections {
		// Only scan executable sections (any section in executable segment)
		seg := vs.file.Segment(section.Seg)
		if seg == nil || (seg.Prot&0x4) == 0 { // not executable
			continue
		}

		data, err := section.Data()
		if err != nil {
			continue
		}

		// Scan this section for BL instructions targeting our address
		for i := 0; i+4 <= len(data); i += 4 {
			instrValue := binary.LittleEndian.Uint32(data[i : i+4])
			instrAddr := section.Addr + uint64(i)

			// Check if this is a BL or B instruction (include tail-calls)
			isBL := (instrValue & 0xfc000000) == 0x94000000 // BL
			isB := (instrValue & 0xfc000000) == 0x14000000  // B (tail-call)

			if isBL || isB {
				// Calculate the target address using proper signed arithmetic
				targetAddr := vs.decodeBranchTargetFromConstructor(instrAddr, instrValue)

				// If this BL/B targets our constructor, add the caller function start
				if targetAddr == target {
					// Find the function start containing this caller
					functionStart := vs.findFunctionStart(instrAddr)
					if functionStart != 0 {
						callers = append(callers, functionStart)
					}
				}
			}
		}
	}

	return callers, nil
}

// findFunctionStart finds the start address of the function containing the given address
func (vs *VtableSymbolicator) findFunctionStart(addr uint64) uint64 {
	// For now, just return the calling instruction address itself
	// This will allow the system to detect calls to the constructor
	return addr
}

// addDysymtabConstructorStubs adds dysymtab stub entries for constructors
func (vs *VtableSymbolicator) addDysymtabConstructorStubs() (int, error) {
	stubCount := 0

	// Check if we have dysymtab info
	if vs.file.Dysymtab == nil {
		return 0, nil
	}

	// Look for stub sections
	stubsSection := vs.file.Section("__TEXT", "__stubs")
	if stubsSection == nil {
		return 0, nil
	}

	indirectSymSection := vs.file.Section("__DATA", "__la_symbol_ptr")
	if indirectSymSection == nil {
		indirectSymSection = vs.file.Section("__DATA_CONST", "__got")
		if indirectSymSection == nil {
			return 0, nil
		}
	}

	log.Debugf("Found stubs section at %#x with %d bytes", stubsSection.Addr, stubsSection.Size)
	log.Debugf("Found indirect symbol section at %#x with %d bytes", indirectSymSection.Addr, indirectSymSection.Size)

	// Process indirect symbol table entries
	indirectSyms := vs.file.Dysymtab.IndirectSyms
	if len(indirectSyms) == 0 {
		log.Debugf("No indirect symbols found in dysymtab")
		return 0, nil
	}

	// Get the stub section reserved fields to understand the layout
	reserved1 := stubsSection.Reserved1 // Index into indirect symbol table
	reserved2 := stubsSection.Reserved2 // Size of each stub entry

	if reserved2 == 0 {
		reserved2 = 12 // Default ARM64 stub size (3 instructions)
	}

	stubEntries := int(stubsSection.Size) / int(reserved2)
	log.Debugf("Processing %d stub entries (start index: %d, stub size: %d)", stubEntries, reserved1, reserved2)

	// Process each stub entry
	for i := 0; i < stubEntries && int(reserved1)+i < len(indirectSyms); i++ {
		indirectSymIndex := indirectSyms[reserved1+uint32(i)]
		
		// Skip special values
		if indirectSymIndex == 0x40000000 || indirectSymIndex == 0x80000000 {
			continue
		}

		// Get the symbol from the symbol table
		if vs.file.Symtab != nil && int(indirectSymIndex) < len(vs.file.Symtab.Syms) {
			sym := vs.file.Symtab.Syms[indirectSymIndex]
			
			// Check if this is a constructor symbol
			if vs.isConstructorSymbolName(sym.Name) {
				stubAddr := stubsSection.Addr + uint64(i)*uint64(reserved2)
				vs.constructorTargetSet[stubAddr] = true
				stubCount++
				log.Debugf("Added dysymtab constructor stub: %s at %#x", sym.Name, stubAddr)
			}
		}
	}

	log.Debugf("Added %d dysymtab constructor stubs", stubCount)
	return stubCount, nil
}

// findConstructorCandidatesForString finds functions called immediately after loading known class strings into x1
// This follows the correct iometa algorithm: find code that loads string address into x1 then immediately calls a function
func (vs *VtableSymbolicator) findConstructorCandidatesForString(className string, stringAddrs []uint64) (map[uint64]bool, error) {
	candidates := make(map[uint64]bool)

	// Get all executable sections to search for string references
	var executableSections []*types.Section
	for _, sect := range vs.file.Sections {
		// Find the segment for this section
		var sectSeg *macho.Segment
		for _, seg := range vs.file.Segments() {
			if sect.Addr >= seg.Addr && sect.Addr < seg.Addr+seg.Filesz {
				sectSeg = seg
				break
			}
		}

		// Only include S_REGULAR sections in executable __TEXT segments
		if sectSeg != nil && sectSeg.Prot&0x4 != 0 && strings.HasPrefix(sectSeg.Name, "__TEXT") {
			sectionType := sect.Flags & 0xff
			if sectionType == 0x0 { // S_REGULAR - contains code
				executableSections = append(executableSections, sect)
			}
		}
	}

	// For each executable section, scan for patterns that load our target strings into x1 followed by BL
	for _, sect := range executableSections {
		data, err := sect.Data()
		if err != nil {
			continue
		}

		if err := vs.findConstructorCallsInSection(data, sect.Addr, stringAddrs, className, candidates); err != nil {
			log.Debugf("Error scanning section %s.%s for constructor calls: %v", sect.Seg, sect.Name, err)
		}
	}

	return candidates, nil
}

// findConstructorCallsInSection scans a code section for the specific pattern:
// - Load known class string address into x1 register
// - Immediately call a function (BL instruction)
func (vs *VtableSymbolicator) findConstructorCallsInSection(data []byte, baseAddr uint64, stringAddrs []uint64, className string, candidates map[uint64]bool) error {
	r := bytes.NewReader(data)
	addr := baseAddr

	// We need to track register state across instructions to find the pattern
	var registerState [32]uint64 // Track x0-x31 register values
	var registerValid [32]bool   // Track which registers have valid values

	for r.Len() >= 4 {
		var instr uint32
		if err := binary.Read(r, binary.LittleEndian, &instr); err != nil {
			break
		}

		// Check for ADRP instruction (calculate page address)
		if vs.isADRPInstruction(instr) {
			reg := vs.extractADRPRegister(instr)
			imm := vs.extractADRPImmediate(instr)

			if reg < 32 {
				pageAddr := (addr & ^uint64(0xFFF)) + uint64(imm<<12)
				registerState[reg] = pageAddr
				registerValid[reg] = true
			}
		} else if vs.isADDInstruction(instr) {
			// Check for ADD instruction (add offset to page address)
			dstReg := vs.extractADDDestRegister(instr)
			srcReg := vs.extractADDSourceRegister(instr)
			imm := vs.extractADDImmediate(instr)

			if dstReg < 32 && srcReg < 32 && registerValid[srcReg] {
				finalAddr := registerState[srcReg] + imm
				registerState[dstReg] = finalAddr
				registerValid[dstReg] = true

				// Special case: if this loads our target string into x1, look for immediate BL
				if dstReg == 1 { // x1 register
					for _, stringAddr := range stringAddrs {
						if finalAddr == stringAddr {
							// Found our string loaded into x1! Look for immediate BL instruction
							if err := vs.checkForImmediateBL(r, addr+4, className, stringAddr, candidates); err != nil {
								log.Debugf("Error checking for BL after string load at %#x: %v", addr, err)
							}
						}
					}
				}
			}
		} else if vs.isLDRLiteralToX1(instr) {
			// LDR literal X1, =string: immediate string loading pattern
			strPtr := vs.extractLDRLiteralTarget(addr, instr)
			for _, stringAddr := range stringAddrs {
				if strPtr == stringAddr {
					// Found our string loaded into x1 via LDR literal! Look for immediate BL
					if err := vs.checkForImmediateBL(r, addr+4, className, stringAddr, candidates); err != nil {
						log.Debugf("Error checking for BL after LDR literal at %#x: %v", addr, err)
					}
					break
				}
			}
		} else if vs.isBLInstruction(instr) {
			// Reset register state after function calls (conservative approach)
			for i := range registerValid {
				registerValid[i] = false
			}
		}

		addr += 4
	}

	return nil
}

// checkForImmediateBL looks for a BL instruction immediately following a string load into x1
func (vs *VtableSymbolicator) checkForImmediateBL(r *bytes.Reader, currentAddr uint64, className string, stringAddr uint64, candidates map[uint64]bool) error {
	// Save current position
	pos, _ := r.Seek(0, io.SeekCurrent)

	// Look ahead for BL instruction within next few instructions (allowing for intervening setup)
	maxLookahead := 10 // instructions
	addr := currentAddr

	for i := 0; i < maxLookahead && r.Len() >= 4; i++ {
		var instr uint32
		if err := binary.Read(r, binary.LittleEndian, &instr); err != nil {
			break
		}

		if vs.isBLInstruction(instr) || (instr&0xFFFFFC1F) == 0xD63F0000 /* BLR */ || (instr&0xFFFFFC1F) == 0xD73F0C00 /* BLRAA */ {
			if vs.isBLInstruction(instr) {
				// Found BL instruction - extract target using proper signed arithmetic
				blTarget := vs.decodeBranchTargetFromConstructor(addr, instr)

				candidates[blTarget] = true
				log.Debugf("Found constructor candidate for '%s': string %#x loaded into x1 at %#x, BL to %#x at %#x",
					className, stringAddr, currentAddr-4, blTarget, addr)
			} else {
				// Found BLR/BLRAA - rely on later pass to resolve target
				instrName := "BLR"
				if (instr & 0xFFFFFC1F) == 0xD73F0C00 {
					instrName = "BLRAA"
				}
				log.Debugf("Found constructor candidate for '%s': string %#x loaded into x1 at %#x, %s at %#x (target resolved later)",
					className, stringAddr, currentAddr-4, instrName, addr)
			}
			break
		}

		// Stop if we hit another function call or branch
		if vs.isBranchInstruction(instr) {
			break
		}

		addr += 4
	}

	// Restore position
	r.Seek(pos, io.SeekStart)
	return nil
}

// ARM64 instruction helper functions
func (vs *VtableSymbolicator) isADRPInstruction(instr uint32) bool {
	return (instr & 0x9F000000) == 0x90000000
}

func (vs *VtableSymbolicator) extractADRPRegister(instr uint32) uint32 {
	return instr & 0x1F // Bits 0-4
}

func (vs *VtableSymbolicator) extractADRPImmediate(instr uint32) int64 {
	// ADRP uses PC-relative 4KB page addressing
	// Extract immlo (bits 29-30) and immhi (bits 5-23)
	immlo := (instr >> 29) & 0x3
	immhi := (instr >> 5) & 0x7FFFF
	imm := (immhi << 2) | immlo

	// Sign extend 21-bit immediate
	if imm&0x100000 != 0 {
		imm |= ^uint32(0x1FFFFF)
	}

	return int64(int32(imm))
}

func (vs *VtableSymbolicator) isADDInstruction(instr uint32) bool {
	return (instr & 0xFF000000) == 0x91000000 // ADD (immediate)
}

func (vs *VtableSymbolicator) extractADDDestRegister(instr uint32) uint32 {
	return instr & 0x1F
}

func (vs *VtableSymbolicator) extractADDSourceRegister(instr uint32) uint32 {
	return (instr >> 5) & 0x1F
}

func (vs *VtableSymbolicator) extractADDImmediate(instr uint32) uint64 {
	imm := (instr >> 10) & 0xFFF
	// Check if shift bit is set (bit 22)
	if (instr>>22)&1 != 0 {
		imm <<= 12 // LSL #12
	}
	return uint64(imm)
}

func (vs *VtableSymbolicator) isLDRLiteralToX1(instr uint32) bool {
	// LDR X1, literal: 0x58000001 pattern with 19-bit offset
	return (instr&0xFF000000) == 0x58000000 && (instr&0x1F) == 1 // X1 register
}

func (vs *VtableSymbolicator) extractLDRLiteralTarget(pc uint64, instr uint32) uint64 {
	// Extract 19-bit signed immediate
	imm := (instr >> 5) & 0x7FFFF
	if imm&0x40000 != 0 { // Sign extend
		imm |= ^uint32(0x7FFFF)
	}
	offset := int64(int32(imm)) << 2 // Scale by 4
	return uint64(int64(pc) + offset)
}

func (vs *VtableSymbolicator) isBLInstruction(instr uint32) bool {
	return (instr & 0xFC000000) == 0x94000000
}

// decodeBranchTargetFromConstructor properly decodes BL/B target with signed arithmetic
func (vs *VtableSymbolicator) decodeBranchTargetFromConstructor(pc uint64, instr uint32) uint64 {
	// Extract 26-bit immediate from BL/B instruction
	imm26 := instr & 0x03ffffff

	// Sign-extend to 28-bit signed offset (imm26 << 2)
	// Use proper signed arithmetic to avoid uint wrap bugs
	offset := int64(int32(imm26<<6)>>6) << 2

	// Add to PC using signed arithmetic, then convert to uint64
	return uint64(int64(pc) + offset)
}

func (vs *VtableSymbolicator) extractBLImmediate(instr uint32) int32 {
	imm := instr & 0x03FFFFFF
	// Sign extend 26-bit immediate
	if imm&0x02000000 != 0 {
		imm |= ^uint32(0x03FFFFFF)
	}
	return int32(imm)
}

// isBranchInstruction checks if instruction is any kind of branch (not just BL)
func (vs *VtableSymbolicator) isBranchInstruction(instr uint32) bool {
	// B (unconditional branch)
	if (instr & 0xFC000000) == 0x14000000 {
		return true
	}
	// BL (branch with link)
	if (instr & 0xFC000000) == 0x94000000 {
		return true
	}
	// Conditional branches (B.cond)
	if (instr & 0xFF000010) == 0x54000000 {
		return true
	}
	// CBZ/CBNZ
	if (instr & 0x7E000000) == 0x34000000 {
		return true
	}
	// TBZ/TBNZ
	if (instr & 0x7E000000) == 0x36000000 {
		return true
	}
	return false
}

// findConstructorEntryPoints finds all addresses that BL instructions can target to reach the constructor
func (vs *VtableSymbolicator) findConstructorEntryPoints() {
	log.Debugf("Scanning for simple constructor trampolines and wrappers...")
	
	// Simple approach: scan all functions that are 1-3 instructions long and just call the constructor
	// This catches most stub functions and simple trampolines without complex analysis
	
	added := 0
	maxFunctionsToCheck := 10000 // Reasonable limit
	checked := 0
	
	// Get all executable sections
	for _, sect := range vs.file.Sections {
		if checked >= maxFunctionsToCheck {
			break
		}
		
		seg := vs.file.Segment(sect.Seg)
		if seg == nil || (seg.Prot&0x4) == 0 {
			continue
		}
		
		data, err := sect.Data()
		if err != nil {
			continue
		}
		
		// Scan for short functions that might be trampolines
		for i := 0; i+12 <= len(data); i += 4 { // Check every 4 bytes for potential function starts
			if checked >= maxFunctionsToCheck {
				break
			}
			
			addr := sect.Addr + uint64(i)
			
			// Skip if we already know about this address
			if vs.constructorTargetSet[addr] {
				continue
			}
			
			// Check if this looks like a simple trampoline (1-3 instructions)
			if vs.isSimpleConstructorTrampoline(data[i:], addr, min(64, len(data)-i)) {
				vs.constructorTargetSet[addr] = true
				added++
				log.Debugf("Found constructor trampoline at %#x", addr)
			}
			
			checked++
		}
	}
	
	log.Debugf("Added %d constructor trampolines/wrappers (checked %d potential locations)", added, checked)
}

// isSimpleConstructorTrampoline checks if code at an address is a simple trampoline to the constructor
func (vs *VtableSymbolicator) isSimpleConstructorTrampoline(code []byte, addr uint64, maxLen int) bool {
	if len(code) < 4 {
		return false
	}
	
	// Check the first few instructions for direct BL to constructor
	instrCount := min(3, maxLen/4) // Check up to 3 instructions
	
	for i := 0; i < instrCount && i*4+4 <= len(code); i++ {
		instrValue := binary.LittleEndian.Uint32(code[i*4 : i*4+4])
		instrAddr := addr + uint64(i*4)
		
		// Check for BL instruction
		if (instrValue & 0xFC000000) == 0x94000000 {
			target := vs.decodeBranchTarget(instrAddr, instrValue)
			
			// If this BL targets the constructor directly, this is a trampoline
			if target == vs.constructorAddr {
				return true
			}
			
			// If this BL targets another known constructor entry point, it's also a trampoline
			if vs.constructorTargetSet[target] {
				return true
			}
		}
		
		// Check for B instruction (tail call)
		if (instrValue & 0xFC000000) == 0x14000000 {
			target := vs.decodeBranchTarget(instrAddr, instrValue)
			
			if target == vs.constructorAddr || vs.constructorTargetSet[target] {
				return true
			}
		}
	}
	
	return false
}

// decodeADRPLDRTarget decodes the target address from an ADRP + LDR instruction pair
func (vs *VtableSymbolicator) decodeADRPLDRTarget(stubAddr uint64, adrpInstr, ldrInstr uint32) uint64 {
	// Decode ADRP instruction
	adrpReg := adrpInstr & 0x1F
	immlo := (adrpInstr >> 29) & 0x3
	immhi := (adrpInstr >> 5) & 0x7FFFF
	imm := (immhi << 2) | immlo

	// Sign extend 21-bit immediate
	if imm&0x100000 != 0 {
		imm |= ^uint32(0x1FFFFF)
	}

	pageAddr := (stubAddr & ^uint64(0xFFF)) + uint64(int32(imm)<<12)

	// Decode LDR instruction
	ldrReg := ldrInstr & 0x1F
	ldrSrcReg := (ldrInstr >> 5) & 0x1F

	// Ensure the LDR uses the same register as ADRP destination
	if ldrReg != adrpReg || ldrSrcReg != adrpReg {
		return 0
	}

	// Extract LDR immediate (12-bit, scaled by 8 for 64-bit loads)
	ldrImm := (ldrInstr >> 10) & 0xFFF
	offset := uint64(ldrImm * 8) // Scale by 8 for 64-bit loads

	return pageAddr + offset
}
