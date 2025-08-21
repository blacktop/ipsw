package vtable

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

// ARM64 instruction constants
const (
	// Instruction masks and opcodes
	BL_MASK        = 0xFC000000
	BL_OPCODE      = 0x94000000
	B_OPCODE       = 0x14000000
	BLR_MASK       = 0xFFFFFC1F
	BLR_OPCODE     = 0xD63F0000
	BLRAA_OPCODE   = 0xD73F0C00
	ADRP_MASK      = 0x9F000000
	ADRP_OPCODE    = 0x90000000
	ADD_IMM_MASK   = 0xFF000000
	ADD_IMM_OPCODE = 0x91000000
	LDR_LIT_MASK   = 0xFF000000
	LDR_LIT_OPCODE = 0x58000000
	MOV_REG_MASK   = 0x7FE0FFE0
	MOV_REG_OPCODE = 0x2A0003E0
	MOVZ_MASK      = 0x7F800000
	MOVZ_OPCODE    = 0x52800000
	MOVK_MASK      = 0x7F800000
	MOVK_OPCODE    = 0x72800000
	ORR_REG_MASK   = 0x7FE0FFE0
	ORR_XZR_X      = 0xAA0003E0

	// Register extraction masks
	REG_MASK      = 0x1F
	SRC_REG_SHIFT = 5
	IMM12_MASK    = 0xFFF
	IMM12_SHIFT   = 10
	IMM19_MASK    = 0x7FFFF
	IMM19_SHIFT   = 5
	IMM16_MASK    = 0xFFFF
	IMM16_SHIFT   = 5

	// Immediate value constants
	IMM26_MASK     = 0x03FFFFFF
	IMM26_SIGN_BIT = 0x02000000
	IMM26_SIGN_EXT = -0x04000000
	IMM21_SIGN_BIT = 0x100000
	IMM21_SIGN_EXT = ^uint32(0x1FFFFF)
	IMM19_SIGN_BIT = 0x40000
	IMM19_SIGN_EXT = ^uint32(0x7FFFF)

	// Memory and analysis constants
	MAX_STRING_LEN     = 256
	MAX_LOOKBACK       = 32
	MAX_CONTEXT_INSTRS = 16
	INSTR_SIZE         = 4
	VM_PROT_EXECUTE    = 0x4
	PAGE_MASK          = 0xFFF
	REGISTER_COUNT     = 32

	// PAC stripping mask
	PAC_MASK = 0x0000FFFFFFFFFFFF
)

// discoverClasses scans for OSMetaClass constructor calls to discover C++ classes
func (vs *VtableSymbolicator) discoverClasses() error {
	if vs.constructorAddr == 0 {
		return fmt.Errorf("OSMetaClass constructor not found")
	}

	// Get all executable sections (any section in executable segments)
	var executableSections []*types.Section
	for _, sect := range vs.file.Sections {
		// Find the segment for this section
		seg := vs.file.Segment(sect.Seg)
		if seg == nil {
			continue
		}

		// Include any section in an executable segment (remove S_REGULAR restriction)
		if (seg.Prot & VM_PROT_EXECUTE) != 0 {
			executableSections = append(executableSections, sect)
		}
	}

	sectionNames := make([]string, len(executableSections))
	for i, sect := range executableSections {
		sectionNames[i] = fmt.Sprintf("%s.%s", sect.Seg, sect.Name)
	}
	log.Debugf("Scanning %d executable sections: %v", len(executableSections), sectionNames)

	// Scan only the executable sections for constructor calls
	for _, sect := range executableSections {
		data, err := sect.Data()
		if err != nil || len(data) == 0 {
			off, err2 := vs.file.GetOffset(sect.Addr)
			if err2 != nil || off == 0 {
				log.Debugf("Skipping section %s.%s: %v", sect.Seg, sect.Name, err)
				continue
			}
			data = make([]byte, sect.Size)
			if n, err3 := vs.file.ReadAt(data, int64(off)); err3 != nil || n != len(data) {
				log.Debugf("Skipping section %s.%s: readAt failed: %v", sect.Seg, sect.Name, err3)
				continue
			}
		}

		log.Debugf("Scanning section %s.%s (addr: %#x, size: %#x)", sect.Seg, sect.Name, sect.Addr, sect.Size)

		if err := vs.scanSectionForClasses(sect, data); err != nil {
			log.Warnf("Failed to scan section %s.%s for classes: %v", sect.Seg, sect.Name, err)
		}
	}

	log.Debugf("Discovered %d classes", len(vs.classes))

	// Log discovery counters in verbose mode
	vs.logDiscoveryCounters()

	return nil
}

// scanSectionForClasses scans a single section for OSMetaClass constructor calls
func (vs *VtableSymbolicator) scanSectionForClasses(sect *types.Section, data []byte) error {
	r := bytes.NewReader(data)
	addr := sect.Addr
	blCount := 0
	maxInstructions := 1000000 // Safety limit: max 1M instructions per section
	instructionCount := 0

	for r.Len() > 0 && instructionCount < maxInstructions {
		instructionCount++
		var instrValue uint32
		if err := binary.Read(r, binary.LittleEndian, &instrValue); err != nil {
			break
		}

		// Check if this is a BL or B instruction to any constructor (direct or indirect)
		isBL := (instrValue & BL_MASK) == BL_OPCODE
		isB := (instrValue & BL_MASK) == B_OPCODE

		if isBL || isB {
			blCount++
			vs.counters.TotalBLInstructions++

			if blCount <= 5 {
				instrType := "BL"
				if isB {
					instrType = "B"
				}
				log.Debugf("Found %s instruction #%d at %#x: %#08x", instrType, blCount, addr, instrValue)
			}

			// Fix critical branch target arithmetic - use proper signed arithmetic
			target := vs.decodeBranchTarget(addr, instrValue)

			isConstructorCall := vs.constructorTargetSet[target]
			symbolFallbackUsed := false

			// Fallback: check symbol table for constructor symbol name when Symtab is present
			if !isConstructorCall && vs.file.Symtab != nil {
				strippedTarget := stripPAC(target)
				for _, sym := range vs.file.Symtab.Syms {
					if (sym.Value == target || sym.Value == strippedTarget) && vs.isConstructorSymbolName(sym.Name) {
						isConstructorCall = true
						symbolFallbackUsed = true
						log.Debugf("Accepted constructor by symbol name fallback: %s at %#x (PAC-aware)", sym.Name, sym.Value)
						break
					}
				}
			}

			if isConstructorCall {
				vs.counters.AcceptedBL++
				if symbolFallbackUsed {
					vs.counters.SymbolFallbackUsed++
				}
				// Found a call to OSMetaClass constructor (BL or tail-call B)
				instrType := "BL"
				if isB {
					instrType = "B (tail-call)"
				}
				log.Debugf("Found OSMetaClass constructor %s at %#x", instrType, addr)
				if err := vs.analyzeConstructorCall(addr, data, int(addr-sect.Addr)); err != nil {
					log.Warnf("Failed to analyze constructor call at %#x: %v", addr, err)
				} else {
					log.Debugf("Successfully analyzed constructor call at %#x", addr)
				}
			} else {
				vs.counters.RejectedTargetNotInSet++
				if addr < sect.Addr+20*INSTR_SIZE { // Log first 20 BL/B instructions to see targets
					instrType := "BL"
					if isB {
						instrType = "B"
					}
					log.Debugf("%s instruction at %#x targets %#x (not in constructor target set)", instrType, addr, target)
				}
			}
		}

		// Detect BLR/BLRAA Xn and resolve Xn from a small backward window
		isBLR := (instrValue & BLR_MASK) == BLR_OPCODE
		isBLRAA := (instrValue & BLR_MASK) == BLRAA_OPCODE
		if isBLR || isBLRAA {
			vs.counters.TotalBLRInstructions++

			// Extract Xn
			xn := (instrValue >> SRC_REG_SHIFT) & REG_MASK
			// Walk back ~10 insns to resolve Xn as an address via ADR(P)+ADD/ADR+LDR/LDR literal/MOVZ/MOVK/MOV reg
			if ptr, ok := vs.resolveRegAsAddress(addr, xn, 10, sect, data); ok {
				target := ptr
				derefFailed := false

				// If the resolved address isn't in the target set, try dereferencing it (GOT/const pointer slot)
				if !vs.constructorTargetSet[target] {
					// Try to dereference the GOT/const slot
					if tgt, err := vs.file.GetPointerAtAddress(target); err == nil && tgt != 0 {
						target = tgt
					} else if val, err := vs.readUint64AtAddr(target); err == nil && val != 0 {
						target = val
					} else {
						derefFailed = true
					}
				}

				// Strip PAC bits before checking target set and symbol table
				strippedTarget := stripPAC(target)
				isConstructorCall := vs.constructorTargetSet[strippedTarget]
				symbolFallbackUsed := false

				// Also try the original target in case PAC wasn't used
				if !isConstructorCall {
					isConstructorCall = vs.constructorTargetSet[target]
				}

				// Fallback: check symbol table for constructor symbol name when Symtab is present
				if !isConstructorCall && vs.file.Symtab != nil {
					for _, sym := range vs.file.Symtab.Syms {
						if (sym.Value == target || sym.Value == strippedTarget) && vs.isConstructorSymbolName(sym.Name) {
							isConstructorCall = true
							symbolFallbackUsed = true
							log.Debugf("Accepted constructor by symbol name fallback: %s at %#x (PAC-aware)", sym.Name, sym.Value)
							break
						}
					}
				}

				if isConstructorCall {
					vs.counters.AcceptedBLR++
					if symbolFallbackUsed {
						vs.counters.SymbolFallbackUsed++
					}
					instrType := "BLR"
					if isBLRAA {
						instrType = "BLRAA"
					}
					if target != ptr {
						log.Debugf("Found OSMetaClass constructor %s at %#x (slot: %#x -> target: %#x)", instrType, addr, ptr, target)
					} else {
						log.Debugf("Found OSMetaClass constructor %s at %#x (target: %#x)", instrType, addr, target)
					}
					if err := vs.analyzeConstructorCall(addr, data, int(addr-sect.Addr)); err != nil {
						log.Warnf("Failed to analyze constructor call (%s) at %#x: %v",
							map[bool]string{true: "BLRAA", false: "BLR"}[isBLRAA], addr, err)
					} else {
						log.Debugf("Successfully analyzed constructor call (%s) at %#x",
							map[bool]string{true: "BLRAA", false: "BLR"}[isBLRAA], addr)
					}
				} else {
					// Count rejection reasons
					if derefFailed {
						vs.counters.RejectedDerefFailed++
					} else {
						vs.counters.RejectedTargetNotInSet++
					}
				}
			}
		}

		addr += INSTR_SIZE
	}

	return nil
}

// logDiscoveryCounters logs diagnostic counters
func (vs *VtableSymbolicator) logDiscoveryCounters() {
	log.Debugf("Discovery counters:")
	log.Debugf("  Total BL instructions: %d", vs.counters.TotalBLInstructions)
	log.Debugf("  Total BLR instructions: %d", vs.counters.TotalBLRInstructions)
	log.Debugf("  Accepted BL: %d", vs.counters.AcceptedBL)
	log.Debugf("  Accepted BLR: %d", vs.counters.AcceptedBLR)
	log.Debugf("  Rejected (target not in set): %d", vs.counters.RejectedTargetNotInSet)
	log.Debugf("  Rejected (X1 not known): %d", vs.counters.RejectedX1NotKnown)
	log.Debugf("  Rejected (deref failed): %d", vs.counters.RejectedDerefFailed)
	log.Debugf("  Symbol fallback used: %d", vs.counters.SymbolFallbackUsed)
}

// isConstructorSymbolName checks if a symbol name matches OSMetaClass constructor patterns
func (vs *VtableSymbolicator) isConstructorSymbolName(name string) bool {
	return name == "__ZN11OSMetaClassC2EPKcPKS_j" ||
		name == "__ZN11OSMetaClassC1EPKcPKS_j" ||
		name == "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t" ||
		name == "__ZN11OSMetaClassC1EPKcPKS_jPP4zoneS1_19zone_create_flags_t"
}

// stripPAC strips Pointer Authentication Code (PAC) bits from an address
func stripPAC(addr uint64) uint64 {
	// For 64-bit ARM pointers, PAC typically uses the upper 16 bits
	// Keep the lower 48 bits which contain the actual address
	return addr & PAC_MASK
}

// decodeBranchTarget properly decodes BL/B target with signed arithmetic
func (vs *VtableSymbolicator) decodeBranchTarget(pc uint64, instr uint32) uint64 {
	// Extract 26-bit immediate from BL/B instruction
	imm26 := instr & IMM26_MASK

	// Sign-extend to 28-bit signed offset (imm26 << 2)
	// Use proper signed arithmetic to avoid uint wrap bugs
	offset := int64(int32(imm26<<6)>>6) << 2

	// Add to PC using signed arithmetic, then convert to uint64
	return uint64(int64(pc) + offset)
}

// resolveRegAsAddress resolves a register as an address by looking back through recent instructions
func (vs *VtableSymbolicator) resolveRegAsAddress(addr uint64, reg uint32, window int, sect *types.Section, data []byte) (uint64, bool) {
	// Calculate the offset of the current address in the section data
	if addr < sect.Addr || addr >= sect.Addr+sect.Size {
		return 0, false
	}

	currentOffset := int(addr - sect.Addr)
	if currentOffset >= len(data) {
		return 0, false
	}

	// Look backward through instructions to track register value
	var registerState [REGISTER_COUNT]uint64 // Track X0-X31 register values
	var registerValid [REGISTER_COUNT]bool   // Track which registers have valid values

	// Scan backward up to 'window' instructions
	maxOffset := max(0, currentOffset-window*INSTR_SIZE)

	for offset := currentOffset - INSTR_SIZE; offset >= maxOffset && offset >= 0; offset -= INSTR_SIZE {
		if offset < 0 || offset+INSTR_SIZE > len(data) {
			continue
		}

		instrValue := binary.LittleEndian.Uint32(data[offset : offset+INSTR_SIZE])
		instrAddr := sect.Addr + uint64(offset)

		// Check for ADRP instruction (page address calculation)
		if (instrValue & ADRP_MASK) == ADRP_OPCODE {
			dstReg := instrValue & REG_MASK
			if dstReg < REGISTER_COUNT {
				// Extract ADRP immediate
				immlo := (instrValue >> 29) & 0x3
				immhi := (instrValue >> 5) & 0x7FFFF
				imm := (immhi << 2) | immlo

				// Sign extend 21-bit immediate
				if imm&IMM21_SIGN_BIT != 0 {
					imm |= IMM21_SIGN_EXT
				}

				pageAddr := (instrAddr & ^uint64(PAGE_MASK)) + uint64(int32(imm)<<12)
				registerState[dstReg] = pageAddr
				registerValid[dstReg] = true
			}
		}

		// Check for ADD instruction (add offset to page address)
		if (instrValue & ADD_IMM_MASK) == ADD_IMM_OPCODE { // ADD immediate
			dstReg := instrValue & REG_MASK
			srcReg := (instrValue >> SRC_REG_SHIFT) & REG_MASK
			imm := (instrValue >> IMM12_SHIFT) & IMM12_MASK

			// Check if shift bit is set (bit 22)
			if (instrValue>>22)&1 != 0 {
				imm <<= 12 // LSL #12
			}

			if dstReg < REGISTER_COUNT && srcReg < REGISTER_COUNT && registerValid[srcReg] {
				registerState[dstReg] = registerState[srcReg] + uint64(imm)
				registerValid[dstReg] = true
			}
		}

		// Check for LDR literal instruction
		if (instrValue & LDR_LIT_MASK) == LDR_LIT_OPCODE { // LDR literal
			dstReg := instrValue & REG_MASK
			if dstReg < REGISTER_COUNT {
				// Extract 19-bit signed immediate
				imm := (instrValue >> IMM19_SHIFT) & IMM19_MASK
				if imm&IMM19_SIGN_BIT != 0 { // Sign extend
					imm |= IMM19_SIGN_EXT
				}
				literalAddr := instrAddr + uint64(int32(imm)<<2)

				// Try to read the value at the literal address
				if value, err := vs.readUint64AtAddr(literalAddr); err == nil {
					registerState[dstReg] = value
					registerValid[dstReg] = true
				}
			}
		}

		// Check for MOV (register) instruction
		if (instrValue & MOV_REG_MASK) == MOV_REG_OPCODE { // MOV Wd, Wm (alias for ORR Wd, WZR, Wm)
			dstReg := instrValue & REG_MASK
			srcReg := (instrValue >> 16) & REG_MASK
			if dstReg < REGISTER_COUNT && srcReg < REGISTER_COUNT && registerValid[srcReg] {
				registerState[dstReg] = registerState[srcReg]
				registerValid[dstReg] = true
			}
		}

		// Check for MOV (wide immediate) instructions - MOVZ, MOVK
		if (instrValue & MOVZ_MASK) == MOVZ_OPCODE { // MOVZ
			dstReg := instrValue & REG_MASK
			if dstReg < REGISTER_COUNT {
				imm := (instrValue >> IMM16_SHIFT) & IMM16_MASK
				shift := ((instrValue >> 21) & 0x3) * 16
				registerState[dstReg] = uint64(imm) << shift
				registerValid[dstReg] = true
			}
		}

		// Add MOVK handling for building 64-bit immediates
		if (instrValue & MOVK_MASK) == MOVK_OPCODE { // MOVK
			dstReg := instrValue & REG_MASK
			if dstReg < REGISTER_COUNT && registerValid[dstReg] {
				imm := (instrValue >> IMM16_SHIFT) & IMM16_MASK
				shift := ((instrValue >> 21) & 0x3) * 16
				// Keep existing bits, update only the shifted 16-bit field
				mask := uint64(0xFFFF) << shift
				registerState[dstReg] = (registerState[dstReg] &^ mask) | (uint64(imm) << shift)
				// registerValid remains true since we're building on existing value
			}
		}

		// Also accept ORR-based MOV Xd, Xn (64-bit)
		if (instrValue & ORR_REG_MASK) == ORR_XZR_X { // MOV Xd, Xn via ORR Xd, XZR, Xn
			dstReg := instrValue & REG_MASK
			srcReg := (instrValue >> 16) & REG_MASK
			if dstReg < REGISTER_COUNT && srcReg < REGISTER_COUNT && registerValid[srcReg] {
				registerState[dstReg] = registerState[srcReg]
				registerValid[dstReg] = true
			}
		}

		// If we found the value for our target register, return it
		if reg < REGISTER_COUNT && registerValid[reg] {
			return registerState[reg], true
		}
	}

	// If we reach here, we couldn't resolve the register value
	return 0, false
}

func (vs *VtableSymbolicator) readUint64AtAddr(addr uint64) (uint64, error) {
	// Validate address is not zero
	if addr == 0 {
		return 0, fmt.Errorf("cannot read from null address")
	}

	// Try to read from file segments
	for _, seg := range vs.file.Segments() {
		if addr >= seg.Addr && addr+8 <= seg.Addr+seg.Filesz {
			data, err := seg.Data()
			if err != nil {
				log.Debugf("Failed to get segment data for %s: %v", seg.Name, err)
				continue
			}
			offset := addr - seg.Addr
			if offset+8 <= uint64(len(data)) {
				return binary.LittleEndian.Uint64(data[offset : offset+8]), nil
			}
			log.Debugf("Offset %d+8 beyond segment %s data length %d", offset, seg.Name, len(data))
		}
	}
	return 0, fmt.Errorf("address %#x not readable in any segment", addr)
}

func (vs *VtableSymbolicator) analyzeConstructorCall(callAddr uint64, sectionData []byte, offset int) error {
	// We need to trace backwards to find the register setup for the constructor call
	// OSMetaClass constructor signature: OSMetaClass(const char* className, const OSMetaClass* superClass, unsigned int classSize)
	// On ARM64: X0 = this (MetaClass object ptr), X1 = className, X2 = superClass, X3 = classSize

	// Create a simple ARM64 instruction tracer to extract register values
	tracer := &ConstructorTracer{
		file:            vs.file,
		callAddr:        callAddr,
		constructorAddr: vs.constructorAddr,
		segData:         sectionData,
		offset:          offset,
		vs:              vs, // Add reference to parent for cache access
	}

	classInfo, err := tracer.extractClassInfo()
	if err != nil {
		log.Debugf("Failed to trace constructor call at %#x: %v", callAddr, err)

		// Try partial-state salvage via static X1/X0 extraction before falling back to placeholder
		log.Debugf("Attempting static X1 extraction for failed call at %#x", callAddr)

		if className, _, err2 := vs.extractX1NameStatically(callAddr); err2 == nil && className != "" {
			metaPtr, _ := vs.extractX0ValueStatically(callAddr) // best-effort

			// Avoid key collision: never insert with key 0, and don't overwrite existing
			key := metaPtr
			if key == 0 {
				// synthesize a unique key so we don't collide on 0
				key = (uint64(1) << 63) | callAddr
			}

			// don't overwrite existing entries
			if _, exists := vs.classes[key]; !exists {
				classMeta := &ClassMeta{
					Name:        className,
					Size:        0,
					MetaPtr:     metaPtr,
					SuperMeta:   0,
					DiscoveryPC: callAddr,
				}
				vs.classes[key] = classMeta
				if _, ok := vs.classByName[className]; !ok {
					vs.classByName[className] = classMeta
				}

				log.Debugf("Salvaged class via static X1/X0: %s (meta=%#x, key=%#x) at %#x", className, metaPtr, key, callAddr)
			}

			return nil
		}

		// X1 name extraction failed
		vs.counters.RejectedX1NotKnown++

		// Log unresolved X1 site before creating placeholder
		if sect := vs.findSectionContaining(callAddr); sect != nil {
			if data, err := sect.Data(); err == nil {
				vs.logUnresolved(callAddr, sect, data)
			}
		}

		// Create a placeholder entry for failed extractions
		return vs.createPlaceholderClass(callAddr)
	}

	log.Debugf("Extracted class info: name=%s, metaPtr=%#x, size=%d", classInfo.ClassName, classInfo.MetaPtr, classInfo.ClassSize)

	// Create the class metadata entry
	classMeta := &ClassMeta{
		Name:        classInfo.ClassName,
		Size:        classInfo.ClassSize,
		MetaPtr:     classInfo.MetaPtr,
		SuperMeta:   classInfo.SuperMeta,
		DiscoveryPC: callAddr,
	}

	// CRITICAL FIX: Use synthetic key when MetaPtr is 0 to avoid collisions
	key := classMeta.MetaPtr
	if key == 0 {
		key = (uint64(1) << 63) | callAddr // synthetic stable key
	}

	vs.classes[key] = classMeta
	vs.classByName[classMeta.Name] = classMeta

	log.Debugf("Discovered class %s at %#x (key: %#x, size: %d, super: %#x)",
		classMeta.Name, classMeta.MetaPtr, key, classMeta.Size, classMeta.SuperMeta)

	return nil
}

// ConstructorTracer traces ARM64 instructions to extract class metadata from constructor calls
type ConstructorTracer struct {
	file            *macho.File
	callAddr        uint64
	constructorAddr uint64
	segData         []byte
	offset          int
	verbose         bool
	vs              *VtableSymbolicator // Reference to parent for cache access
}

// ConstructorClassInfo holds extracted class information from constructor analysis
type ConstructorClassInfo struct {
	ClassName string
	ClassSize uint32
	MetaPtr   uint64
	SuperMeta uint64
}

// extractClassInfo extracts class metadata from constructor call using static analysis
func (ct *ConstructorTracer) extractClassInfo() (*ConstructorClassInfo, error) {
	// Extract class name from X1 register
	className, err := ct.extractX1ClassName()
	if err != nil {
		return nil, fmt.Errorf("failed to extract class name: %v", err)
	}

	// Extract meta pointer from X0 register
	metaPtr, err := ct.extractX0MetaPtr()
	if err != nil {
		log.Debugf("Failed to extract meta pointer: %v", err)
		metaPtr = 0 // Use fallback
	}

	// Extract superclass from X2 register
	superMeta, err := ct.extractX2SuperClass()
	if err != nil {
		log.Debugf("Failed to extract superclass: %v", err)
		superMeta = 0 // Use fallback
	}

	// Extract class size from X3 register
	classSize, err := ct.extractX3ClassSize()
	if err != nil {
		log.Debugf("Failed to extract class size: %v", err)
		classSize = 0 // Use fallback
	}

	return &ConstructorClassInfo{
		ClassName: className,
		ClassSize: classSize,
		MetaPtr:   metaPtr,
		SuperMeta: superMeta,
	}, nil
}

// extractX1ClassName extracts the class name string from X1 register
func (ct *ConstructorTracer) extractX1ClassName() (string, error) {
	// Look backward for ADRP/ADD or LDR patterns that load string address into X1
	currentOffset := ct.offset

	for i := 0; i < MAX_LOOKBACK && currentOffset >= INSTR_SIZE; i++ {
		currentOffset -= INSTR_SIZE
		if currentOffset < 0 || currentOffset+INSTR_SIZE > len(ct.segData) {
			break
		}

		instrValue := binary.LittleEndian.Uint32(ct.segData[currentOffset : currentOffset+INSTR_SIZE])
		addr := ct.callAddr - uint64(ct.offset-currentOffset)

		// Check for ADD instruction to X1 (final step of ADRP/ADD)
		if (instrValue & ADD_IMM_MASK) == ADD_IMM_OPCODE { // ADD immediate
			dstReg := instrValue & REG_MASK
			if dstReg == 1 { // X1
				// Extract ADD immediate with optional LSL #12 when bit 22 = 1
				imm := (instrValue >> IMM12_SHIFT) & IMM12_MASK
				if (instrValue>>22)&1 != 0 {
					imm <<= 12 // LSL #12
				}

				// Found ADD to X1, look for preceding ADRP and add the immediate
				adrpAddr, ok := ct.findPrecedingADRP(currentOffset, 1)
				if ok {
					// CRITICAL FIX: Add the ADD immediate to the ADRP page address
					finalAddr := adrpAddr + uint64(imm)
					return ct.extractStringFromAddress(finalAddr)
				}
			}
		}

		// Check for LDR literal to X1
		if (instrValue & LDR_LIT_MASK) == LDR_LIT_OPCODE { // LDR literal
			reg := instrValue & REG_MASK
			if reg == 1 { // X1
				// Calculate literal address
				imm := (instrValue >> IMM19_SHIFT) & IMM19_MASK
				if imm&IMM19_SIGN_BIT != 0 { // Sign extend
					imm |= IMM19_SIGN_EXT
				}
				literalAddr := addr + uint64(int32(imm)<<2)

				// Read the pointer at the literal address
				if stringAddr, err := ct.vs.readUint64AtAddr(literalAddr); err == nil {
					return ct.extractStringFromAddress(stringAddr)
				}
			}
		}
	}

	return "", fmt.Errorf("could not find X1 string setup")
}

// findPrecedingADRP looks backward for an ADRP instruction targeting the specified register
func (ct *ConstructorTracer) findPrecedingADRP(startOffset int, targetReg uint32) (uint64, bool) {
	for offset := startOffset - INSTR_SIZE; offset >= max(startOffset-64, 0) && offset >= 0; offset -= INSTR_SIZE {
		if offset+INSTR_SIZE > len(ct.segData) {
			continue
		}
		instrValue := binary.LittleEndian.Uint32(ct.segData[offset : offset+INSTR_SIZE])

		// Check for ADRP
		if (instrValue & ADRP_MASK) == ADRP_OPCODE {
			reg := instrValue & REG_MASK
			if reg == targetReg {
				// Calculate ADRP target address
				addr := ct.callAddr - uint64(ct.offset-offset)
				immlo := (instrValue >> 29) & 0x3
				immhi := (instrValue >> 5) & 0x7FFFF
				imm := (immhi << 2) | immlo

				// Sign extend 21-bit immediate
				if imm&IMM21_SIGN_BIT != 0 {
					imm |= IMM21_SIGN_EXT
				}

				pageAddr := (addr & ^uint64(PAGE_MASK)) + uint64(int32(imm)<<12)
				return pageAddr, true
			}
		}
	}

	return 0, false
}

// extractStringFromAddress reads a C string from the given address
func (ct *ConstructorTracer) extractStringFromAddress(addr uint64) (string, error) {
	// Read up to MAX_STRING_LEN bytes to find the string

	for _, seg := range ct.file.Segments() {
		if addr >= seg.Addr && addr < seg.Addr+seg.Filesz {
			data, err := seg.Data()
			if err != nil {
				continue
			}

			offset := addr - seg.Addr
			if offset >= uint64(len(data)) {
				continue
			}

			// Find null terminator
			end := offset
			for end < uint64(len(data)) && end < offset+MAX_STRING_LEN && data[end] != 0 {
				end++
			}

			if end > offset {
				return string(data[offset:end]), nil
			}
		}
	}

	return "", fmt.Errorf("could not read string at address %#x", addr)
}

// extractX0MetaPtr extracts the meta pointer from X0 register
func (ct *ConstructorTracer) extractX0MetaPtr() (uint64, error) {
	currentOffset := ct.offset

	for i := 0; i < MAX_LOOKBACK && currentOffset >= INSTR_SIZE; i++ {
		currentOffset -= INSTR_SIZE
		if currentOffset < 0 || currentOffset+INSTR_SIZE > len(ct.segData) {
			break
		}

		instrValue := binary.LittleEndian.Uint32(ct.segData[currentOffset : currentOffset+INSTR_SIZE])
		addr := ct.callAddr - uint64(ct.offset-currentOffset)

		// Check for ADD instruction to X0 (final step of ADRP/ADD)
		if (instrValue & ADD_IMM_MASK) == ADD_IMM_OPCODE { // ADD immediate
			dstReg := instrValue & REG_MASK
			if dstReg == 0 { // X0
				// Extract ADD immediate with optional LSL #12 when bit 22 = 1
				imm := (instrValue >> IMM12_SHIFT) & IMM12_MASK
				if (instrValue>>22)&1 != 0 {
					imm <<= 12 // LSL #12
				}

				// Found ADD to X0, look for preceding ADRP and add the immediate
				adrpAddr, ok := ct.findPrecedingADRP(currentOffset, 0)
				if ok {
					metaPtr := adrpAddr + uint64(imm)
					if metaPtr != 0 {
						return metaPtr, nil
					}
				}
			}
		}

		// Check for LDR literal to X0
		if (instrValue & LDR_LIT_MASK) == LDR_LIT_OPCODE { // LDR literal
			reg := instrValue & REG_MASK
			if reg == 0 { // X0
				// Calculate literal address
				imm := (instrValue >> IMM19_SHIFT) & IMM19_MASK
				if imm&IMM19_SIGN_BIT != 0 { // Sign extend
					imm |= IMM19_SIGN_EXT
				}
				literalAddr := addr + uint64(int32(imm)<<2)

				// Read the pointer at the literal address
				if metaPtr, err := ct.vs.readUint64AtAddr(literalAddr); err == nil && metaPtr != 0 {
					return metaPtr, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("could not extract X0 meta ptr")
}

func (ct *ConstructorTracer) extractX2SuperClass() (uint64, error) {
	// TODO: Implement X2 superclass extraction
	return 0, fmt.Errorf("X2 extraction not yet implemented")
}

func (ct *ConstructorTracer) extractX3ClassSize() (uint32, error) {
	// TODO: Implement X3 class size extraction
	return 0, fmt.Errorf("X3 extraction not yet implemented")
}

// Helper functions for analyzeConstructorCall
func (vs *VtableSymbolicator) extractX1NameStatically(callAddr uint64) (string, uint64, error) {
	// Find the section containing the call
	sect := vs.findSectionContaining(callAddr)
	if sect == nil {
		return "", 0, fmt.Errorf("call address not in any section")
	}

	data, err := sect.Data()
	if err != nil {
		return "", 0, err
	}

	offset := int(callAddr - sect.Addr)
	if offset >= len(data) {
		return "", 0, fmt.Errorf("offset beyond section")
	}

	// Use ConstructorTracer for extraction
	tracer := &ConstructorTracer{
		file:     vs.file,
		callAddr: callAddr,
		segData:  data,
		offset:   offset,
		vs:       vs,
	}

	className, err := tracer.extractX1ClassName()
	return className, 0, err
}

func (vs *VtableSymbolicator) extractX0ValueStatically(callAddr uint64) (uint64, error) {
	// TODO: Implement X0 value extraction
	return 0, fmt.Errorf("X0 extraction not implemented")
}

func (vs *VtableSymbolicator) findSectionContaining(addr uint64) *types.Section {
	for _, sect := range vs.file.Sections {
		if addr >= sect.Addr && addr < sect.Addr+sect.Size {
			return sect
		}
	}
	return nil
}

func (vs *VtableSymbolicator) logUnresolved(callAddr uint64, sect *types.Section, data []byte) {
	// Add to unresolved ring buffer
	offset := int(callAddr - sect.Addr)
	context := make([]uint32, 0, MAX_CONTEXT_INSTRS)

	// Extract context instructions with bounds checking
	for i := max(0, offset-32); i < min(len(data)-3, offset+32) && i+INSTR_SIZE <= len(data); i += INSTR_SIZE {
		if i < 0 || i+INSTR_SIZE > len(data) {
			continue
		}
		instrValue := binary.LittleEndian.Uint32(data[i : i+INSTR_SIZE])
		context = append(context, instrValue)
		if len(context) >= MAX_CONTEXT_INSTRS {
			break
		}
	}

	entry := rbEntry{
		CallAddr: callAddr,
		FnStart:  0, // TODO: find function start
		Context:  context,
	}

	vs.unresolvedRB.push(entry)
	log.Debugf("Logged unresolved call at %#x", callAddr)
}

func (vs *VtableSymbolicator) createPlaceholderClass(callAddr uint64) error {
	// Create a placeholder class entry
	key := (uint64(1) << 63) | callAddr // Synthetic key to avoid collisions

	if _, exists := vs.classes[key]; !exists {
		classMeta := &ClassMeta{
			Name:        fmt.Sprintf("UnknownClass_%x", callAddr),
			Size:        0,
			MetaPtr:     key,
			SuperMeta:   0,
			DiscoveryPC: callAddr,
		}

		vs.classes[key] = classMeta
		vs.classByName[classMeta.Name] = classMeta

		log.Debugf("Created placeholder class %s at %#x", classMeta.Name, callAddr)
	}

	return nil
}
