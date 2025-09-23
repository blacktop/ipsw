package cpp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
)

// findVtableBySymbol looks up vtables using C++ name mangling
func (c *Cpp) findVtableBySymbol(m *macho.File, className string) (vtable, metaVtable uint64) {
	if m.Symtab == nil {
		if exports, err := m.DyldExports(); err != nil || len(exports) == 0 {
			return 0, 0
		}
	}

	// Build mangled names
	nameLen := len(className)
	mainSymbol := fmt.Sprintf("__ZTV%d%s", nameLen, className)
	metaSymbol := fmt.Sprintf("__ZTVN%d%s9MetaClassE", nameLen, className)

	// Try FindSymbolAddress for main vtable
	if addr, err := m.FindSymbolAddress(mainSymbol); err == nil {
		vtable = addr + 16 // Skip 16-byte vtable header
	}

	// Try FindSymbolAddress for meta vtable
	if addr, err := m.FindSymbolAddress(metaSymbol); err == nil {
		metaVtable = addr + 16 // Skip 16-byte vtable header
	}

	// Also check DyldExports if Symtab didn't have it
	if exports, err := m.DyldExports(); err == nil {
		for _, exp := range exports {
			switch exp.Name {
			case mainSymbol:
				vtable = exp.Address + 16
			case metaSymbol:
				metaVtable = exp.Address + 16
			}
		}
	}

	return vtable, metaVtable
}

func registerToIndex(reg disassemble.Register) (int, bool) {
	switch {
	case reg >= disassemble.REG_X0 && reg <= disassemble.REG_X30:
		return int(reg - disassemble.REG_X0), true
	case reg >= disassemble.REG_W0 && reg <= disassemble.REG_W30:
		return int(reg - disassemble.REG_W0), true
	default:
		return 0, false
	}
}

func (c *Cpp) emulateCtorForVtable(m *macho.File, ctorAddr uint64) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("MachO file is not available")
	}
	if ctorAddr == 0 {
		return 0, fmt.Errorf("constructor address is not set")
	}

	fn, err := m.GetFunctionForVMAddr(ctorAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to locate constructor function: %w", err)
	}

	funcData, cached := c.fdCache.get(fn.StartAddr)
	if !cached {
		funcData, err = m.GetFunctionData(fn)
		if err != nil {
			return 0, fmt.Errorf("failed to read constructor bytes: %w", err)
		}
		c.fdCache.put(fn.StartAddr, funcData)
	}

	emuCfg := emulate.DefaultEngineConfig()
	emuCfg.InitialPC = fn.StartAddr
	emuCfg.StopAddress = fn.EndAddr + 4
	emuCfg.MaxInstructions = 512
	emuCfg.StopOnError = false
	emuCfg.MemoryHandler = func(addr uint64, size int) ([]byte, error) {
		if addr >= fn.StartAddr && addr < fn.StartAddr+uint64(len(funcData)) {
			offset := addr - fn.StartAddr
			if offset+uint64(size) <= uint64(len(funcData)) {
				return funcData[offset : offset+uint64(size)], nil
			}
		}
		buf := make([]byte, size)
		if _, err := m.ReadAtAddr(buf, addr); err != nil {
			return make([]byte, size), nil
		}
		return buf, nil
	}

	var vtableAddr uint64
	preHook := core.PreInstructionHook(func(state core.State, info core.InstructionInfo) core.HookResult {
		instr := info.Instruction
		if instr == nil {
			return core.HookResult{}
		}

		switch instr.Operation {
		case disassemble.ARM64_STR, disassemble.ARM64_STUR:
			if len(instr.Operands) < 2 {
				return core.HookResult{}
			}
			memOp := instr.Operands[1]
			if len(memOp.Registers) == 0 || memOp.GetImmediate() != 0 {
				return core.HookResult{}
			}
			base := memOp.Registers[0]
			if base != disassemble.REG_X0 && base != disassemble.REG_W0 {
				return core.HookResult{}
			}
			storeOp := instr.Operands[0]
			if len(storeOp.Registers) == 0 {
				return core.HookResult{}
			}
			if idx, ok := registerToIndex(storeOp.Registers[0]); ok {
				vtableAddr = state.GetX(idx)
				return core.HookResult{Halt: true, SkipInstruction: true}
			}
		}

		return core.HookResult{}
	})

	emuCfg.Hooks = []emulate.HookRegistration{
		{Kind: core.HookPreInstruction, Handler: preHook},
	}

	engine := emulate.NewEngineWithConfig(emuCfg)
	if err := engine.SetMemory(fn.StartAddr, funcData); err != nil {
		return 0, fmt.Errorf("failed to load OSMetaClass constructor into emulator: %w", err)
	}

	if err := engine.Run(); err != nil {
		return 0, fmt.Errorf("failed to emulate constructor at %#x: %w", fn.StartAddr, err)
	}
	if vtableAddr == 0 {
		return 0, fmt.Errorf("failed to locate vtable store in constructor %#x", fn.StartAddr)
	}

	return vtableAddr, nil
}

func (c *Cpp) parseVtableMethods(m *macho.File, vptr uint64, className string) ([]Method, error) {
	log.Debugf("parseVtableMethods called for class %s with vptr=%#x", className, vptr)
	// Read vtable header
	data := make([]byte, 16)
	if _, err := m.ReadAtAddr(data, vptr); err != nil {
		return nil, fmt.Errorf("failed to read vtable header at %#x: %v", vptr, err)
	}
	dr := bytes.NewReader(data)
	var offsetToTop int64
	if err := binary.Read(dr, binary.LittleEndian, &offsetToTop); err != nil {
		return nil, fmt.Errorf("failed to parse vtable offset-to-top at %#x: %v", vptr, err)
	}
	var rtti uint64
	if err := binary.Read(dr, binary.LittleEndian, &rtti); err != nil {
		return nil, fmt.Errorf("failed to parse vtable RTTI at %#x: %v", vptr, err)
	}
	if offsetToTop != 0 || rtti != 0 {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Vtable header for class %s at %#x: offset-to-top=%d, RTTI=%#x", className, vptr, int64(offsetToTop), rtti))
	}
	vptr += 16 // Move past header

	// Debug: print what we're about to read
	log.Debugf("Starting to read methods from vtable at %#x for class %s", vptr, className)

	var methods []Method

	i := 0
	for {
		addr, err := m.GetPointerAtAddress(vptr)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read vtable entry at %#x: %v", vptr, err)
		}
		// Check for 0xffffffffffffffff end marker first (sentinel value)
		if addr == 0xffffffffffffffff {
			break // End of vtable
		}
		if addr == 0 {
			break // End of vtable
		}

		methodFile := m
		if m.FindSegmentForVMAddr(addr) == nil {
			if owner := c.fileForVMAddr(addr); owner != nil {
				methodFile = owner
			}
		}

		if _, err := methodFile.GetFunctionForVMAddr(addr); err != nil {
			log.Debugf("vtable entry at %#x (addr=%#x) could not be resolved to a function for class %s: %v (continuing)", vptr, addr, className, err)
		}

		// Extract PAC from the Mach-O that owns the vtable (m), not c.root
		// For kext classes, the vtable is in the kext's Mach-O, not the kernel
		pac := extractPACFromPointer(m, vptr)

		mi := Method{
			Address: addr,
			Index:   i * 8, // Index should be byte offset, not entry count
			PAC:     pac,
		}

		resolveMethodName(methodFile, &mi, className)

		methods = append(methods, mi)

		vptr += 8
		i++
	}

	log.Debugf("parseVtableMethods for class %s found %d methods", className, len(methods))
	return methods, nil
}

func (c *Cpp) populateVtablesFromAlloc(class *Class) error {
	if c.allocIndex < 0 {
		return fmt.Errorf("alloc index not set")
	}

	m := c.fileForClass(class)
	if m == nil {
		return fmt.Errorf("no Mach-O available for class %s", class.Name)
	}

	entryAddr := class.MetaVtableAddr + uint64(c.allocIndex*8)
	allocPtr, err := m.GetPointerAtAddress(entryAddr)
	if err != nil || allocPtr == 0 {
		return fmt.Errorf("failed to read alloc function pointer at %#x: %v", entryAddr, err)
	}
	allocPtr = m.SlidePointer(allocPtr)
	if allocPtr == c.cxaPureVirtual {
		return fmt.Errorf("detected pure virtual call at %#x for class %s", allocPtr, class.Name)
	}

	vt, err := c.emulateCtorForVtable(m, allocPtr)
	if err != nil || vt == 0 {
		return fmt.Errorf("failed to emulate constructor at %#x for class %s: %v", allocPtr, class.Name, err)
	}

	class.VtableAddr = vt
	// Method parsing moved to post-processing phase (populateVtablesPhase)

	return nil
}

// populateVtablesPhase is the unified post-processing phase that:
// 1. Populates missing vtable addresses using the alloc method (fallback for classes without symbols)
// 2. Parses vtable and metavtable methods if WithMethods is enabled
// Called after class discovery and deduplication, before ensuring OSObject.
func (c *Cpp) populateVtablesPhase(classes []Class) []Class {
	// Early return if alloc index wasn't determined
	if c.allocIndex < 0 {
		log.Debug("Skipping vtable population phase - alloc index not determined")
		return classes
	}

	log.Debugf("Starting vtable/method population phase (allocIndex=%d, withMethods=%v)", c.allocIndex, c.cfg.WithMethods)

	metavtabPopulated := 0
	metavtabFailed := 0
	vtabPopulated := 0
	vtabSkipped := 0
	vtabFailed := 0
	methodsParsed := 0
	methodsFailed := 0

	for i := range classes {
		m := c.fileForClass(&classes[i])
		if m == nil {
			log.Debugf("Skipping class %s - no Mach-O file available", classes[i].Name)
			vtabSkipped++
			continue
		}

		// Step 0: Populate missing MetaVtableAddr by reading from metaclass structure
		// The first 8 bytes of an OSMetaClass object point to its metavtable
		if classes[i].MetaVtableAddr == 0 && classes[i].MetaPtr != 0 {
			if metavtabPtr, err := m.GetPointerAtAddress(classes[i].MetaPtr); err == nil {
				// Slide the pointer if needed
				metavtabPtr = m.SlidePointer(metavtabPtr)
				if metavtabPtr >= 0xfffffff000000000 { // Valid kernel address
					classes[i].MetaVtableAddr = metavtabPtr
					metavtabPopulated++
					log.Debugf("Populated MetaVtableAddr for %s at %#x (read from MetaPtr %#x)",
						classes[i].Name, metavtabPtr, classes[i].MetaPtr)
				}
			} else {
				log.Debugf("Failed to read MetaVtableAddr from MetaPtr %#x for %s: %v",
					classes[i].MetaPtr, classes[i].Name, err)
				metavtabFailed++
			}
		}

		// Step 1: Populate missing vtables using alloc method (fallback)
		if classes[i].VtableAddr == 0 && classes[i].MetaVtableAddr != 0 {
			if err := c.populateVtablesFromAlloc(&classes[i]); err != nil {
				log.Debugf("Failed to populate vtable for %s: %v", classes[i].Name, err)
				vtabFailed++
			} else {
				vtabPopulated++
				log.Debugf("Populated vtable for %s at %#x", classes[i].Name, classes[i].VtableAddr)
			}
		}

		// Step 2: Parse methods if WithMethods is enabled
		if c.cfg.WithMethods {
			// Parse main vtable methods
			if classes[i].VtableAddr != 0 && len(classes[i].Methods) == 0 {
				methods, err := c.parseVtableMethods(m, classes[i].VtableAddr-16, classes[i].Name)
				if err != nil {
					log.Debugf("Failed to parse vtable methods for %s: %v", classes[i].Name, err)
					methodsFailed++
				} else {
					classes[i].Methods = methods
					methodsParsed++
					log.Debugf("Parsed %d methods for %s", len(methods), classes[i].Name)
				}
			}

			// TODO: Parse metavtable methods if needed
			// For now, we only parse main vtable methods as per original iometa behavior
		}
	}

	if metavtabPopulated > 0 || metavtabFailed > 0 {
		log.Infof("MetaVtable population: %d populated, %d failed", metavtabPopulated, metavtabFailed)
	}
	if vtabPopulated > 0 || vtabFailed > 0 {
		log.Infof("Vtable population: %d populated, %d skipped, %d failed", vtabPopulated, vtabSkipped, vtabFailed)
	}
	if c.cfg.WithMethods && (methodsParsed > 0 || methodsFailed > 0) {
		log.Infof("Method parsing: %d classes parsed, %d failed", methodsParsed, methodsFailed)
	}

	return classes
}
