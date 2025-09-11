package cpp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/fatih/color"
)

const errorLogMessage = "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error)."

var OSMetaClassFunc uint64 = 0 // Address of OSMetaClass::OSMetaClass function

var (
	colorClass    = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorBundle   = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorAddr     = color.New(color.Faint).SprintfFunc()
	colorMethod   = color.New(color.FgHiCyan).SprintFunc()
	colorOverride = color.New(color.FgYellow).SprintFunc()
	colorNew      = color.New(color.FgHiGreen).SprintFunc()
)

// ClassMeta represents metadata for a C++ class discovered in the kernelcache
type ClassMeta struct {
	Name        string       // Class name (e.g., "IOService")
	Size        uint32       // Size of class instances in bytes
	MetaPtr     uint64       // Address of the OSMetaClass object for this class
	SuperMeta   uint64       // Address of superclass's meta (0 if none)
	SuperClass  *ClassMeta   // Pointer to parent class (resolved later)
	AllocFunc   uint64       // Address of the alloc function
	VtableAddr  uint64       // Address of the class's vtable
	Methods     []MethodInfo // Virtual methods in the vtable
	DiscoveryPC uint64       // PC where this class was discovered
	Bundle      string       // Bundle/kext this class belongs to
}

// MethodInfo represents a virtual method in a class vtable
type MethodInfo struct {
	Address    uint64
	Name       string
	Index      int
	OverrideOf uint64
	PAC        uint16
}

// String returns a formatted string representation of the ClassMeta
func (c *ClassMeta) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("init=%s size=%s meta=%s vtab=%s", colorAddr("%#x", c.AllocFunc), colorAddr("%#03x", c.Size), colorAddr("%#x", c.MetaPtr), colorAddr("%#x", c.VtableAddr)))
	if c.SuperMeta != 0 {
		b.WriteString(fmt.Sprintf(" parent=%s", colorAddr("%#x", c.SuperMeta)))
	}
	b.WriteString(fmt.Sprintf(" %s", colorClass(c.Name)))
	if c.Bundle != "" {
		b.WriteString(fmt.Sprintf(" (%s)", colorBundle(c.Bundle)))
	}
	return b.String()
}

// String returns a formatted string representation of the MethodInfo
func (m *MethodInfo) String() string {
	offset := fmt.Sprintf("%#x", m.Index*8)
	funcAddr := colorAddr("%#x", m.Address)
	var extra strings.Builder
	if m.OverrideOf != 0 {
		extra.WriteString(fmt.Sprintf(" overrides=%s", colorAddr("%#x", m.OverrideOf)))
	} else {
		extra.WriteString(" overrides=0x0000000000000000")
	}
	if m.PAC != 0 {
		extra.WriteString(fmt.Sprintf(" pac=0x%04x", m.PAC))
	}
	methodName := demangle.Do(m.Name, false, true)
	if m.OverrideOf != 0 {
		methodName = colorOverride(methodName)
	} else {
		methodName = colorNew(methodName)
	}
	return fmt.Sprintf("    %6s func=%s%s %s", offset, funcAddr, extra.String(), methodName)
}

func findOsMetaClassFunc(m *macho.File) (uint64, error) {
	var osMetaClassFunc uint64

	strs, err := m.GetCStrings()
	if err != nil {
		return 0, fmt.Errorf("failed to get cstrings: %v", err)
	}

	var targetStrAddr uint64
	for _, str2addr := range strs {
		for str, addr := range str2addr {
			if str == errorLogMessage {
				targetStrAddr = addr
				break
			}
		}
		if targetStrAddr != 0 {
			break
		}
	}
	if targetStrAddr == 0 {
		return 0, fmt.Errorf("failed to find target string in cstrings")
	}

	for _, fn := range m.GetFunctions() {
		data, err := m.GetFunctionData(fn)
		if err != nil {
			return 0, fmt.Errorf("failed to get function data at %#x: %v", fn.StartAddr, err)
		}
		engine := disass.NewMachoDisass(m, &disass.Config{
			Data:         data,
			StartAddress: fn.StartAddr,
			Quiet:        true,
		})

		if err := engine.Triage(); err != nil {
			return 0, fmt.Errorf("first pass triage failed: %v", err)
		}

		if ok, loc := engine.Contains(targetStrAddr); ok {
			fn, err := m.GetFunctionForVMAddr(loc)
			if err != nil {
				return 0, fmt.Errorf("failed to get function at %#x: %v", loc, err)
			}
			osMetaClassFunc = fn.StartAddr
			log.Debugf("Found OSMetaClass::OSMetaClass at %#x (referenced by log message at %#x)", osMetaClassFunc, loc)
			break
		}
	}

	return osMetaClassFunc, nil
}

// parseClassMeta emulates the constructor function to extract class metadata
func parseClassMeta(m *macho.File, startAddr uint64, data []byte) ([]ClassMeta, error) {
	var classes []ClassMeta

	// Get function information to know where to stop
	fn, err := m.GetFunctionForVMAddr(startAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get function info for %#x: %v", startAddr, err)
	}
	endAddr := fn.EndAddr

	// Track whether we've followed a stub 'b' into the real MetaClass constructor
	followedStub := false

	// Create a bounds guard for the function range and hook into Pre/Post.
	guard, err := emulate.NewBoundsGuard(startAddr, endAddr, emulate.WithStrictRange(false))
	if err != nil {
		return nil, fmt.Errorf("failed to create bounds guard: %v", err)
	}

	cfg := emulate.DefaultEngineConfig()
	// Allow enough headroom to capture many back-to-back class inits
	// without prematurely hitting the instruction budget.
	cfg.MaxInstructions = 50000
	// Skip over unsupported instructions like PAC* and RETAA/RETAB
	// so we can continue scanning within the function body.
	cfg.StopOnError = false
	cfg.MemoryHandler = func(addr uint64, size int) ([]byte, error) {
		data := make([]byte, size)
		_, err := m.ReadAtAddr(data, addr)
		if err != nil {
			// For stack addresses and other unmapped regions, return zeros to continue emulation
			// This allows us to find multiple OSMetaClass calls even when stack operations fail
			if addr >= 0x7ffe00000000 || addr < 0x100000 || (addr >= 0x100000000 && addr < 0x1000000000) {
				return data, nil // Return zero-filled buffer
			}
			return nil, fmt.Errorf("memory read error at %#x: %v", addr, err)
		}
		return data, nil
	}
	cfg.StringHandler = func(addr uint64) (string, error) {
		str, err := m.GetCString(addr)
		if err != nil {
			return "", fmt.Errorf("string read error at %#x: %v", addr, err)
		}
		return str, nil
	}
	cfg.ShouldHaltPreHandler = func(state core.State, info core.InstructionInfo) bool {
		// First, allow the guard to stop on range/return conditions.
		if guard.Pre(state, info) {
			return true
		}
		// Detect direct call to OSMetaClass (BL imm / BLR Xn)
		switch info.Instruction.Operation {
		case disassemble.ARM64_BL:
			if len(info.Instruction.Operands) > 0 &&
				OSMetaClassFunc == info.Instruction.Operands[0].Immediate {
				log.Debugf("Found OSMetaClass call at PC %#x, halting to process", state.GetPC())
				return true
			}
		case disassemble.ARM64_BLR, disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ, disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ:
			if len(info.Instruction.Operands) > 0 && len(info.Instruction.Operands[0].Registers) > 0 {
				rn := core.MapRegister(info.Instruction.Operands[0].Registers[0])
				if state.GetX(rn) == OSMetaClassFunc {
					log.Debugf("Found OSMetaClass call via BLR at PC %#x, halting to process", state.GetPC())
					return true
				}
			}
		}
		// Otherwise, keep running
		return false
	}
	cfg.ShouldHaltPostHandler = func(state core.State, info core.InstructionInfo) bool {
		return guard.Post(state, info)
	}
	cfg.ShouldTakeBranchHandler = func(state core.State, info core.InstructionInfo) bool {
		switch info.Instruction.Operation {
		case disassemble.ARM64_BL:
			if len(info.Instruction.Operands) > 0 && info.Instruction.Operands[0].Immediate == OSMetaClassFunc {
				// We'll halt pre and process; do not take the call
				return false
			}
			// Don't follow other calls
			return false
		case disassemble.ARM64_BLR, disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ, disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ:
			// Never follow register-indirect calls
			return false
		case disassemble.ARM64_B, disassemble.ARM64_B_AL:
			// Handle unconditional branches 'b' to support stub patterns but avoid
			// escaping into unrelated functions after we've started collecting classes.
			// We only allow an external hop once before discovering any classes.
			// Compute target
			var target uint64
			if len(info.Instruction.Operands) > 0 && info.Instruction.Operands[0].Immediate != 0 {
				target = info.Instruction.Operands[0].Immediate
			} else {
				// Fallback: decode current instruction value to compute target
				var inst uint32
				if _, err := m.ReadAtAddr((*[4]byte)(unsafe.Pointer(&inst))[:], state.GetPC()); err == nil {
					if (inst & 0xFC000000) == 0x14000000 {
						off := int32(inst&0x03FFFFFF) << 2
						if (off & 0x08000000) != 0 { // sign-extend
							off |= ^0x0FFFFFFF
						}
						target = state.GetPC() + uint64(off)
					}
				}
			}
			if target == 0 {
				return false
			}
			// Allow if the target stays within the current function body,
			if curFn, err1 := m.GetFunctionForVMAddr(state.GetPC()); err1 == nil {
				if tgtFn, err2 := m.GetFunctionForVMAddr(target); err2 == nil {
					if tgtFn.StartAddr == curFn.StartAddr {
						return true
					}
				}
			}
			// or allow exactly one external 'b' (stub hop) before first class discovery.
			if !followedStub && len(classes) == 0 {
				followedStub = true
				return true
			}
			return false
		default:
			return true
		}
	}

	emu := emulate.NewEngineWithConfig(cfg)
	if err := emu.SetMemory(startAddr, data); err != nil {
		return nil, fmt.Errorf("failed to set emulation memory: %v", err)
	}
	emu.SetPC(startAddr)

	// Loop: emulate until we hit an OSMetaClass call or reach safe stop conditions
	for {
		err := emu.Run()
		state := emu.GetState()
		pc := state.GetPC()

		// If emulation failed, check if we found any classes
		if err != nil {
			if !errors.Is(err, core.ErrUnmappedMemory) && len(classes) == 0 {
				return nil, fmt.Errorf("emulation error: %v", err)
			}
			log.Debugf("Emulation ended with error: %v (found %d classes)", err, len(classes))
			break
		}

		// Read the instruction at current PC to check if it's an OSMetaClass call
		var inst uint32
		if _, err := m.ReadAtAddr((*[4]byte)(unsafe.Pointer(&inst))[:], pc); err != nil {
			log.Debugf("Failed to read instruction at %#x: %v", pc, err)
			break
		}

		// Check if this is a call to OSMetaClass (BL or BLR)
		isOSMetaClassCall := false
		if (inst & 0xFC000000) == 0x94000000 { // BL immediate
			offset := int32(inst&0x03FFFFFF) << 2
			if (offset & 0x08000000) != 0 { // sign-extend
				offset |= ^0x0FFFFFFF
			}
			target := pc + uint64(offset)
			if target == OSMetaClassFunc {
				isOSMetaClassCall = true
			}
		} else if (inst & 0xFFFFFC1F) == 0xD63F0000 { // BLR Xn
			rn := (inst >> 5) & 0x1F
			target := state.GetX(int(rn))
			if target == OSMetaClassFunc {
				isOSMetaClassCall = true
			}
		}

		// Guard handles returns and tail-calls; no custom early stop here.

		if isOSMetaClassCall {
			// Process the OSMetaClass call
			if name, err := state.ReadString(state.GetX(1)); err == nil {
				c := ClassMeta{
					AllocFunc: startAddr,
					Name:      name,
					MetaPtr:   state.GetX(0),
					SuperMeta: m.SlidePointer(state.GetX(2)),
					Size:      uint32(state.GetX(3)),
				}

				// Extract vtable information right after the call
				vtableAddr := extractVtablePtr(m, emu)
				c.VtableAddr = vtableAddr
				if vtableAddr != 0 {
					c.Methods = parseVtableMethods(m, vtableAddr, name)
				}

				classes = append(classes, c)
				log.Debugf("Processed class %s at PC %#x (vtab: %#x, methods: %d), continuing...",
					name, pc, vtableAddr, len(c.Methods))
			}

			// Continue emulation from after the bl instruction (extractVtablePtr now handles PC state)
			emu.SetPC(pc + 4)
			continue
		}

		// If we reached or passed the initial function's end without hitting a call here,
		// and we already collected classes (e.g., last call processed), stop.
		if (pc >= endAddr || pc < startAddr) && len(classes) > 0 {
			log.Debugf("Outside initial function range; already found %d classes, stopping", len(classes))
			break
		}

		// If we got here without hitting an OSMetaClass call, step one instruction and continue
		// This allows proper register setup for subsequent OSMetaClass calls
		log.Debugf("Unexpected halt at PC %#x without OSMetaClass call, stepping...", pc)
		if err := emu.StepOver(); err != nil {
			log.Debugf("Failed to step at PC %#x: %v", pc, err)
			break
		}
		continue
	}

	if len(classes) == 0 {
		return nil, fmt.Errorf("failed to parse class metadata: no valid classes found")
	}

	return classes, nil
}

func parseClasses(m *macho.File, entry *string) ([]ClassMeta, error) {
	var classes []ClassMeta
	if modInitSection := m.Section("__DATA_CONST", "__mod_init_func"); modInitSection != nil {
		ptrs := make([]uint64, modInitSection.Size/8)
		data, err := modInitSection.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read __mod_init_func section: %v", err)
		}
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, ptrs); err != nil {
			return nil, fmt.Errorf("failed to parse __mod_init_func pointers: %v", err)
		}
		for _, addr := range ptrs {
			if addr == 0 {
				continue
			}
			fn, err := m.GetFunctionForVMAddr(m.SlidePointer(addr))
			if err != nil {
				fmt.Printf("Warning: failed to get function at %#x: %v\n", addr, err)
				continue
			}
			funcData, err := m.GetFunctionData(fn)
			if err != nil {
				return nil, fmt.Errorf("failed to get function data at %#x: %v", fn.StartAddr, err)
			}
			initClasses, err := parseClassMeta(m, fn.StartAddr, funcData)
			if err != nil {
				// return nil, fmt.Errorf("failed to parse class metadata for init func at %#x: %v", fn.StartAddr, err)
				if entry != nil {
					log.WithField("entry", *entry).Debugf("failed to parse class metadata for init func at %#x: %v", fn.StartAddr, err)
				} else {
					log.Debugf("failed to parse class metadata for init func at %#x: %v", fn.StartAddr, err)
				}
				continue
			}
			if len(initClasses) > 1 {
				if entry != nil {
					log.WithField("entry", *entry).Infof("Found %d classes in single init function at %#x", len(initClasses), fn.StartAddr)
				} else {
					log.Infof("Found %d classes in single init function at %#x", len(initClasses), fn.StartAddr)
				}
			}
			for _, class := range initClasses {
				if entry != nil {
					class.Bundle = *entry
					log.WithField("entry", *entry).Debugf("Discovered class: %s (init: %#x) in %s", class.Name, class.AllocFunc, *entry)
				} else {
					class.Bundle = "kernel"
					log.WithFields(log.Fields{
						"init": fmt.Sprintf("%#x", class.AllocFunc),
					}).Debug(class.Name)
				}
				classes = append(classes, class)
			}
		}
	} else {
		log.WithField("entry", entry).Warnf("No __mod_init_func section found")
	}
	return classes, nil
}

// GetClasses analyzes the given Mach-O kernel file and extracts C++ class metadata
func GetClasses(kernel *macho.File) (classes []ClassMeta, err error) {
	if kernel.Type == types.MH_FILESET {
		k, err := kernel.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to get kernel fileset entry: %v", err)
		}
		OSMetaClassFunc, err = findOsMetaClassFunc(k)
		if err != nil {
			return nil, fmt.Errorf("failed to find OSMetaClass function: %v", err)
		}
		for _, fs := range kernel.FileSets() {
			entry, err := kernel.GetFileSetFileByName(fs.EntryID)
			if err != nil {
				return nil, fmt.Errorf("failed to get fileset entry %s: %v", fs.EntryID, err)
			}
			defer entry.Close()
			cls, err := parseClasses(entry, &fs.EntryID)
			if err != nil {
				return nil, fmt.Errorf("failed to parse classes from entry %s: %v", fs.EntryID, err)
			}
			classes = append(classes, cls...)
		}
	} else {
		OSMetaClassFunc, err = findOsMetaClassFunc(kernel)
		if err != nil {
			return nil, fmt.Errorf("failed to find OSMetaClass function: %v", err)
		}
		cls, err := parseClasses(kernel, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse classes from kernel: %v", err)
		}
		classes = append(classes, cls...)
	}

	classes = dedupeClasses(classes)
	linkParentsAndComputeOverrides(classes)
	return classes, nil
}

func isValidVtableAddr(m *macho.File, addr uint64) bool {
	if addr == 0 {
		return false
	}
	a := m.SlidePointer(addr)
	if seg := m.FindSegmentForVMAddr(a); seg != nil {
		return strings.HasPrefix(seg.Name, "__DATA") && types.VmProtection(seg.Prot).Read()
	}
	return false
}

func isValidFuncAddr(m *macho.File, addr uint64) bool {
	if addr == 0 {
		return false
	}
	a := m.SlidePointer(addr)
	if seg := m.FindSegmentForVMAddr(a); seg != nil {
		if !types.VmProtection(seg.Prot).Execute() {
			return false
		}
		return isKnownFunction(m, a)
	}
	return false
}

func isKnownFunction(m *macho.File, addr uint64) bool {
	if _, err := m.GetFunctionForVMAddr(addr); err == nil {
		return true
	}
	if m.Symtab != nil {
		for _, s := range m.Symtab.Syms {
			if s.Value == addr && s.Type&types.N_TYPE == types.N_SECT {
				return true
			}
		}
	}
	return true
}

func dedupeClasses(in []ClassMeta) []ClassMeta {
	seen := make(map[uint64]bool, len(in))
	out := make([]ClassMeta, 0, len(in))
	for _, c := range in {
		if c.MetaPtr == 0 {
			// keep pessimistically
			out = append(out, c)
			continue
		}
		if seen[c.MetaPtr] {
			continue
		}
		seen[c.MetaPtr] = true
		out = append(out, c)
	}
	return out
}

func extractVtablePtr(m *macho.File, emu *emulate.Engine) uint64 {
	// Save current state to avoid modifying emulation state
	savedPC := emu.GetPC()

	if emu.GetRegister(1) != 0 {
		if name, err := emu.GetState().ReadString(emu.GetRegister(1)); err == nil {
			if vtab := findVtableSymbol(m, name); vtab != 0 {
				return vtab + 16
			}
		}
	}

	// Create separate emulation context for vtable discovery
	tempPC := savedPC + 4
	emu.SetPC(tempPC)

	for range 4 {
		if err := emu.StepOver(); err != nil {
			break
		}
		x16 := emu.GetRegister(16)
		if isValidVtableAddr(m, x16) {
			// Restore original state before returning
			emu.SetPC(savedPC)
			return x16
		}
	}

	// Restore original state
	emu.SetPC(savedPC)
	return 0
}

func findVtableSymbol(m *macho.File, className string) uint64 {
	if m.Symtab == nil {
		return 0
	}
	vtableSymbol := fmt.Sprintf("__ZTV%d%s", len(className), className)
	for _, s := range m.Symtab.Syms {
		if s.Name == vtableSymbol {
			return s.Value
		}
	}
	return 0
}

func parseVtableMethods(m *macho.File, vptr uint64, className string) []MethodInfo {
	methods := make([]MethodInfo, 0, 64)
	ptr := findVtableStart(m, vptr)
	if ptr == 0 {
		return methods
	}

	for i := 0; i < 2048; i++ {
		val, err := m.GetPointerAtAddress(ptr)
		if err != nil || val == 0 {
			break
		}

		// Extract PAC before sliding pointer (like iometa does)
		pac := extractPACFromPointer(m, val)
		addr := m.SlidePointer(val)

		if !isValidFuncAddr(m, addr) {
			break
		}

		mi := MethodInfo{
			Address: addr,
			Index:   i,
			PAC:     pac,
		}
		resolveMethodName(m, &mi, className)
		methods = append(methods, mi)
		ptr += 8
	}
	return methods
}

func findVtableStart(m *macho.File, vptr uint64) uint64 {
	ptr := vptr
	for i := 0; i < 64; i++ {
		val, err := m.GetPointerAtAddress(ptr)
		if err != nil {
			return 0
		}
		if val != 0 && isValidFuncAddr(m, val) {
			return ptr
		}
		ptr += 8
	}
	return 0
}

// extractPACFromPointer extracts PAC diversity from chained fixups
func extractPACFromPointer(m *macho.File, addr uint64) uint16 {
	if !m.HasFixups() {
		return 0
	}
	dcf, err := m.DyldChainedFixups()
	if err != nil {
		return 0
	}
	offset, err := m.GetOffset(addr)
	if err != nil {
		return 0
	}
	if fixup, ok := dcf.Lookup(offset); ok {
		if auth, ok := fixup.(fixupchains.Auth); ok {
			return uint16(auth.Diversity())
		}
	}
	return 0
}

func resolveMethodName(m *macho.File, mi *MethodInfo, className string) {
	if m.Symtab != nil {
		for _, s := range m.Symtab.Syms {
			if s.Value == mi.Address {
				mi.Name = s.Name
				if mi.PAC == 0 {
					if pac, ok := computePAC(mi.Name); ok {
						mi.PAC = pac
					}
				}
				return
			}
		}
	}
	mi.Name = fmt.Sprintf("%s::fn_0x%x()", className, mi.Index*8)
}

func computePAC(sym string) (uint16, bool) {
	if len(sym) == 0 || sym[0] != '_' { // expect underscore
		return 0, false
	}
	s := sym[1:]
	n := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			n = i
			break
		}
	}
	if n == 0 {
		return 0, false
	}
	h := siphash([]byte(s[:n]))
	return uint16(h%0xffff) + 1, true
}

func linkParentsAndComputeOverrides(classes []ClassMeta) {
	byMeta := make(map[uint64]*ClassMeta, len(classes))
	for i := range classes {
		byMeta[classes[i].MetaPtr] = &classes[i]
	}
	for i := range classes {
		if p := byMeta[classes[i].SuperMeta]; p != nil {
			classes[i].SuperClass = p
			computeOverrides(&classes[i], p)
		}
	}
}

func computeOverrides(child *ClassMeta, parent *ClassMeta) {
	if len(child.Methods) == 0 || len(parent.Methods) == 0 {
		return
	}
	for i := range child.Methods {
		if i < len(parent.Methods) {
			child.Methods[i].OverrideOf = parent.Methods[i].Address
		}
	}
}

func siphash(in []byte) uint64 {
	v0 := uint64(0x0a257d1c9bbab1c0)
	v1 := uint64(0xb0eef52375ef8302)
	v2 := uint64(0x1533771c85aca6d4)
	v3 := uint64(0xa0e4e32062ff891c)
	for i := 0; i+8 <= len(in); i += 8 {
		m := uint64(in[i+7])<<56 | uint64(in[i+6])<<48 | uint64(in[i+5])<<40 |
			uint64(in[i+4])<<32 | uint64(in[i+3])<<24 | uint64(in[i+2])<<16 |
			uint64(in[i+1])<<8 | uint64(in[i+0])
		v3 ^= m
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0 ^= m
	}
	b := uint64(len(in)) << 56
	switch len(in) & 7 {
	case 7:
		b |= uint64(in[len(in)-7]) << 48
		fallthrough
	case 6:
		b |= uint64(in[len(in)-6]) << 40
		fallthrough
	case 5:
		b |= uint64(in[len(in)-5]) << 32
		fallthrough
	case 4:
		b |= uint64(in[len(in)-4]) << 24
		fallthrough
	case 3:
		b |= uint64(in[len(in)-3]) << 16
		fallthrough
	case 2:
		b |= uint64(in[len(in)-2]) << 8
		fallthrough
	case 1:
		b |= uint64(in[len(in)-1])
	}
	v3 ^= b
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0 ^= b
	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func rotl(x uint64, b uint) uint64 { return (x << b) | (x >> (64 - b)) }
func sipround(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = rotl(v1, 13) ^ v0
	v0 = rotl(v0, 32)
	v2 += v3
	v3 = rotl(v3, 16) ^ v2
	v0 += v3
	v3 = rotl(v3, 21) ^ v0
	v2 += v1
	v1 = rotl(v1, 17) ^ v2
	v2 = rotl(v2, 32)
	return v0, v1, v2, v3
}
