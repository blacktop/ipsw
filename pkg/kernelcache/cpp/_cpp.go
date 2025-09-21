package cpp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/disass"
	"golang.org/x/sync/errgroup"
)

const errorLogMessage = "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error)."

var (
	errOSMetaStringNotFound = errors.New("osmetaclass error log string not found")
	errOSMetaViaString      = errors.New("osmetaclass function not located via string")
)

// Config controls how class discovery runs.
// Disable expensive phases to keep discovery fast on large kernels.
type Config struct {
	// ResolveVtables finds vtable pointers (emulation + scanning around calls).
	ResolveVtables bool
	// WithMethods parses each class's vtable entries into detailed methods.
	// Implies ResolveVtables.
	WithMethods bool
	// WithOverrides links parents and computes method overrides.
	WithOverrides bool
	// WithAlloc resolves per-class alloc function from MetaClass vtable.
	WithAlloc bool
	// Entries restricts which fileset entries to analyze. If empty, analyze all.
	Entries []string
}

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
	DiscoveryPC uint64       // Program counter where class was discovered
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

// XrefInfo represents a cross-reference to OSMetaClass::OSMetaClass
type XrefInfo struct {
	PC        uint64 // Address of the BL instruction
	FuncStart uint64 // Start of containing function
	FuncEnd   uint64 // End of containing function
}

// InitFuncInfo holds information about a __mod_init_func entry
type InitFuncInfo struct {
	RawPtr    uint64     // Raw pointer value from __mod_init_func
	FuncAddr  uint64     // Decoded function address
	FuncStart uint64     // Function start address
	FuncEnd   uint64     // Function end address
	EntryID   string     // Fileset entry ID
	Xrefs     []XrefInfo // OSMetaClass xrefs in this init function
}

// Cache structures for performance
type stringCache struct {
	mu    sync.RWMutex
	cache map[uint64]string
}

func (c *stringCache) get(addr uint64) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.cache[addr]
	return s, ok
}

func (c *stringCache) put(addr uint64, s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[uint64]string)
	}
	c.cache[addr] = s
}

type funcDataCache struct {
	mu    sync.RWMutex
	cache map[uint64][]byte
}

func (c *funcDataCache) get(addr uint64) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, ok := c.cache[addr]
	return data, ok
}

func (c *funcDataCache) put(addr uint64, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[uint64][]byte)
	}
	c.cache[addr] = data
}

var (
	strCache = &stringCache{}
	fdCache  = &funcDataCache{}
)

type kernelImage struct {
	file  *macho.File
	label string
}

func gatherSearchImages(root *macho.File) []kernelImage {
	if root == nil {
		return nil
	}
	if root.Type != types.MH_FILESET {
		return []kernelImage{{file: root, label: "kernel"}}
	}

	images := make([]kernelImage, 0, len(root.FileSets()))
	if mainKernel, err := root.GetFileSetFileByName("com.apple.kernel"); err == nil {
		images = append(images, kernelImage{file: mainKernel, label: "com.apple.kernel"})
	}

	for _, fs := range root.FileSets() {
		if fs.EntryID == "com.apple.kernel" {
			continue
		}
		entry, err := root.GetFileSetFileByName(fs.EntryID)
		if err != nil {
			log.Debugf("Failed to open fileset entry %s: %v", fs.EntryID, err)
			continue
		}
		images = append(images, kernelImage{file: entry, label: fs.EntryID})
	}

	return images
}

func findOsMetaClassByErrorString(m *macho.File) (uint64, error) {
	strs, err := m.GetCStrings()
	if err != nil {
		return 0, fmt.Errorf("get cstrings: %w", err)
	}

	var targetStrAddr uint64
	for _, str2addr := range strs {
		if addr, ok := str2addr[errorLogMessage]; ok {
			targetStrAddr = addr
			break
		}
	}
	if targetStrAddr == 0 {
		return 0, errOSMetaStringNotFound
	}

	for _, fn := range m.GetFunctions() {
		data, err := m.GetFunctionData(fn)
		if err != nil {
			log.Debugf("Failed to get function data at %#x: %v", fn.StartAddr, err)
			continue
		}

		engine := disass.NewMachoDisass(m, &disass.Config{
			Data:         data,
			StartAddress: fn.StartAddr,
			Quiet:        true,
		})

		if err := engine.Triage(); err != nil {
			log.Debugf("Triage failed for function %#x: %v", fn.StartAddr, err)
			continue
		}

		if ok, loc := engine.Contains(targetStrAddr); ok {
			if fn.StartAddr <= loc && loc < fn.EndAddr {
				log.Debugf("Found OSMetaClass::OSMetaClass via error string at %#x", fn.StartAddr)
				return fn.StartAddr, nil
			}
			if targetFn, err := m.GetFunctionForVMAddr(loc); err == nil {
				log.Debugf("Found OSMetaClass::OSMetaClass via error string at %#x", targetFn.StartAddr)
				return targetFn.StartAddr, nil
			}
			return fn.StartAddr, nil
		}
	}

	return 0, errOSMetaViaString
}

func findOsMetaClassBySymbol(m *macho.File) uint64 {
	if m == nil {
		return 0
	}

	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			if isOsMetaClassCtor(sym.Name) {
				return sym.Value
			}
		}
	}

	if exports, err := m.DyldExports(); err == nil {
		for _, entry := range exports {
			if isOsMetaClassCtor(entry.Name) {
				return entry.Address
			}
		}
	}

	return 0
}

func isOsMetaClassCtor(name string) bool {
	if name == "" {
		return false
	}
	trimmed := strings.TrimPrefix(name, "_")
	if strings.Contains(trimmed, "OSMetaClass::OSMetaClass") {
		return true
	}
	if strings.Contains(trimmed, "OSMetaClassC1") || strings.Contains(trimmed, "OSMetaClassC2") {
		return true
	}
	return false
}

// findOsMetaClassFunc finds the OSMetaClass::OSMetaClass function
func findOsMetaClassFunc(root *macho.File) (uint64, error) {
	images := gatherSearchImages(root)
	if len(images) == 0 {
		return 0, errors.New("no kernel images available to search")
	}

	for _, img := range images {
		addr, err := findOsMetaClassByErrorString(img.file)
		if err == nil && addr != 0 {
			return addr, nil
		}
		if err != nil && !errors.Is(err, errOSMetaStringNotFound) && !errors.Is(err, errOSMetaViaString) {
			log.Debugf("OSMetaClass string search failed in %s: %v", img.label, err)
		}
	}

	for _, img := range images {
		if addr := findOsMetaClassBySymbol(img.file); addr != 0 {
			log.Debugf("Found OSMetaClass::OSMetaClass via symbols at %#x in %s", addr, img.label)
			return addr, nil
		}
	}

	return 0, fmt.Errorf("failed to locate OSMetaClass::OSMetaClass in kernelcache")
}

// findXrefsInInitFunc scans an init function for all OSMetaClass calls (direct, indirect, veneers)
func findXrefsInInitFunc(m *macho.File, initFunc InitFuncInfo, osMetaFunc uint64) (xrefs []XrefInfo, err error) {
	// Get function data from cache or read it
	funcData, cached := fdCache.get(initFunc.FuncStart)
	if !cached {
		fn := types.Function{
			StartAddr: initFunc.FuncStart,
			EndAddr:   initFunc.FuncEnd,
		}
		funcData, err = m.GetFunctionData(fn)
		if err != nil {
			return nil, fmt.Errorf("failed to get function data: %v", err)
		}
		fdCache.put(initFunc.FuncStart, funcData)
	}

	// Scan for direct BL
	for offset := 0; offset+4 <= len(funcData); offset += 4 {
		inst := binary.LittleEndian.Uint32(funcData[offset:])
		pc := initFunc.FuncStart + uint64(offset)
		// Only support BL instruction (direct call)
		if (inst & 0xFC000000) == 0x94000000 {
			imm26 := inst & 0x03FFFFFF
			var immOffset int32
			if (imm26 & 0x02000000) != 0 {
				immOffset = int32(imm26 | 0xFC000000)
			} else {
				immOffset = int32(imm26)
			}
			// BL target = PC (current instruction) + (imm26 << 2)
			target := uint64(int64(pc) + int64(immOffset)*4)
			// Check if it's a direct call to OSMetaClass
			if target == osMetaFunc {
				xrefs = append(xrefs, XrefInfo{
					PC:        pc,
					FuncStart: initFunc.FuncStart,
					FuncEnd:   initFunc.FuncEnd,
				})
			}
		}
	}

	return xrefs, nil
}

// extractClassesFromInitFuncEmulated uses emulation to extract accurate class metadata
func extractClassesFromInitFuncEmulated(m *macho.File, initFunc InitFuncInfo, osMetaClassFunc uint64, cfg *Config) ([]ClassMeta, error) {
	var classes []ClassMeta

	xrefs, err := findXrefsInInitFunc(m, initFunc, osMetaClassFunc)
	if err != nil {
		log.Debugf("Failed to find xrefs in init func %#x: %v", initFunc.FuncStart, err)
		return classes, nil
	}
	if len(xrefs) == 0 {
		return classes, nil
	}

	log.Debugf("Found %d OSMetaClass xrefs in init function %#x", len(xrefs), initFunc.FuncStart)

	funcData, cached := fdCache.get(initFunc.FuncStart)
	if !cached {
		fn := types.Function{
			StartAddr: initFunc.FuncStart,
			EndAddr:   initFunc.FuncEnd,
		}
		funcData, err = m.GetFunctionData(fn)
		if err != nil {
			return nil, fmt.Errorf("failed to get function data: %v", err)
		}
		fdCache.put(initFunc.FuncStart, funcData)
	}

	for _, xref := range xrefs {
		class, err := emulateClassFromXref(m, initFunc, xref, funcData, cfg)
		if err != nil {
			log.Debugf("Emulation failed for xref %#x in init %#x: %v", xref.PC, initFunc.FuncStart, err)
			continue
		}
		classes = append(classes, *class)
	}

	return classes, nil
}

func emulateClassFromXref(m *macho.File, initFunc InitFuncInfo, xref XrefInfo, funcData []byte, cfg *Config) (*ClassMeta, error) {
	// Use limited emulation starting just before the BL
	blOffset := int(xref.PC - initFunc.FuncStart)
	if blOffset < 0 || blOffset+4 > len(funcData) {
		return nil, fmt.Errorf("BL offset %d out of bounds", blOffset)
	}

	// Start emulation from 64 instructions before the BL (256 bytes)
	startOffset := blOffset - 256
	if startOffset < 0 {
		startOffset = 0
	}
	startPC := initFunc.FuncStart + uint64(startOffset)

	// Extract the relevant portion of function data
	endOffset := blOffset + 64 // Include some instructions after BL for vtable
	if endOffset > len(funcData) {
		endOffset = len(funcData)
	}
	emuData := funcData[startOffset:endOffset]

	emuCfg := emulate.DefaultEngineConfig()
	emuCfg.InitialPC = startPC
	emuCfg.MaxInstructions = 512 // Limit emulation steps
	emuCfg.MemoryHandler = func(addr uint64, size int) ([]byte, error) {
		buf := make([]byte, size)
		if _, err := m.ReadAtAddr(buf, addr); err != nil {
			return make([]byte, size), nil
		}
		return buf, nil
	}
	emuCfg.StringHandler = func(addr uint64) (string, error) {
		return m.GetCString(addr)
	}

	engine := emulate.NewEngineWithConfig(emuCfg)
	if err := engine.SetMemory(startPC, emuData); err != nil {
		return nil, fmt.Errorf("failed to map function segment: %w", err)
	}

	// Emulate until we reach the BL
	for steps := 0; steps < emuCfg.MaxInstructions; steps++ {
		pc := engine.GetPC()
		if pc == xref.PC {
			// We're at the BL - capture register state
			metaPtr := engine.GetRegister(0)
			namePtr := engine.GetRegister(1)
			superPtr := engine.GetRegister(2)
			size := uint32(engine.GetRegister(3))

			className := ""
			if cached, ok := strCache.get(namePtr); ok {
				className = cached
			} else if s, err := m.GetCString(namePtr); err == nil {
				className = s
				strCache.put(namePtr, s)
			}
			if className == "" {
				className = fmt.Sprintf("class_%#x", xref.PC)
			}

			class := &ClassMeta{
				Name:        className,
				MetaPtr:     metaPtr,
				SuperMeta:   superPtr,
				Size:        size,
				AllocFunc:   initFunc.FuncAddr,
				DiscoveryPC: xref.PC,
				Bundle:      initFunc.EntryID,
			}

			// Step past the BL and look for vtable in X16
			if cfg != nil && (cfg.ResolveVtables || cfg.WithMethods) {
				// Skip the BL instruction first
				if err := stepOver(engine); err == nil {
					for i := 0; i < 16; i++ {
						if err := stepOver(engine); err != nil {
							break
						}
						if val := engine.GetRegister(16); val != 0 {
							// Don't apply slide to vtable address - it's already correct
							class.VtableAddr = val
							if cfg.WithMethods {
								class.Methods = parseVtableMethods(m, class.VtableAddr, className)
							}
							break
						}
					}
				}
			}

			return class, nil
		}

		// Continue emulation
		if err := stepOver(engine); err != nil {
			// Skip problematic instructions
			if shouldSkipInstruction(err) {
				engine.SetPC(pc + 4)
				continue
			}
			return nil, fmt.Errorf("emulation error at %#x: %w", pc, err)
		}
	}

	return nil, fmt.Errorf("failed to reach BL at %#x after %d steps", xref.PC, emuCfg.MaxInstructions)
}

func stepOver(engine *emulate.Engine) error {
	pc := engine.GetPC()
	if err := engine.StepOver(); err != nil {
		if shouldSkipInstruction(err) {
			engine.SetPC(pc + 4)
			return nil
		}
		return err
	}
	return nil
}

func shouldSkipInstruction(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "UNSUPPORTED") ||
		strings.Contains(msg, "INVALID") ||
		strings.Contains(msg, "PAC") ||
		strings.Contains(msg, "AUT") ||
		strings.Contains(msg, "XPAC") ||
		strings.Contains(msg, "LDADD") ||
		strings.Contains(msg, "MOVI")
}

// getInitFunctions extracts all __mod_init_func entries with enhanced metadata
// m is the file to read __mod_init_func section from (can be entry or main kernel)
// kernel is the main kernel file used for resolving addresses
func getInitFunctions(m *macho.File, kernel *macho.File, entryID string) ([]InitFuncInfo, error) {
	var inits []InitFuncInfo

	// Find __mod_init_func section
	var modInitSec *types.Section
	if sec := m.Section("__DATA_CONST", "__mod_init_func"); sec != nil {
		modInitSec = sec
	} else if sec := m.Section("__DATA", "__mod_init_func"); sec != nil {
		modInitSec = sec
	}

	if modInitSec == nil {
		return nil, fmt.Errorf("failed to find __mod_init_func section")
	}

	// Read all pointers from __mod_init_func
	numPtrs := int(modInitSec.Size / 8)

	log.Debugf("Found __mod_init_func in %s with %d entries at offset %#x", entryID, numPtrs, modInitSec.Offset)

	for i := range numPtrs {
		// Calculate the virtual address of this __mod_init_func entry
		ptrVA := modInitSec.Addr + uint64(i*8)

		// For MH_FILESET, we need to use the main kernel to read the pointer
		// since the address might be outside the entry's segments
		var rawPtr uint64
		var err error
		if kernel != nil {
			rawPtr, err = kernel.GetPointerAtAddress(ptrVA)
		} else {
			rawPtr, err = m.GetPointerAtAddress(ptrVA)
		}
		if err != nil {
			log.Debugf("Failed to read pointer at VA %#x: %v", ptrVA, err)
			continue
		}

		// For iOS kernelcache with fixups, the raw pointer is already the correct address
		// SlidePointer incorrectly adds a slide that moves it outside valid segments
		decodedPtr := rawPtr

		if decodedPtr == 0 {
			continue
		}

		// Just record the decoded pointer - function bounds will be resolved using the main kernel
		inits = append(inits, InitFuncInfo{
			RawPtr:    ptrVA,
			FuncAddr:  decodedPtr,
			FuncStart: decodedPtr,
			FuncEnd:   decodedPtr + 0x1000, // Default to 4KB
			EntryID:   entryID,
		})
	}

	return inits, nil
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
		if _, err := m.GetFunctionForVMAddr(addr); err == nil {
			return true
		}
		return false
	}
	return false
}

// findVtableStart finds the start of a vtable by scanning backwards
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

// parseVtableMethods parses vtable entries efficiently
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

		if !isValidFuncAddr(m, val) {
			break
		}
		addr := m.SlidePointer(val)
		pac := extractPACFromPointer(m, ptr)

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

// extractPACFromPointer extracts PAC diversity from a pointer
func extractPACFromPointer(m *macho.File, ptrAddr uint64) uint16 {
	if !m.HasFixups() {
		return 0
	}
	dcf, err := m.DyldChainedFixups()
	if err != nil {
		return 0
	}
	offset, err := m.GetOffset(ptrAddr)
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

// GetClasses analyzes the given Mach-O kernel file and extracts C++ class metadata
func GetClasses(kernel *macho.File, cfg *Config) (classes []ClassMeta, err error) {
	// reset caches per run
	strCache = &stringCache{}
	fdCache = &funcDataCache{}

	osMetaAddr, err := findOsMetaClassFunc(kernel)
	if err != nil {
		return nil, fmt.Errorf("failed to find OSMetaClass function: %v", err)
	}

	if kernel.Type == types.MH_FILESET {
		var mu sync.Mutex
		var eg errgroup.Group

		// Process each fileset entry in parallel
		for _, fs := range kernel.FileSets() {
			// Skip if specific entries are requested and this isn't one
			if len(cfg.Entries) > 0 && !slices.Contains(cfg.Entries, fs.EntryID) {
				continue
			}

			fs := fs // Capture for goroutine
			eg.Go(func() error {
				entry, err := kernel.GetFileSetFileByName(fs.EntryID)
				if err != nil {
					log.Debugf("Failed to get fileset entry %s: %v", fs.EntryID, err)
					return nil // Continue with other entries
				}

				// Get init functions for this entry
				// Pass both the entry (for __mod_init_func section) and kernel (for pointer resolution)
				initFuncs, err := getInitFunctions(entry, kernel, fs.EntryID)
				if err != nil {
					log.Debugf("Failed to get init functions for %s: %v", fs.EntryID, err)
					return nil
				}

				if len(initFuncs) == 0 {
					log.Debugf("No init functions found in %s", fs.EntryID)
					return nil
				}

				var entryClasses []ClassMeta

				// Process each init function with emulation
				// Use the main kernel for emulation since OSMetaClass references are global
				for _, initFunc := range initFuncs {
					// Try to get proper function bounds from the main kernel
					if fn, err := kernel.GetFunctionForVMAddr(initFunc.FuncAddr); err == nil {
						initFunc.FuncStart = fn.StartAddr
						initFunc.FuncEnd = fn.EndAddr
					}

					cls, err := extractClassesFromInitFuncEmulated(kernel, initFunc, osMetaAddr, cfg)
					if err != nil {
						log.Debugf("Failed to extract classes from init func %#x in %s: %v",
							initFunc.FuncAddr, fs.EntryID, err)
						continue
					}
					entryClasses = append(entryClasses, cls...)
				}

				// Add to global list
				mu.Lock()
				classes = append(classes, entryClasses...)
				mu.Unlock()

				if len(entryClasses) > 0 {
					log.Debugf("Found %d classes in %s", len(entryClasses), fs.EntryID)
				}

				return nil
			})
		}

		if err := eg.Wait(); err != nil {
			return nil, err
		}
	} else {
		// NON-FILESET kernel
		initFuncs, err := getInitFunctions(kernel, nil, "kernel")
		if err != nil {
			log.Debugf("Failed to get init functions: %v", err)
		}

		// Process each init function with emulation
		for _, initFunc := range initFuncs {
			cls, err := extractClassesFromInitFuncEmulated(kernel, initFunc, osMetaAddr, cfg)
			if err != nil {
				log.Debugf("Failed to extract classes from init func %#x: %v", initFunc.FuncAddr, err)
				continue
			}
			classes = append(classes, cls...)
		}
	}

	classes = dedupeClasses(classes)
	if cfg.WithOverrides {
		linkParentsAndComputeOverrides(classes)
	}

	log.Infof("Discovered %d C++ classes", len(classes))
	return classes, nil
}

// linkParentsAndComputeOverrides links parent classes and computes method overrides
func linkParentsAndComputeOverrides(classes []ClassMeta) {
	// Build map of meta pointer to class
	metaMap := make(map[uint64]*ClassMeta)
	for i := range classes {
		if classes[i].MetaPtr != 0 {
			metaMap[classes[i].MetaPtr] = &classes[i]
		}
	}

	// Link parents and compute overrides
	for i := range classes {
		if classes[i].SuperMeta != 0 {
			if parent, ok := metaMap[classes[i].SuperMeta]; ok {
				classes[i].SuperClass = parent

				// Check for method overrides
				if len(classes[i].Methods) > 0 && len(parent.Methods) > 0 {
					for j, method := range classes[i].Methods {
						if j < len(parent.Methods) && method.Address != parent.Methods[j].Address {
							// classes[i].OverrideOf = parent
							break
						}
					}
				}
			}
		}
	}
}

func dedupeClasses(classes []ClassMeta) []ClassMeta {
	type key struct {
		meta   uint64
		name   string
		bundle string
	}
	result := make([]ClassMeta, 0, len(classes))
	indexByKey := make(map[key]int)

	for _, class := range classes {
		k := key{meta: class.MetaPtr, name: class.Name, bundle: class.Bundle}
		if idx, ok := indexByKey[k]; ok {
			existing := &result[idx]
			if existing.VtableAddr == 0 && class.VtableAddr != 0 {
				existing.VtableAddr = class.VtableAddr
			}
			if existing.SuperMeta == 0 && class.SuperMeta != 0 {
				existing.SuperMeta = class.SuperMeta
			}
			if existing.Size == 0 && class.Size != 0 {
				existing.Size = class.Size
			}
			if len(class.Methods) > len(existing.Methods) {
				existing.Methods = class.Methods
			}
			if class.SuperClass != nil && existing.SuperClass == nil {
				existing.SuperClass = class.SuperClass
			}
			if existing.AllocFunc == 0 && class.AllocFunc != 0 {
				existing.AllocFunc = class.AllocFunc
			}
			if existing.DiscoveryPC == 0 && class.DiscoveryPC != 0 {
				existing.DiscoveryPC = class.DiscoveryPC
			}
			continue
		}

		indexByKey[k] = len(result)
		result = append(result, class)
	}

	return result
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
