package cpp

import (
	"encoding/binary"
	"fmt"
	"runtime"
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

// Class represents metadata for a C++ class discovered in the kernelcache
type Class struct {
	Name        string   // Class name (e.g., "IOService")
	Size        uint32   // Size of class instances in bytes
	MetaPtr     uint64   // Address of the OSMetaClass object for this class
	SuperMeta   uint64   // Address of superclass's meta (0 if none)
	SuperClass  *Class   // Pointer to parent class (resolved later)
	AllocFunc   uint64   // Address of the alloc function
	VtableAddr  uint64   // Address of the class's vtable
	Methods     []Method // Virtual methods in the vtable
	DiscoveryPC uint64   // Program counter where class was discovered
	Bundle      string   // Bundle/kext this class belongs to
}

// Method represents a virtual method in a class vtable
type Method struct {
	Address    uint64
	Name       string
	Index      int
	OverrideOf uint64
	PAC        uint16
}

// InitFunc holds information about a __mod_init_func entry
type InitFunc struct {
	types.Function
	entryID string
	xrefs   []uint64 // OSMetaClass xrefs in this init function
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

// Config controls how class discovery runs.
type Config struct {
	// WithMethods parses each class's vtable entries into detailed methods.
	WithMethods bool
	// Entries restricts which fileset entries to analyze. If empty, analyze all.
	Entries []string
}

type Cpp struct {
	root *macho.File
	cfg  *Config

	osMetaClass uint64 // Address of OSMetaClass::OSMetaClass function

	strCache *stringCache
	fdCache  *funcDataCache
}

func Create(root *macho.File, cfg *Config) *Cpp {
	return &Cpp{
		root:     root,
		cfg:      cfg,
		strCache: &stringCache{},
		fdCache:  &funcDataCache{},
	}
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

func (c *Cpp) getOsMetaClassAddr() (err error) {
	if c.osMetaClass != 0 {
		return nil
	}

	kernel := c.root
	if kernel.Type == types.MH_FILESET {
		kernel, err = kernel.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return fmt.Errorf("failed to get main kernel fileset entry: %v", err)
		}
	}

	// search for symbol first (KDK kernels and symbolicated kernelcaches)
	if kernel.Symtab != nil {
		for _, sym := range kernel.Symtab.Syms {
			if isOsMetaClassCtor(sym.Name) {
				c.osMetaClass = sym.Value
				return nil
			}
		}
	}

	if exports, err := kernel.DyldExports(); err == nil {
		for _, entry := range exports {
			if isOsMetaClassCtor(entry.Name) {
				c.osMetaClass = entry.Address
				return nil
			}
		}
	}

	strs, err := kernel.GetCStrings()
	if err != nil {
		return fmt.Errorf("failed to get cstrings: %v", err)
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
		return fmt.Errorf("failed to find OSMetaClass::OSMetaClass error log message string")
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var once sync.Once
	found := make(chan struct{})
	functions := kernel.GetFunctions()
	workChan := make(chan types.Function, len(functions))

	for range runtime.NumCPU() {
		wg.Go(func() {
			for fn := range workChan {
				// Check if already found
				select {
				case <-found:
					return // Exit worker
				default:
				}

				data, err := kernel.GetFunctionData(fn)
				if err != nil {
					log.Debugf("Failed to get function data at %#x: %v", fn.StartAddr, err)
					continue // Process next function
				}

				engine := disass.NewMachoDisass(kernel, &disass.Config{
					Data:         data,
					StartAddress: fn.StartAddr,
					Quiet:        true,
				})

				if err := engine.Triage(); err != nil {
					log.Debugf("First pass triage failed at %#x: %v", fn.StartAddr, err)
					continue // Process next function
				}

				if ok, loc := engine.Contains(targetStrAddr); ok {
					targetFn, err := kernel.GetFunctionForVMAddr(loc)
					if err != nil {
						log.Debugf("Failed to get function at %#x: %v", loc, err)
						continue // Process next function
					}

					mu.Lock()
					if c.osMetaClass == 0 { // Double-check in case another goroutine found it first
						c.osMetaClass = targetFn.StartAddr
						log.Infof("Found OSMetaClass::OSMetaClass at %#x (referenced by log message at %#x)", c.osMetaClass, loc)
						once.Do(func() { close(found) })
					}
					mu.Unlock()
					return // Exit worker once found
				}
			}
		})
	}

	go func() {
		for _, fn := range functions {
			select {
			case <-found:
				close(workChan)
				return
			case workChan <- fn:
			}
		}
		close(workChan)
	}()

	wg.Wait()

	if c.osMetaClass == 0 {
		return fmt.Errorf("failed to find OSMetaClass::OSMetaClass function")
	}

	return nil
}

// GetClasses analyzes the given Mach-O kernel file and extracts C++ class metadata
func (c *Cpp) GetClasses() (classes []Class, err error) {

	if err := c.getOsMetaClassAddr(); err != nil {
		return nil, fmt.Errorf("failed to find OSMetaClass function: %v", err)
	}

	if c.root.Type == types.MH_FILESET {
		var mu sync.Mutex
		var eg errgroup.Group

		for _, fs := range c.root.FileSets() {
			// Filter entries
			if len(c.cfg.Entries) > 0 && !slices.Contains(c.cfg.Entries, fs.EntryID) {
				continue
			}

			fs := fs // Capture for goroutine

			eg.Go(func() error {
				entry, err := c.root.GetFileSetFileByName(fs.EntryID)
				if err != nil {
					log.Debugf("Failed to get fileset entry %s: %v", fs.EntryID, err)
					return nil // Continue with other entries
				}
				// Get init functions for this entry
				initsChan, err := c.getInitFunctions(entry, fs.EntryID)
				if err != nil {
					log.Debugf("Failed to get init functions for %s: %v", fs.EntryID, err)
					return nil
				}

				var entryClasses []Class
				for initFunc := range initsChan {
					cls, err := c.extractClassesFromInitFuncEmulated(entry, initFunc)
					if err != nil {
						log.Debugf("Failed to extract classes from init func %#x in %s: %v", initFunc.StartAddr, fs.EntryID, err)
						continue
					}
					entryClasses = append(entryClasses, cls...)
				}

				mu.Lock()
				classes = append(classes, entryClasses...)
				mu.Unlock()

				if len(entryClasses) > 0 {
					log.Debugf("Found %d classes in %s", len(entryClasses), fs.EntryID)
				}

				return nil
			})

			c.fdCache = &funcDataCache{} // Reset function data cache for each entry
			c.strCache = &stringCache{}  // Reset string cache for each entry
		}

		if err := eg.Wait(); err != nil {
			return nil, err
		}
	} else { // NON-FILESET kernel
		initsChan, err := c.getInitFunctions(c.root, "kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to get init functions: %v", err)
		}
		for initFunc := range initsChan {
			cls, err := c.extractClassesFromInitFuncEmulated(c.root, initFunc)
			if err != nil {
				log.Debugf("Failed to extract classes from init func %#x: %v", initFunc.StartAddr, err)
				continue
			}
			classes = append(classes, cls...)
		}
	}

	classes = dedupeClasses(classes)
	linkParentsAndComputeOverrides(classes)

	log.Debugf("Discovered %d C++ classes", len(classes))
	return classes, nil
}

// findXrefsInInitFunc scans an init function for all OSMetaClass calls (direct, indirect, veneers)
func (c *Cpp) findXrefsInInitFunc(m *macho.File, initFunc InitFunc) (xrefs []uint64, err error) {
	// Get function data from cache or read it
	funcData, cached := c.fdCache.get(initFunc.StartAddr)
	if !cached {
		funcData, err = m.GetFunctionData(initFunc.Function)
		if err != nil {
			return nil, fmt.Errorf("failed to get function data: %v", err)
		}
		c.fdCache.put(initFunc.StartAddr, funcData)
	}

	// Scan for direct BL
	for offset := 0; offset+4 <= len(funcData); offset += 4 {
		inst := binary.LittleEndian.Uint32(funcData[offset:])
		pc := initFunc.StartAddr + uint64(offset)
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
			if target == c.osMetaClass {
				xrefs = append(xrefs, pc)
			}
		}
	}

	return xrefs, nil
}

// extractClassesFromInitFuncEmulated uses emulation to extract accurate class metadata
func (c *Cpp) extractClassesFromInitFuncEmulated(m *macho.File, initFunc InitFunc) ([]Class, error) {
	var classes []Class

	xrefs, err := c.findXrefsInInitFunc(m, initFunc)
	if err != nil {
		log.Debugf("Failed to find xrefs in init func %#x: %v", initFunc.StartAddr, err)
		return classes, nil
	}
	if len(xrefs) == 0 {
		return classes, nil
	}

	log.Debugf("Found %d OSMetaClass xrefs in init function %#x", len(xrefs), initFunc.StartAddr)

	funcData, cached := c.fdCache.get(initFunc.StartAddr)
	if !cached {
		funcData, err = m.GetFunctionData(initFunc.Function)
		if err != nil {
			return nil, fmt.Errorf("failed to get function data: %v", err)
		}
		c.fdCache.put(initFunc.StartAddr, funcData)
	}

	for _, xref := range xrefs {
		class, err := c.emulateClassFromXref(m, initFunc, xref, funcData)
		if err != nil {
			log.Debugf("Emulation failed for xref %#x in init %#x: %v", xref, initFunc.StartAddr, err)
			continue
		}
		classes = append(classes, *class)
	}

	return classes, nil
}

func (c *Cpp) emulateClassFromXref(m *macho.File, initFunc InitFunc, xref uint64, funcData []byte) (*Class, error) {
	// Use limited emulation starting just before the BL
	blOffset := int(xref - initFunc.StartAddr)
	if blOffset < 0 || blOffset+4 > len(funcData) {
		return nil, fmt.Errorf("BL offset %d out of bounds", blOffset)
	}

	// Start emulation from 64 instructions before the BL (256 bytes)
	startOffset := max(blOffset-256, 0)
	startPC := initFunc.StartAddr + uint64(startOffset)

	// Extract the relevant portion of function data
	endOffset := min(
		// Include some instructions after BL for vtable
		blOffset+64, len(funcData))
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
		if pc == xref {
			namePtr := engine.GetRegister(1)
			className := ""
			if cached, ok := c.strCache.get(namePtr); ok {
				className = cached
			} else if s, err := m.GetCString(namePtr); err == nil {
				className = s
				c.strCache.put(namePtr, s)
			}
			if className == "" {
				return nil, fmt.Errorf("failed to read class name string at %#x", namePtr)
			}

			class := &Class{
				Name:        className,
				MetaPtr:     engine.GetRegister(0),
				SuperMeta:   engine.GetRegister(2),
				Size:        uint32(engine.GetRegister(3)),
				AllocFunc:   initFunc.StartAddr,
				DiscoveryPC: xref,
				Bundle:      initFunc.entryID,
			}

			// Step past the BL and look for vtable in X16
			if c.cfg.WithMethods {
				// Skip the BL instruction first
				if err := stepOver(engine); err == nil {
					for i := 0; i < 16; i++ {
						if err := stepOver(engine); err != nil {
							break
						}
						if val := engine.GetRegister(16); val != 0 {
							// Don't apply slide to vtable address - it's already correct
							class.VtableAddr = val
							if c.cfg.WithMethods {
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
			return nil, fmt.Errorf("emulation error at %#x: %w", pc, err)
		}
	}

	return nil, fmt.Errorf("failed to reach BL at %#x after %d steps", xref, emuCfg.MaxInstructions)
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

func (c *Cpp) getInitFunctions(m *macho.File, entryID string) (<-chan InitFunc, error) {
	var modInitSec *types.Section
	if sec := m.Section("__DATA_CONST", "__mod_init_func"); sec != nil {
		modInitSec = sec
	} else if sec := m.Section("__DATA", "__mod_init_func"); sec != nil {
		modInitSec = sec
	}
	if modInitSec == nil {
		return nil, fmt.Errorf("failed to find __mod_init_func section")
	}

	numPtrs := int(modInitSec.Size / 8)
	initsChan := make(chan InitFunc, min(numPtrs, 100))

	log.Debugf("Found __mod_init_func in %s with %d entries at offset %#x", entryID, numPtrs, modInitSec.Offset)

	go func() {
		defer close(initsChan)

		for i := range numPtrs {
			ptrVA := modInitSec.Addr + uint64(i*8)

			var ptr uint64
			var err error
			if c.root.Type == types.MH_FILESET {
				// For MH_FILESET, we need to use the main kernel to read the pointer
				// since the address might be outside the entry's segments
				ptr, err = c.root.GetPointerAtAddress(ptrVA)
			} else {
				ptr, err = m.GetPointerAtAddress(ptrVA)
			}
			if err != nil {
				log.Debugf("Failed to read pointer at VA %#x: %v", ptrVA, err)
				continue
			}
			if ptr == 0 {
				log.Debugf("Skipping null init func pointer at VA %#x", ptrVA)
				continue
			}

			fn, err := m.GetFunctionForVMAddr(ptr)
			if err != nil {
				log.Debugf("No function found for init func pointer %#x at VA %#x: %v", ptr, ptrVA, err)
				continue
			}

			initsChan <- InitFunc{
				Function: fn,
				entryID:  entryID,
			}
		}
	}()

	return initsChan, nil
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
func parseVtableMethods(m *macho.File, vptr uint64, className string) []Method {
	methods := make([]Method, 0, 64)
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

		mi := Method{
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
	err = nil
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

// linkParentsAndComputeOverrides links parent classes and computes method overrides
func linkParentsAndComputeOverrides(classes []Class) {
	// Build map of meta pointer to class
	metaMap := make(map[uint64]*Class)
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

func dedupeClasses(classes []Class) []Class {

	type key struct {
		meta   uint64
		name   string
		bundle string
	}
	result := make([]Class, 0, len(classes))
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
