package cpp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"golang.org/x/sync/errgroup"
)

const errorLogMessage = "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error)."

// Class represents metadata for a C++ class discovered in the kernelcache
type Class struct {
	Name           string   // Class name (e.g., "IOService")
	Size           uint32   // Size of class instances in bytes
	MetaPtr        uint64   // Address of the OSMetaClass object for this class
	SuperMeta      uint64   // Address of superclass's meta (0 if none)
	SuperClass     *Class   // Pointer to parent class (resolved later)
	AllocFunc      uint64   // Address of the alloc function
	VtableAddr     uint64   // Address of the class's vtable
	MetaVtableAddr uint64   // Address of the metaclass's vtable
	Methods        []Method // Virtual methods in the vtable
	DiscoveryPC    uint64   // Program counter where class was discovered
	Bundle         string   // Bundle/kext this class belongs to
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
	ClassName string
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
			if exp.Name == mainSymbol {
				vtable = exp.Address + 16
			} else if exp.Name == metaSymbol {
				metaVtable = exp.Address + 16
			}
		}
	}

	return vtable, metaVtable
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

	// If we're looking for a specific class, set up early bailout
	var found atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if c.root.Type == types.MH_FILESET {
		var mu sync.Mutex
		eg, ctx := errgroup.WithContext(ctx)

		for _, fs := range c.root.FileSets() {
			// Filter entries
			if len(c.cfg.Entries) > 0 && !slices.Contains(c.cfg.Entries, fs.EntryID) {
				continue
			}

			fs := fs // Capture for goroutine

			eg.Go(func() error {
				// Check if target already found
				if c.cfg.ClassName != "" && found.Load() {
					return nil
				}

				entry, err := c.root.GetFileSetFileByName(fs.EntryID)
				if err != nil {
					log.Debugf("Failed to get fileset entry %s: %v", fs.EntryID, err)
					return nil // Continue with other entries
				}
				// Get init functions for this entry
				initsChan, err := c.getInitFunctions(ctx, entry, fs.EntryID)
				if err != nil {
					log.Debugf("Failed to get init functions for %s: %v", fs.EntryID, err)
					return nil
				}

				var entryClasses []Class
				for {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case initFunc, ok := <-initsChan:
						if !ok {
							// Channel closed, done processing
							goto done
						}
						cls, targetFound, err := c.extractClassesFromInitFunc(ctx, entry, initFunc)
						if err != nil {
							log.Debugf("Failed to extract classes from init func %#x in %s: %v", initFunc.StartAddr, fs.EntryID, err)
							continue
						}
						entryClasses = append(entryClasses, cls...)

						// Check if we found the target class
						if targetFound {
							found.Store(true)
							cancel() // Signal all goroutines to stop
							mu.Lock()
							classes = append(classes, entryClasses...)
							mu.Unlock()
							return nil
						}
					}
				}
			done:
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
			if err == context.Canceled {
				// Expected when target found
				log.Debugf("Search cancelled after finding target class")
			} else {
				return nil, err
			}
		}
	} else { // NON-FILESET kernel
		initsChan, err := c.getInitFunctions(ctx, c.root, "kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to get init functions: %v", err)
		}
		for {
			select {
			case <-ctx.Done():
				break
			case initFunc, ok := <-initsChan:
				if !ok {
					// Channel closed, done processing
					break
				}
				cls, targetFound, err := c.extractClassesFromInitFunc(ctx, c.root, initFunc)
				if err != nil {
					log.Debugf("Failed to extract classes from init func %#x: %v", initFunc.StartAddr, err)
					continue
				}
				classes = append(classes, cls...)

				// Check if we found the target class
				if targetFound {
					cancel()
					break
				}
			}
			if ctx.Err() != nil {
				break
			}
		}
	}

	classes = dedupeClasses(classes)
	linkParentsAndComputeOverrides(classes)

	return classes, nil
}

// extractClassesFromInitFunc uses full emulation to extract class metadata
// Returns (classes, targetFound, error) where targetFound indicates if cfg.ClassName was found
func (c *Cpp) extractClassesFromInitFunc(ctx context.Context, m *macho.File, initFunc InitFunc) ([]Class, bool, error) {
	var classes []Class
	var currentClass *Class
	var osMetaClassCallPC uint64
	var stubDepth int // Track how deep we are in stub calls (0 = original function, 1 = first stub)
	var targetFound bool

	log.WithField("init", fmt.Sprintf("%#x", initFunc.StartAddr)).Debugf("Emulating init function in %s", initFunc.entryID)

	// Check if context is already cancelled
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}

	// Get function data
	funcData, cached := c.fdCache.get(initFunc.StartAddr)
	if !cached {
		var err error
		funcData, err = m.GetFunctionData(initFunc.Function)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get function data: %v", err)
		}
		c.fdCache.put(initFunc.StartAddr, funcData)
	}

	// Setup emulation config
	emuCfg := emulate.DefaultEngineConfig()
	emuCfg.InitialPC = initFunc.StartAddr
	emuCfg.StopAddress = initFunc.EndAddr + 4 // Stop after function ends
	emuCfg.MaxInstructions = 2000             // Safety limit
	emuCfg.StopOnError = false                // skip unsupported instructions

	// Memory handler for reading from binary
	emuCfg.MemoryHandler = func(addr uint64, size int) ([]byte, error) {
		// First check if it's in our loaded function
		if addr >= initFunc.StartAddr && addr < initFunc.StartAddr+uint64(len(funcData)) {
			offset := addr - initFunc.StartAddr
			if offset+uint64(size) <= uint64(len(funcData)) {
				return funcData[offset : offset+uint64(size)], nil
			}
		}
		// Otherwise read from binary
		buf := make([]byte, size)
		if _, err := m.ReadAtAddr(buf, addr); err != nil {
			return make([]byte, size), nil // Return zeros on error
		}
		return buf, nil
	}

	// String handler for reading C strings
	emuCfg.StringHandler = func(addr uint64) (string, error) {
		return m.GetCString(addr)
	}

	// Pre-instruction hook to detect calls to OSMetaClass::OSMetaClass
	preHook := core.PreInstructionHook(func(state core.State, info core.InstructionInfo) core.HookResult {
		// Check if this is a BL instruction
		if info.Instruction != nil && info.Instruction.Operation == disassemble.ARM64_BL {
			// Get the branch target from the operands
			if len(info.Instruction.Operands) > 0 {
				// The first operand should have the immediate value for the branch target
				target := info.Instruction.Operands[0].Immediate

				// Check if this is calling OSMetaClass::OSMetaClass
				if target == c.osMetaClass {
					// Capture register state for class info
					namePtr := state.GetX(1) // X1 = class name
					className := ""
					if cached, ok := c.strCache.get(namePtr); ok {
						className = cached
					} else if s, err := m.GetCString(namePtr); err == nil {
						className = s
						c.strCache.put(namePtr, s)
					}

					if className != "" {
						currentClass = &Class{
							Name:        className,
							MetaPtr:     state.GetX(0),         // X0 = meta pointer
							SuperMeta:   state.GetX(2),         // X2 = super meta
							Size:        uint32(state.GetX(3)), // X3 = size
							AllocFunc:   initFunc.StartAddr,
							DiscoveryPC: info.Address,
							Bundle:      initFunc.entryID,
						}
						osMetaClassCallPC = info.Address
						utils.Indent(log.WithFields(log.Fields{
							"class": className,
							"addr":  fmt.Sprintf("%#x", info.Address),
							"init":  fmt.Sprintf("%#x", initFunc.StartAddr),
						}).Debug, 2)("Found Class")

						// Check if this is our target class
						if c.cfg.ClassName != "" && strings.EqualFold(className, c.cfg.ClassName) {
							targetFound = true
							// If we don't need methods, we can bail out now
							if !c.cfg.WithMethods {
								return core.HookResult{Halt: true}
							}
							// Otherwise continue to collect vtable info
						}

						// Skip executing the BL instruction since we've already extracted the class info
						return core.HookResult{SkipInstruction: true}
					} else {
						log.Errorf("Failed to read class name string at %#x in %s", namePtr, initFunc.entryID)
						return core.HookResult{Halt: true}
					}
				}
			}
		}

		// Check for unconditional branch (B) to handle stubs - but only follow first level
		if info.Instruction != nil && info.Instruction.Operation == disassemble.ARM64_B {
			if len(info.Instruction.Operands) > 0 {
				// The first operand should have the immediate value for the branch target
				target := info.Instruction.Operands[0].Immediate

				if target != 0 {
					// Check if this branches to a different function (stub)
					if fn, err := m.GetFunctionForVMAddr(target); err == nil {
						// Check if we're branching to a different function
						currentFunc, _ := m.GetFunctionForVMAddr(info.Address)
						if fn.StartAddr != currentFunc.StartAddr {
							// Only follow the stub if we're at depth 0 (original function)
							if stubDepth == 0 {
								// Load the target function for continued emulation
								if targetData, err := m.GetFunctionData(fn); err == nil {
									// Update memory with target function
									c.fdCache.put(fn.StartAddr, targetData)
									utils.Indent(log.Debug, 2)(fmt.Sprintf("Following stub from %#x to %#x (depth: %d -> %d)", info.Address, target, stubDepth, stubDepth+1))
									stubDepth++ // Increment depth when following stub
									// Let the emulator handle the branch naturally
								}
							} else {
								utils.Indent(log.Debug, 2)(fmt.Sprintf("Skipping nested stub at %#x to %#x (depth limit reached: %d)", info.Address, target, stubDepth))
								// Don't follow nested stubs - just continue
							}
						}
					}
				}
			}
		}
		return core.HookResult{} // Continue normally
	})

	// Post-instruction hook to check for vtable in X16 after OSMetaClass call
	postHook := core.PostInstructionHook(func(state core.State, info core.InstructionInfo) core.HookResult {
		// Check if we returned to original function (RET instruction)
		if stubDepth > 0 && info.Instruction != nil && info.Instruction.Operation == disassemble.ARM64_RET {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Returning from stub at %#x (depth: %d -> %d)", info.Address, stubDepth, stubDepth-1))
			stubDepth--
		}

		if info.Address == initFunc.EndAddr+4 {
			// We've reached the end of the function
			if currentClass != nil {
				// Add any pending class without vtable
				classes = append(classes, *currentClass)
				currentClass = nil
			}
			return core.HookResult{Halt: true}
		}

		if currentClass != nil && osMetaClassCallPC != 0 && c.cfg.WithMethods {
			if info.Address > osMetaClassCallPC && info.Address <= osMetaClassCallPC+16 { // Within 4 instructions
				if info.Instruction.Operation != disassemble.ARM64_ADRP { // Skip ADRP since it won't have the full address yet
					if val := state.GetX(16); val != 0 {
						if sec := m.FindSectionForVMAddr(val); sec != nil {
							if sec.Name == "__const" {
								// This is actually the metavtable
								currentClass.MetaVtableAddr = val + 16

								// Now find the real vtable using symbols first
								vtable, metaVtable := c.findVtableBySymbol(m, currentClass.Name)
								if vtable != 0 {
									currentClass.VtableAddr = vtable
								}
								if metaVtable == 0 && currentClass.MetaVtableAddr != 0 {
									// We found it via emulation already
									metaVtable = currentClass.MetaVtableAddr
								} else if metaVtable != 0 {
									currentClass.MetaVtableAddr = metaVtable
								}

								// Note: In many cases, especially for kernelcaches without symbols,
								// the main vtable might not be discoverable through the MetaPtr at
								// this point in initialization. The metavtable is what we can reliably
								// discover through emulation (x16 register after OSMetaClass ctor).

								// Parse methods from the MAIN vtable, not meta
								if c.cfg.WithMethods && currentClass.VtableAddr != 0 {
									var err error
									currentClass.Methods, err = c.parseVtableMethods(m, currentClass.VtableAddr-16, currentClass.Name)
									if err != nil {
										log.Warnf("Failed to parse vtable methods for class %s: %v", currentClass.Name, err)
									}
								}
							} else {
								log.Warnf("Skipping vtable for class %s at %#x in %s - not in __const section (found in %s)", currentClass.Name, val, initFunc.entryID, sec.Name)
							}

							// Check if this is our target class (with vtable info)
							if c.cfg.ClassName != "" && strings.EqualFold(currentClass.Name, c.cfg.ClassName) {
								targetFound = true
								return core.HookResult{Halt: true}
							}

							// Add the class and reset for next one
							classes = append(classes, *currentClass)
							currentClass = nil
							osMetaClassCallPC = 0
						}
					}
				}
			}
		}
		return core.HookResult{} // Continue normally
	})

	// Register hooks with the emulator
	emuCfg.Hooks = []emulate.HookRegistration{
		{Kind: core.HookPreInstruction, Handler: preHook},
		{Kind: core.HookPostInstruction, Handler: postHook},
	}

	engine := emulate.NewEngineWithConfig(emuCfg)

	// Load the function code
	if err := engine.SetMemory(initFunc.StartAddr, funcData); err != nil {
		return nil, false, fmt.Errorf("failed to load function: %w", err)
	}

	// Run the emulation
	if err := engine.Run(); err != nil {
		// Check if we hit the stop address (normal termination)
		if engine.GetPC() >= initFunc.EndAddr {
			// This is expected - we reached the end
		} else {
			return nil, false, fmt.Errorf("emulation failed at %#x: %w (unsupported instructions should be added to emulator)", engine.GetPC(), err)
		}
	}

	// Add any pending class without vtable
	if currentClass != nil {
		if c.cfg.ClassName != "" && strings.EqualFold(currentClass.Name, c.cfg.ClassName) {
			targetFound = true
		}
		classes = append(classes, *currentClass)
	}

	return classes, targetFound, nil
}

func (c *Cpp) getInitFunctions(ctx context.Context, m *macho.File, entryID string) (<-chan InitFunc, error) {
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
			// Check for cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

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

			select {
			case <-ctx.Done():
				return
			case initsChan <- InitFunc{
				Function: fn,
				entryID:  entryID,
			}:
			}
		}
	}()

	return initsChan, nil
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

		if _, err := m.GetFunctionForVMAddr(addr); err != nil {
			log.Debugf("vtable entry at %#x (addr=%#x) is not valid function for class %s: %v", vptr, addr, className, err)
			// For debugging, don't fail completely - just skip this entry and break
			break
		}

		pac := extractPACFromPointer(c.root, vptr)

		mi := Method{
			Address: addr,
			Index:   i * 8, // Index should be byte offset, not entry count
			PAC:     pac,
		}

		resolveMethodName(m, &mi, className)

		methods = append(methods, mi)

		vptr += 8
		i++
	}

	log.Debugf("parseVtableMethods for class %s found %d methods", className, len(methods))
	return methods, nil
}

// extractPACFromPointer extracts PAC diversity from a pointer
func extractPACFromPointer(m *macho.File, ptrAddr uint64) uint16 {
	if !m.HasFixups() {
		return 0
	}
	if offset, err := m.GetOffset(ptrAddr); err != nil {
		return 0
	} else {
		dcf, err := m.DyldChainedFixups()
		if err != nil {
			return 0
		}
		if fixup, err := dcf.GetFixupAtOffset(offset); err == nil && fixup != nil {
			if auth, ok := fixup.(fixupchains.Auth); ok {
				return uint16(auth.Diversity())
			}
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
			if existing.MetaVtableAddr == 0 && class.MetaVtableAddr != 0 {
				existing.MetaVtableAddr = class.MetaVtableAddr
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
