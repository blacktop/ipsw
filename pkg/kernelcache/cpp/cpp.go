package cpp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
	"github.com/blacktop/arm64-cgo/emulate/instructions"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/disass"
	"golang.org/x/sync/errgroup"
)

const (
	errorLogMessage     = "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error)."
	cxaPureVirtualPanic = "__cxa_pure_virtual"
)

// Class represents metadata for a C++ class discovered in the kernelcache
type Class struct {
	Name           string   // Class name (e.g., "IOService")
	NamePtr        uint64   // Pointer to class name string
	Size           uint32   // Size of class instances in bytes
	MetaPtr        uint64   // Address of the OSMetaClass object for this class
	SuperMeta      uint64   // Address of superclass's meta (0 if none)
	SuperClass     *Class   // Pointer to parent class (resolved later)
	Ctor           uint64   // Address of the alloc function
	VtableAddr     uint64   // Address of the class's vtable
	MetaVtableAddr uint64   // Address of the metaclass's vtable
	Methods        []Method // Virtual methods in the vtable
	DiscoveryPC    uint64   // Program counter where class was discovered
	Bundle         string   // Bundle/kext this class belongs to

	m *macho.File
}

// Method represents a virtual method in a class vtable
type Method struct {
	Address    uint64
	Name       string
	Index      int
	OverrideOf uint64
	PAC        uint16
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

type stubCache struct {
	mu   sync.RWMutex
	data map[uint64]uint64
}

func (c *stubCache) get(target uint64) (uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stub, ok := c.data[target]
	return stub, ok
}

func (c *stubCache) set(target, stub uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[uint64]uint64)
	}
	c.data[target] = stub
}

// PhaseTimings tracks time spent in each major phase of GetClasses()
type PhaseTimings struct {
	Anchor      time.Duration // findAnchorFunctions
	FilesetPrep time.Duration // prepareFilesetCache
	Discovery   time.Duration // xref scan + ctor emulation (combined)
	Dedupe      time.Duration // deduplication by class name
	Vtable      time.Duration // populateVtablesPhase
	OSObject    time.Duration // ensureOSObjectClass
	Linking     time.Duration // linkParentsAndComputeOverrides

	// Discovery sub-phase timings (aggregate CPU time across all parallel workers)
	// NOTE: These sum to MORE than Discovery wall-clock time due to parallelism
	XrefScan      time.Duration // Cumulative time in findCallersInText across all workers
	CtorEmulation time.Duration // Cumulative time in extractClassesFromCtorFunc across all workers
}

// Config controls how class discovery runs.
type Config struct {
	ClassName string
	// WithMethods parses each class's vtable entries into detailed methods.
	WithMethods bool
	// Entries restricts which fileset entries to analyze. If empty, analyze all.
	Entries []string
	// Max instructions to emulate per constructor
	MaxCtorInstructions int
	// DisableStubResolution skips stub resolution (set to true to avoid wasted overhead in modern kernelcaches)
	DisableStubResolution bool
	// UseXrefAnchorDiscovery uses xref-based anchor discovery instead of sequential scan
	UseXrefAnchorDiscovery bool
}

type Cpp struct {
	root *macho.File
	cfg  *Config

	// anchor functions
	osMetaClassVariants []uint64 // Addresses of all OSMetaClass::OSMetaClass variants (standard + extended)
	cxaPureVirtual      uint64   // Address of __cxa_pure_virtual function
	allocIndex          int      // Index of alloc function in vtable

	fdCache      *funcDataCache
	filesetCache map[string]*macho.File // Cache for parsed fileset entries
	stubCache    *stubCache             // Cache of stub addresses to their target ctors
	wrappers     []uint64               // Wrapper functions found in kernel (for cross-entry discovery)
	wrapperMu    sync.RWMutex           // Protects wrappers slice

	// Stub resolution instrumentation (thread-safe via atomic)
	stubAttempts atomic.Uint64 // Total calls to resolveStubFunction
	stubHits     atomic.Uint64 // Stub found (non-zero return)
	stubMisses   atomic.Uint64 // Stub not found (zero return)
	stubRetries  atomic.Uint64 // Emulations that had to retry due to invalid x0

	// Discovery sub-phase timing accumulators (thread-safe via atomic, in nanoseconds)
	xrefScanNanos      atomic.Int64 // Accumulated time in findCallersInText
	ctorEmulationNanos atomic.Int64 // Accumulated time in extractClassesFromCtorFunc

	// Phase timing data (written by main goroutine only, not thread-safe)
	timings PhaseTimings

	// Expected class count per constructor (key: ctor start addr, value: xref count)
	ctorClassCounts sync.Map // map[uint64]int protected by sync.Map for thread-safety

	// Early termination metrics (thread-safe via atomic)
	earlyTermCount     atomic.Uint64 // ctors that halted early
	fullEmulationCount atomic.Uint64 // ctors that ran to completion
	extraClassesCount  atomic.Uint64 // ctors with more classes than expected

	// Emulation profiling metrics (thread-safe via atomic)
	emuMetrics struct {
		mu                sync.Mutex
		instructionCounts []int // Per-ctor instruction counts
		postCaptureInsns  []int // Instructions emulated after capturing metadata
	}
	hookMetrics struct {
		preHookCalls  atomic.Uint64
		postHookCalls atomic.Uint64
		boundsChecks  atomic.Uint64
	}
	memMetrics struct {
		cacheHits   atomic.Uint64
		cacheMisses atomic.Uint64
		ioReads     atomic.Uint64 // actual file reads via memory handler
		bytesRead   atomic.Uint64
	}
}

func Create(root *macho.File, cfg *Config) *Cpp {
	return &Cpp{
		root:         root,
		cfg:          cfg,
		fdCache:      &funcDataCache{},
		filesetCache: make(map[string]*macho.File),
		stubCache:    &stubCache{data: make(map[uint64]uint64)},
		allocIndex:   -1,
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

// isOSMetaClassVariant checks if an address matches any known OSMetaClass::OSMetaClass variant
func (c *Cpp) isOSMetaClassVariant(addr uint64) bool {
	for _, variant := range c.osMetaClassVariants {
		if addr == variant {
			return true
		}
	}
	return false
}

// anchorMetrics tracks instrumentation for anchor discovery
type anchorMetrics struct {
	symbolsScanned     int
	exportsScanned     int
	stringsScanned     int
	functionsScanned   int
	functionsProcessed int
	usedStringFallback bool

	symbolScanTime   time.Duration
	exportScanTime   time.Duration
	stringScanTime   time.Duration
	funcScanTime     time.Duration
	getCStringsTime  time.Duration
	getFunctionsTime time.Duration
}

// findAnchorViaXref finds a function that references the given string address
func (c *Cpp) findAnchorViaXref(kernel *macho.File, targetStringAddr uint64, anchorName string) (uint64, error) {
	// Get all functions
	functions := kernel.GetFunctions()

	var result atomic.Uint64
	var wg sync.WaitGroup
	workChan := make(chan types.Function, len(functions))

	// Parallel workers to scan functions
	for range runtime.NumCPU() {
		wg.Go(func() {
			for fn := range workChan {
				// Early exit if another worker found it
				if result.Load() != 0 {
					return
				}

				// Get function data
				data, err := kernel.GetFunctionData(fn)
				if err != nil {
					continue
				}

				// Quick check: does function reference targetStringAddr?
				engine := disass.NewMachoDisass(kernel, &disass.Config{
					Data:         data,
					StartAddress: fn.StartAddr,
					Quiet:        true,
				})

				if err := engine.Triage(); err != nil {
					continue
				}

				if ok, _ := engine.Contains(targetStringAddr); ok {
					// Found it!
					result.Store(fn.StartAddr)
					log.Debugf("Found %s at %#x (references string at %#x)", anchorName, fn.StartAddr, targetStringAddr)
					return
				}
			}
		})
	}

	// Feed functions to workers
	go func() {
		for _, fn := range functions {
			if result.Load() != 0 {
				break
			}
			workChan <- fn
		}
		close(workChan)
	}()

	wg.Wait()

	if addr := result.Load(); addr != 0 {
		return addr, nil
	}
	return 0, fmt.Errorf("anchor %s not found", anchorName)
}

func (c *Cpp) findAnchorsViaXref() error {
	metrics := anchorMetrics{}

	kernel := c.root
	if kernel.Type == types.MH_FILESET {
		var err error
		kernel, err = kernel.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return fmt.Errorf("failed to get main kernel fileset entry: %v", err)
		}
	}

	// Get C strings
	tCStrStart := time.Now()
	strs, err := kernel.GetCStrings()
	if err != nil {
		return fmt.Errorf("failed to get cstrings: %v", err)
	}
	metrics.getCStringsTime = time.Since(tCStrStart)

	var errorStrAddr uint64
	var panicStrAddr uint64

	// Find target strings
	tStrStart := time.Now()
	for _, str2addr := range strs {
		for str, addr := range str2addr {
			metrics.stringsScanned++
			if str == errorLogMessage {
				errorStrAddr = addr
			}
			if str == cxaPureVirtualPanic {
				panicStrAddr = addr
			}
		}
		if errorStrAddr != 0 && panicStrAddr != 0 {
			break
		}
	}
	metrics.stringScanTime = time.Since(tStrStart)

	if errorStrAddr == 0 {
		return fmt.Errorf("failed to find OSMetaClass::OSMetaClass error log message string")
	}
	if panicStrAddr == 0 {
		return fmt.Errorf("failed to find __cxa_pure_virtual panic string")
	}

	// Find functions via xref scanning
	tFuncScanStart := time.Now()

	// Find both anchors in parallel
	var wg sync.WaitGroup
	var osMetaClassAddr, cxaPureVirtualAddr atomic.Uint64
	var osMetaErr, cxaPureErr atomic.Pointer[error]

	wg.Go(func() {
		if addr, err := c.findAnchorViaXref(kernel, errorStrAddr, "OSMetaClass::OSMetaClass"); err != nil {
			osMetaErr.Store(&err)
		} else {
			osMetaClassAddr.Store(addr)
		}
	})

	wg.Go(func() {
		if addr, err := c.findAnchorViaXref(kernel, panicStrAddr, "__cxa_pure_virtual"); err != nil {
			cxaPureErr.Store(&err)
		} else {
			cxaPureVirtualAddr.Store(addr)
		}
	})

	wg.Wait()
	metrics.funcScanTime = time.Since(tFuncScanStart)

	// Check results
	if addr := osMetaClassAddr.Load(); addr != 0 {
		c.osMetaClassVariants = append(c.osMetaClassVariants, addr)
	}
	c.cxaPureVirtual = cxaPureVirtualAddr.Load()

	if len(c.osMetaClassVariants) == 0 {
		if errPtr := osMetaErr.Load(); errPtr != nil {
			return *errPtr
		}
		return fmt.Errorf("failed to find OSMetaClass::OSMetaClass function")
	}
	if c.cxaPureVirtual == 0 {
		if errPtr := cxaPureErr.Load(); errPtr != nil {
			return *errPtr
		}
		return fmt.Errorf("failed to find __cxa_pure_virtual function")
	}

	// Emit metrics
	log.Debugf("Anchor discovery metrics (xref mode):")
	log.Debugf("  strings: scanned=%d time=%s", metrics.stringsScanned, metrics.stringScanTime)
	log.Debugf("  string preparation: GetCStrings() time=%s", metrics.getCStringsTime)
	log.Debugf("  function scanning: time=%s (xref-based)", metrics.funcScanTime)

	return nil
}

func (c *Cpp) findAnchorFunctions() (err error) {
	metrics := anchorMetrics{}

	if len(c.osMetaClassVariants) > 0 && c.cxaPureVirtual != 0 {
		return nil
	}

	// Use xref-based discovery if enabled
	if c.cfg != nil && c.cfg.UseXrefAnchorDiscovery {
		return c.findAnchorsViaXref()
	}

	kernel := c.root
	if kernel.Type == types.MH_FILESET {
		kernel, err = kernel.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return fmt.Errorf("failed to get main kernel fileset entry: %v", err)
		}
	}

	// search for symbols first (KDK kernels and symbolicated kernelcaches)
	tSymStart := time.Now()
	seen := make(map[uint64]bool) // Track unique addresses
	if kernel.Symtab != nil {
		for _, sym := range kernel.Symtab.Syms {
			metrics.symbolsScanned++
			if isOsMetaClassCtor(sym.Name) {
				if !seen[sym.Value] {
					c.osMetaClassVariants = append(c.osMetaClassVariants, sym.Value)
					seen[sym.Value] = true
					log.Debugf("Found OSMetaClass variant '%s' at %#x", sym.Name, sym.Value)
				}
			} else if strings.Contains(sym.Name, "__cxa_pure_virtual") {
				c.cxaPureVirtual = sym.Value
			}
		}
	}
	metrics.symbolScanTime = time.Since(tSymStart)

	tExpStart := time.Now()
	if exports, err := kernel.DyldExports(); err == nil {
		for _, entry := range exports {
			metrics.exportsScanned++
			if isOsMetaClassCtor(entry.Name) {
				if !seen[entry.Address] {
					c.osMetaClassVariants = append(c.osMetaClassVariants, entry.Address)
					seen[entry.Address] = true
					log.Debugf("Found OSMetaClass variant '%s' at %#x", entry.Name, entry.Address)
				}
			} else if strings.Contains(entry.Name, "__cxa_pure_virtual") {
				c.cxaPureVirtual = entry.Address
			}
		}
	}
	metrics.exportScanTime = time.Since(tExpStart)

	// Return early if we found both from symbols/exports
	if len(c.osMetaClassVariants) > 0 && c.cxaPureVirtual != 0 {
		log.Infof("Found %d OSMetaClass variant(s) from symbols/exports", len(c.osMetaClassVariants))
		log.WithField("addr", fmt.Sprintf("%#x", c.cxaPureVirtual)).Debug("Found '__cxa_pure_virtual' from symbols")
		log.Debugf("Anchor discovery metrics:")
		log.Debugf("  symbols: scanned=%d time=%s", metrics.symbolsScanned, metrics.symbolScanTime)
		log.Debugf("  exports: scanned=%d time=%s", metrics.exportsScanned, metrics.exportScanTime)
		return nil
	}

	// String fallback needed
	metrics.usedStringFallback = true

	tCStrStart := time.Now()
	strs, err := kernel.GetCStrings()
	if err != nil {
		return fmt.Errorf("failed to get cstrings: %v", err)
	}
	metrics.getCStringsTime = time.Since(tCStrStart)

	var errorStrAddr uint64
	var panicStrAddr uint64

	// Only search for strings if we still need to find functions
	needOsMetaClass := len(c.osMetaClassVariants) == 0
	needCxaPureVirtual := c.cxaPureVirtual == 0

	if !needOsMetaClass && !needCxaPureVirtual {
		return nil // Already found both
	}

	tStrStart := time.Now()
	for _, str2addr := range strs {
		for str, addr := range str2addr {
			metrics.stringsScanned++
			if needOsMetaClass && str == errorLogMessage {
				errorStrAddr = addr
			}
			if needCxaPureVirtual && str == cxaPureVirtualPanic {
				panicStrAddr = addr
			}
		}
		if (!needOsMetaClass || errorStrAddr != 0) && (!needCxaPureVirtual || panicStrAddr != 0) {
			break
		}
	}
	metrics.stringScanTime = time.Since(tStrStart)

	if needOsMetaClass && errorStrAddr == 0 {
		return fmt.Errorf("failed to find OSMetaClass::OSMetaClass error log message string")
	}
	if needCxaPureVirtual && panicStrAddr == 0 {
		return fmt.Errorf("failed to find __cxa_pure_virtual panic string")
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var once sync.Once
	found := make(chan struct{})

	tGetFuncsStart := time.Now()
	functions := kernel.GetFunctions()
	metrics.getFunctionsTime = time.Since(tGetFuncsStart)
	metrics.functionsScanned = len(functions)

	// Sort functions by size (smallest first) - anchors more likely in small panic helpers
	sort.Slice(functions, func(i, j int) bool {
		sizeI := functions[i].EndAddr - functions[i].StartAddr
		sizeJ := functions[j].EndAddr - functions[j].StartAddr
		return sizeI < sizeJ
	})

	workChan := make(chan types.Function, len(functions))

	tFuncScanStart := time.Now()
	var processedCount atomic.Uint64

	for range runtime.NumCPU() {
		wg.Go(func() {
			for fn := range workChan {
				processedCount.Add(1)

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

				// Check for OSMetaClass if we still need it
				if needOsMetaClass && errorStrAddr != 0 {
					if ok, loc := engine.Contains(errorStrAddr); ok {
						targetFn, err := kernel.GetFunctionForVMAddr(loc)
						if err != nil {
							log.Debugf("Failed to get function at %#x: %v", loc, err)
						} else {
							mu.Lock()
							if len(c.osMetaClassVariants) == 0 { // Double-check in case another goroutine found it first
								c.osMetaClassVariants = append(c.osMetaClassVariants, targetFn.StartAddr)
								log.Debugf("Found OSMetaClass::OSMetaClass at %#x (referenced by log message at %#x)", targetFn.StartAddr, loc)
								// Check if we now have both functions
								if c.cxaPureVirtual != 0 {
									once.Do(func() { close(found) })
									mu.Unlock()
									return // Exit worker - both found
								}
							}
							mu.Unlock()
						}
					}
				}

				// Check for __cxa_pure_virtual if we still need it
				if needCxaPureVirtual && panicStrAddr != 0 {
					if ok, loc := engine.Contains(panicStrAddr); ok {
						targetFn, err := kernel.GetFunctionForVMAddr(loc)
						if err != nil {
							log.Debugf("Failed to get function at %#x: %v", loc, err)
						} else {
							mu.Lock()
							if c.cxaPureVirtual == 0 { // Double-check in case another goroutine found it first
								c.cxaPureVirtual = targetFn.StartAddr
								log.Debugf("Found __cxa_pure_virtual at %#x (referenced by log message at %#x)", c.cxaPureVirtual, loc)
								// Check if we now have both functions
								if len(c.osMetaClassVariants) > 0 {
									once.Do(func() { close(found) })
									mu.Unlock()
									return // Exit worker - both found
								}
							}
							mu.Unlock()
						}
					}
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
	metrics.funcScanTime = time.Since(tFuncScanStart)
	metrics.functionsProcessed = int(processedCount.Load())

	// Verify we found both required functions
	if len(c.osMetaClassVariants) == 0 && c.cxaPureVirtual == 0 {
		return fmt.Errorf("failed to find both OSMetaClass::OSMetaClass and __cxa_pure_virtual functions")
	} else if len(c.osMetaClassVariants) == 0 {
		return fmt.Errorf("failed to find OSMetaClass::OSMetaClass function")
	} else if c.cxaPureVirtual == 0 {
		return fmt.Errorf("failed to find __cxa_pure_virtual function")
	}

	// Emit metrics
	log.Debugf("Anchor discovery metrics:")
	log.Debugf("  symbols: scanned=%d time=%s", metrics.symbolsScanned, metrics.symbolScanTime)
	log.Debugf("  exports: scanned=%d time=%s", metrics.exportsScanned, metrics.exportScanTime)
	if metrics.usedStringFallback {
		log.Debugf("  strings: scanned=%d time=%s (fallback used)", metrics.stringsScanned, metrics.stringScanTime)
		log.Debugf("  string preparation: GetCStrings() time=%s", metrics.getCStringsTime)
		log.Debugf("  functions: GetFunctions() count=%d time=%s", metrics.functionsScanned, metrics.getFunctionsTime)
		log.Debugf("  function scanning: processed=%d time=%s", metrics.functionsProcessed, metrics.funcScanTime)
	}

	return nil
}

func (c *Cpp) findAllocIndex(m *macho.File, vtable uint64) (int, error) {
	idx := 0
	addr := vtable
	for {
		ptr, err := m.GetPointerAtAddress(addr)
		if err != nil {
			if err == io.EOF {
				break
			}
			return -1, fmt.Errorf("failed to read vtable entry at %#x: %v", addr, err)
		}
		if ptr == 0 || ptr == 0xffffffffffffffff {
			break
		}
		if ptr == c.cxaPureVirtual {
			return idx, nil
		}
		addr += 8
		idx++
	}

	return -1, fmt.Errorf("__cxa_pure_virtual not found in OSMetaClass vtable")
}

func (c *Cpp) findOSObjectGetMetaClass(m *macho.File, metaPtr uint64) uint64 {
	if addr, err := m.FindSymbolAddress("__ZNK8OSObject12getMetaClassEv"); err == nil {
		return addr
	}

	const maxInstr = 6
	const maxSize = uint64(maxInstr * 4)

	var result uint64
	var once sync.Once
	var wg sync.WaitGroup

	functions := m.GetFunctions()
	workChan := make(chan types.Function, len(functions))

	for range runtime.NumCPU() {
		wg.Go(func() {
			for fn := range workChan {
				if atomic.LoadUint64(&result) != 0 {
					return
				}
				funcData, cached := c.fdCache.get(fn.StartAddr)
				if !cached {
					data, err := m.GetFunctionData(fn)
					if err != nil || len(data) == 0 {
						continue
					}
					funcData = data
					c.fdCache.put(fn.StartAddr, funcData)
				}
				engine := disass.NewMachoDisass(m, &disass.Config{
					Data:         funcData,
					StartAddress: fn.StartAddr,
					Quiet:        true,
				})
				if err := engine.Triage(); err != nil {
					continue
				}
				if ok, _ := engine.Contains(metaPtr); ok {
					once.Do(func() {
						atomic.StoreUint64(&result, fn.StartAddr)
					})
					return
				}
			}
		})
	}

	for _, fn := range functions {
		if atomic.LoadUint64(&result) != 0 {
			break
		}
		if fn.EndAddr <= fn.StartAddr {
			continue
		}
		size := fn.EndAddr - fn.StartAddr
		if size == 0 || size > maxSize {
			continue
		}
		workChan <- fn
	}
	close(workChan)

	wg.Wait()

	return atomic.LoadUint64(&result)
}

func (c *Cpp) findVtableEntryIndex(m *macho.File, vtable uint64, target uint64) int {
	if m == nil || vtable == 0 || target == 0 {
		return -1
	}
	addr := vtable
	for idx := range 512 {
		ptr, err := m.GetPointerAtAddress(addr + uint64(idx*8))
		if err != nil {
			break
		}
		if ptr == 0 || ptr == 0xffffffffffffffff {
			break
		}
		if ptr == target {
			return idx
		}
	}
	return -1
}

func (c *Cpp) findOSObjectVtableViaGetMetaClass(m *macho.File, getMeta uint64, expectedIdx int, sec *types.Section) (uint64, int) {
	if m == nil || getMeta == 0 || sec == nil {
		return 0, -1
	}

	start := sec.Addr
	end := sec.Addr + sec.Size
	for addr := start + 16; addr+8 <= end; addr += 8 {
		ptr, err := m.GetPointerAtAddress(addr)
		if err != nil || ptr != getMeta {
			continue
		}

		var base uint64
		var idx int
		found := false

		if expectedIdx >= 0 {
			offset := uint64(expectedIdx+2) * 8
			if addr < start+offset {
				continue
			}
			base = addr - offset
			zero1, err1 := m.GetPointerAtAddress(base)
			zero2, err2 := m.GetPointerAtAddress(base + 8)
			if err1 != nil || err2 != nil || zero1 != 0 || zero2 != 0 {
				continue
			}
			idx = expectedIdx
			found = true
		} else {
			probe := addr
			for probe >= start+16 {
				prev, err1 := m.GetPointerAtAddress(probe - 8)
				prevPrev, err2 := m.GetPointerAtAddress(probe - 16)
				if err1 != nil || err2 != nil {
					break
				}
				if prev == 0 && prevPrev == 0 {
					base = probe - 16
					idx = int((addr - (base + 16)) / 8)
					found = true
					break
				}
				probe -= 8
			}
			if !found {
				continue
			}
		}

		if base < start {
			continue
		}

		vtable := base + 16
		log.Debugf("OSObject vtable located via getMetaClass pointer in %s/%s at %#x", sec.Seg, sec.Name, vtable)
		return vtable, idx
	}

	return 0, -1
}

// prepareFilesetCache pre-parses all fileset entries to avoid GetFileSetFileByName errors
// This ensures we have valid *macho.File pointers for all entries before workers start
func (c *Cpp) prepareFilesetCache() error {
	if c.root.Type != types.MH_FILESET {
		return nil
	}

	log.Debug("Pre-parsing all fileset entries to populate cache")

	for _, fs := range c.root.FileSets() {
		// Skip entries that don't match filter (if specified)
		if len(c.cfg.Entries) > 0 && !slices.Contains(c.cfg.Entries, fs.EntryID) {
			continue
		}

		entry, err := c.root.GetFileSetFileByName(fs.EntryID)
		if err != nil {
			log.Debugf("Failed to parse fileset entry %s during cache preparation: %v", fs.EntryID, err)
			continue // Skip this entry but continue with others
		}
		c.filesetCache[fs.EntryID] = entry
		log.Debugf("Cached fileset entry: %s", fs.EntryID)
	}

	log.Debugf("Successfully cached %d fileset entries", len(c.filesetCache))
	return nil
}

// GetClasses analyzes the given Mach-O kernel file and extracts C++ class metadata
func (c *Cpp) GetClasses() (classes []Class, err error) {
	var tStart time.Time

	// Phase 1: Anchor discovery
	tStart = time.Now()
	if err := c.findAnchorFunctions(); err != nil {
		return nil, fmt.Errorf("failed to find anchor functions: %v", err)
	}
	c.timings.Anchor = time.Since(tStart)

	// Phase 2: Fileset cache preparation
	tStart = time.Now()
	if c.root.Type == types.MH_FILESET {
		if err := c.prepareFilesetCache(); err != nil {
			return nil, fmt.Errorf("failed to prepare fileset cache: %v", err)
		}
	}
	c.timings.FilesetPrep = time.Since(tStart)

	// Phase 3: Class discovery (xref scan + ctor emulation)
	tStart = time.Now()

	// If we're looking for a specific class, set up early bailout
	var found atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if c.root.Type == types.MH_FILESET {
		var mu sync.Mutex        // For classes slice
		var cacheMu sync.RWMutex // For filesetCache

		// CRITICAL: Process com.apple.kernel FIRST to populate wrappers list for cross-entry discovery
		for _, fs := range c.root.FileSets() {
			if fs.EntryID != "com.apple.kernel" {
				continue
			}
			if len(c.cfg.Entries) > 0 && !slices.Contains(c.cfg.Entries, fs.EntryID) {
				continue
			}

			cacheMu.RLock()
			entry, exists := c.filesetCache[fs.EntryID]
			cacheMu.RUnlock()
			if !exists {
				break // Skip kernel if not in cache
			}

			log.Debugf("Scanning ctor functions for %s (priority: wrapper discovery)", fs.EntryID)

			tXrefStart := time.Now()
			ctors, err := c.findCallersInText(entry, c.osMetaClassVariants, fs.EntryID)
			c.xrefScanNanos.Add(time.Since(tXrefStart).Nanoseconds())
			if err != nil {
				return nil, fmt.Errorf("failed to find OSMetaClass callers in %s: %v", fs.EntryID, err)
			}

			// Emulate ctors from kernel to populate classes
			var entryClasses []Class
			seen := make(map[uint64]bool)
			for _, ctor := range ctors {
				if ctx.Err() != nil {
					break
				}
				if seen[ctor.StartAddr] {
					continue
				}
				seen[ctor.StartAddr] = true

				tEmuStart := time.Now()
				ctorClasses, targetFound, err := c.extractClassesFromCtorFunc(ctx, entry, &ctor, fs.EntryID)
				c.ctorEmulationNanos.Add(time.Since(tEmuStart).Nanoseconds())
				if err != nil {
					log.Debugf("Failed to emulate ctor %#x in %s: %v", ctor.StartAddr, fs.EntryID, err)
					continue
				}

				if len(ctorClasses) > 0 {
					entryClasses = append(entryClasses, ctorClasses...)
				}

				if targetFound {
					found.Store(true)
					classes = append(classes, entryClasses...)
					// Continue to populate wrappers even if target found
				}
			}

			if len(entryClasses) > 0 {
				log.Debugf("Found %d classes in %s via ctor scan", len(entryClasses), fs.EntryID)
				classes = append(classes, entryClasses...)
			}
			break // Only process kernel once
		}

		// Now process remaining entries in parallel
		eg, ctx := errgroup.WithContext(ctx)

		for _, fs := range c.root.FileSets() {
			// Skip kernel (already processed)
			if fs.EntryID == "com.apple.kernel" {
				continue
			}

			// Filter entries
			if len(c.cfg.Entries) > 0 && !slices.Contains(c.cfg.Entries, fs.EntryID) {
				continue
			}

			fs := fs // Capture for goroutine

			eg.Go(func() error {
				if c.cfg.ClassName != "" && found.Load() {
					return nil
				}

				cacheMu.RLock()
				entry, exists := c.filesetCache[fs.EntryID]
				cacheMu.RUnlock()

				if !exists {
					log.Debugf("Fileset entry %s not in cache (skipped during preparation)", fs.EntryID)
					return nil
				}

				log.Debugf("Scanning ctor functions for %s", fs.EntryID)

				// Find callers within this bundle (time xref scan)
				tXrefStart := time.Now()
				ctors, err := c.findCallersInText(entry, c.osMetaClassVariants, fs.EntryID)
				c.xrefScanNanos.Add(time.Since(tXrefStart).Nanoseconds())
				if err != nil {
					return fmt.Errorf("failed to find OSMetaClass callers in %s: %v", fs.EntryID, err)
				}

				// Emulate all ctors
				var entryClasses []Class
				seen := make(map[uint64]bool)

				for _, ctor := range ctors {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if seen[ctor.StartAddr] {
						continue
					}
					seen[ctor.StartAddr] = true

					// Time ctor emulation
					tEmuStart := time.Now()
					ctorClasses, targetFound, err := c.extractClassesFromCtorFunc(ctx, entry, &ctor, fs.EntryID)
					c.ctorEmulationNanos.Add(time.Since(tEmuStart).Nanoseconds())
					if err != nil {
						log.Debugf("Failed to emulate ctor %#x in %s: %v", ctor.StartAddr, fs.EntryID, err)
						continue
					}

					if len(ctorClasses) > 0 {
						entryClasses = append(entryClasses, ctorClasses...)
					}

					if targetFound {
						found.Store(true)
						cancel()
						mu.Lock()
						classes = append(classes, entryClasses...)
						mu.Unlock()
						return nil
					}
				}

				if len(entryClasses) > 0 {
					log.Debugf("Found %d classes in %s via ctor scan", len(entryClasses), fs.EntryID)
				}

				mu.Lock()
				classes = append(classes, entryClasses...)
				mu.Unlock()
				return nil
			})
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
		log.Debug("Scanning ctor functions for kernel")

		// Time xref scan
		tXrefStart := time.Now()
		ctors, err := c.findCallersInText(c.root, c.osMetaClassVariants, "kernel")
		c.xrefScanNanos.Add(time.Since(tXrefStart).Nanoseconds())
		if err != nil {
			return nil, fmt.Errorf("failed to find OSMetaClass callers in kernel: %v", err)
		}

		seen := make(map[uint64]bool)
		for _, ctor := range ctors {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if seen[ctor.StartAddr] {
				continue
			}
			seen[ctor.StartAddr] = true

			// Time ctor emulation
			tEmuStart := time.Now()
			ctorClasses, targetFound, err := c.extractClassesFromCtorFunc(ctx, c.root, &ctor, "kernel")
			c.ctorEmulationNanos.Add(time.Since(tEmuStart).Nanoseconds())
			if err != nil {
				log.Debugf("Failed to emulate ctor %#x in kernel: %v", ctor.StartAddr, err)
				continue
			}
			classes = append(classes, ctorClasses...)
			if targetFound {
				cancel()
				break
			}
		}
	}
	c.timings.Discovery = time.Since(tStart)

	// Populate discovery sub-phase timings from atomic accumulators
	c.timings.XrefScan = time.Duration(c.xrefScanNanos.Load())
	c.timings.CtorEmulation = time.Duration(c.ctorEmulationNanos.Load())

	// Phase 4: Deduplication
	tStart = time.Now()
	// Deduplicate classes by name, keeping only the first occurrence
	// This filters out helper functions that register the same class multiple times
	seen := make(map[string]bool)
	uniqueClasses := make([]Class, 0, len(classes))
	for _, cls := range classes {
		if !seen[cls.Name] {
			seen[cls.Name] = true
			uniqueClasses = append(uniqueClasses, cls)
		}
	}
	classes = uniqueClasses
	c.timings.Dedupe = time.Since(tStart)

	// Phase 5: Vtable population
	tStart = time.Now()
	classes = c.populateVtablesPhase(classes)
	c.timings.Vtable = time.Since(tStart)

	// Phase 6: OSObject backfill
	tStart = time.Now()
	classes = c.ensureOSObjectClass(classes)
	c.timings.OSObject = time.Since(tStart)

	// Phase 7: Parent linking
	tStart = time.Now()
	linkParentsAndComputeOverrides(classes)
	c.timings.Linking = time.Since(tStart)

	// Emit stub resolution summary (controlled by --verbose flag via log level)
	attempts := c.stubAttempts.Load()
	hits := c.stubHits.Load()
	misses := c.stubMisses.Load()
	retries := c.stubRetries.Load()
	if attempts > 0 || retries > 0 {
		log.Infof("Stub resolution summary: attempts=%d hits=%d misses=%d retries=%d", attempts, hits, misses, retries)
	} else {
		log.Debug("Stub resolution: no stubs needed (all ctors emulated directly)")
	}

	// Emit emulation profiling metrics (debug logging controls visibility)
	c.reportEmulationMetrics()

	return classes, nil
}

// GetPhaseTimings returns timing data for each major phase of GetClasses()
func (c *Cpp) GetPhaseTimings() PhaseTimings {
	return c.timings
}

// resolveWrapperFunction attempts to find a wrapper function that calls the target constructor.
// This handles the case where OSMetaClass::OSMetaClass is called by a wrapper,
// and the wrapper is called by the actual constructor.
// Returns the wrapper address if found, or 0 if not found.
func (c *Cpp) resolveWrapperFunction(m *macho.File, targetAddr uint64) uint64 {
	// Check cache first (reuse stubCache for wrapper→target mappings)
	if wrapper, ok := c.stubCache.get(targetAddr); ok {
		return wrapper
	}

	log.Debugf("Searching for wrapper function calling ctor %#x", targetAddr)

	// Strategy 1: Check if preceding function ends exactly at ctor start
	functions := m.GetFunctions()
	for _, fn := range functions {
		if fn.EndAddr == targetAddr {
			// Preceding function ends at ctor start - likely a wrapper
			log.Debugf("Found preceding function %#x ending at ctor start %#x", fn.StartAddr, targetAddr)
			c.stubCache.set(targetAddr, fn.StartAddr)
			return fn.StartAddr
		}
	}

	// Strategy 2: Scan for B/BL instructions targeting this ctor
	// Get TEXT section
	var textSec *types.Section
	if sec := m.Section("__TEXT_EXEC", "__text"); sec != nil {
		textSec = sec
	} else if sec := m.Section("__TEXT", "__text"); sec != nil {
		textSec = sec
	}
	if textSec == nil {
		c.stubCache.set(targetAddr, 0)
		return 0
	}

	textData, err := textSec.Data()
	if err != nil {
		c.stubCache.set(targetAddr, 0)
		return 0
	}
	textBase := textSec.Addr

	// Scan for B or BL instructions targeting our ctor
	for offset := 0; offset < len(textData)-3; offset += 4 {
		pc := textBase + uint64(offset)
		instr := binary.LittleEndian.Uint32(textData[offset : offset+4])

		// Check for BL (0b100101) or B (0b000101) instruction
		opcode := instr >> 26
		if opcode == 0b100101 || opcode == 0b000101 {
			// Extract 26-bit signed immediate
			imm26 := int32(instr & 0x03FFFFFF)
			if imm26&0x02000000 != 0 {
				imm26 |= -0x04000000
			}
			branchTarget := pc + uint64(imm26<<2)

			if branchTarget == targetAddr {
				// Found a branch to our ctor - get the calling function
				if fn, err := m.GetFunctionForVMAddr(pc); err == nil {
					// Verify this isn't the ctor itself (avoid loops)
					if fn.StartAddr != targetAddr {
						log.Debugf("Found wrapper function %#x with branch to ctor %#x", fn.StartAddr, targetAddr)
						c.stubCache.set(targetAddr, fn.StartAddr)
						return fn.StartAddr
					}
				}
			}
		}
	}

	// No wrapper found, cache the negative result
	c.stubCache.set(targetAddr, 0)
	return 0
}

// resolveStubFunction attempts to find a stub function that sets x0 and branches to the target.
// Returns the stub address if found, or 0 if not found.
func (c *Cpp) resolveStubFunction(m *macho.File, targetAddr uint64) uint64 {
	// Instrument: track attempt
	c.stubAttempts.Add(1)

	// Check cache first
	if stub, ok := c.stubCache.get(targetAddr); ok {
		return stub
	}

	// Get all functions in the binary
	functions := m.GetFunctions()

	// Look for a function that ends with an unconditional branch to our target
	for _, fn := range functions {
		// Skip if function is too large (stubs are typically small)
		if fn.EndAddr-fn.StartAddr > 32 {
			continue
		}

		// Read the last instruction of the function
		lastInstrAddr := fn.EndAddr - 4
		instrBytes := make([]byte, 4)
		if _, err := m.ReadAtAddr(instrBytes, lastInstrAddr); err != nil {
			continue
		}
		instr := binary.LittleEndian.Uint32(instrBytes)

		// Check if it's an unconditional branch (B instruction, not BL)
		// B instruction: bits 31-26 = 0b000101
		if (instr >> 26) == 0b000101 {
			// Extract 26-bit signed immediate
			imm26 := int32(instr & 0x03FFFFFF)
			if imm26&0x02000000 != 0 {
				imm26 |= -0x04000000
			}
			branchTarget := lastInstrAddr + uint64(imm26<<2)

			// Check if this branches to our target
			if branchTarget == targetAddr {
				// Found a potential stub! Verify it sets x0
				funcData, err := m.GetFunctionData(fn)
				if err != nil || len(funcData) < 8 {
					continue
				}

				// Check first instruction for MOV to x0
				firstInstr := binary.LittleEndian.Uint32(funcData[0:4])
				// MOV (between registers) or MOV (immediate) to x0
				// We're looking for patterns like:
				// - MOV x0, x8 (register to register)
				// - MOV x0, #immediate
				// Simple check: destination register is x0 (bits 4-0 = 0)
				if (firstInstr & 0x1F) == 0 {
					// Cache and return the stub address
					c.stubCache.set(targetAddr, fn.StartAddr)
					c.stubHits.Add(1) // Instrument: stub found
					log.Debugf("Resolved stub %#x -> %#x", fn.StartAddr, targetAddr)
					return fn.StartAddr
				}
			}
		}
	}

	// No stub found, cache the negative result
	c.stubCache.set(targetAddr, 0)
	c.stubMisses.Add(1) // Instrument: stub not found
	return 0
}

// findCallersInText finds all functions that contain a BL to the target address
// and tracks the expected class count for each constructor (for early termination)
// For fileset entries, it also performs depth-1 discovery using wrappers from com.apple.kernel
func (c *Cpp) findCallersInText(m *macho.File, targets []uint64, entryID string) ([]types.Function, error) {
	var textSec *types.Section
	if sec := m.Section("__TEXT_EXEC", "__text"); sec != nil {
		textSec = sec
	} else if sec := m.Section("__TEXT", "__text"); sec != nil {
		textSec = sec
	}
	if textSec == nil {
		return nil, fmt.Errorf("failed to find __text section")
	}

	textData, err := textSec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __text section: %w", err)
	}
	textBase := textSec.Addr

	var callers []types.Function
	seen := make(map[uint64]bool)
	ctorXrefCounts := make(map[uint64]int) // Track BL count per constructor

	// Scan the __text section for BL instructions
	for offset := 0; offset < len(textData)-3; offset += 4 {
		pc := textBase + uint64(offset)
		instr := binary.LittleEndian.Uint32(textData[offset : offset+4])
		// Check if this is a BL instruction
		if (instr >> 26) == 0b100101 {
			// Extract 26-bit signed immediate
			imm26 := int32(instr & 0x03FFFFFF)
			if imm26&0x02000000 != 0 {
				imm26 |= -0x04000000
			}
			blTarget := pc + uint64(imm26<<2)

			// Check if this BL targets any of the OSMetaClass variants
			for _, target := range targets {
				if blTarget == target {
					// Found a call to our target! Get the caller function
					if fn, err := m.GetFunctionForVMAddr(pc); err == nil {
						ctorXrefCounts[fn.StartAddr]++
						if !seen[fn.StartAddr] {
							callers = append(callers, fn)
							seen[fn.StartAddr] = true
						}
					}
					break // Found match, no need to check other targets
				}
			}
		}
	}

	// Depth-1 discovery: Find callers of the direct callers (wrappers)
	// This recovers constructors that call wrapper functions instead of OSMetaClass directly
	directCallerAddrs := make([]uint64, 0, len(callers))
	for _, caller := range callers {
		directCallerAddrs = append(directCallerAddrs, caller.StartAddr)
	}

	// Store wrappers from com.apple.kernel for cross-entry discovery
	if entryID == "com.apple.kernel" && len(directCallerAddrs) > 0 {
		c.wrapperMu.Lock()
		c.wrappers = directCallerAddrs
		c.wrapperMu.Unlock()
		log.Debugf("Stored %d wrappers from com.apple.kernel for cross-entry discovery", len(directCallerAddrs))
	}

	// Build combined wrapper list: local wrappers + global wrappers from kernel
	c.wrapperMu.RLock()
	globalWrappers := c.wrappers
	c.wrapperMu.RUnlock()

	allWrappers := directCallerAddrs
	if entryID != "com.apple.kernel" && len(globalWrappers) > 0 {
		// Add kernel wrappers to our search list for cross-entry discovery
		allWrappers = append(allWrappers, globalWrappers...)
		log.Debugf("Using %d local + %d global wrappers for depth-1 discovery", len(directCallerAddrs), len(globalWrappers))
	}

	// Scan for functions that call our wrappers (depth-1 discovery)
	// This runs even if directCallerAddrs is empty, to catch cross-entry wrappers
	if len(allWrappers) > 0 {
		for offset := 0; offset < len(textData)-3; offset += 4 {
			pc := textBase + uint64(offset)
			instr := binary.LittleEndian.Uint32(textData[offset : offset+4])

			// Check for BL or B instruction
			opcode := instr >> 26
			if opcode == 0b100101 || opcode == 0b000101 { // BL or B
				// Extract 26-bit signed immediate
				imm26 := int32(instr & 0x03FFFFFF)
				if imm26&0x02000000 != 0 {
					imm26 |= -0x04000000
				}
				branchTarget := pc + uint64(imm26<<2)

				// Check if this branches to any of our wrappers (local or global)
				for _, wrapperAddr := range allWrappers {
					if branchTarget == wrapperAddr {
						// Found a function calling a wrapper
						if fn, err := m.GetFunctionForVMAddr(pc); err == nil {
							// Make sure this isn't a direct caller itself (avoid duplicates)
							if !seen[fn.StartAddr] {
								callers = append(callers, fn)
								seen[fn.StartAddr] = true
								ctorXrefCounts[fn.StartAddr]++
								isGlobal := ""
								for _, gw := range globalWrappers {
									if wrapperAddr == gw {
										isGlobal = " (cross-entry)"
										break
									}
								}
								log.Debugf("Depth-1: Found ctor %#x calling wrapper %#x%s", fn.StartAddr, wrapperAddr, isGlobal)
							}
						}
						break
					}
				}
			}
		}
	}

	// Store expected class counts for early termination
	for ctorAddr, xrefCount := range ctorXrefCounts {
		c.ctorClassCounts.Store(ctorAddr, xrefCount)
		if xrefCount > 1 {
			log.Debugf("Ctor %#x: expecting %d class registrations", ctorAddr, xrefCount)
		}
	}

	return callers, nil
}

// extractClassesFromCtorFunc emulates a ctor leaf function and extracts any classes it registers
// This is the optimized path that jumps directly to the leaf function
// pendingClass tracks the state of a class being discovered during constructor emulation
type pendingClass struct {
	metaPtr            uint64
	namePtr            uint64
	superMeta          uint64
	size               uint64
	discoveryPC        uint64
	metaVtableAddr     uint64 // captured from x16 (pre-PAC!)
	instructionsPastBL int    // instructions emulated after BL to OSMetaClass
	lastX16Value       uint64 // Track last x16 value before PAC for accurate metavtable capture
}

func (c *Cpp) extractClassesFromCtorFunc(ctx context.Context, m *macho.File, ctor *types.Function, entryID string) ([]Class, bool, error) {
	var err error
	log.Debugf("Emulating ctor function %#x in %s", ctor.StartAddr, entryID)

	// Check if this constructor is actually a stub - if x0 validation fails during emulation,
	// we'll attempt to resolve the stub and re-run with the actual stub function
	actualCtor := ctor
	isRetryWithStub := false

retryWithStub:
	// Get function data
	funcData, cached := c.fdCache.get(actualCtor.StartAddr)
	if !cached {
		funcData, err = m.GetFunctionData(*actualCtor)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read constructor bytes: %w", err)
		}
		c.fdCache.put(actualCtor.StartAddr, funcData)
	}
	log.WithField("ctor", fmt.Sprintf("%#x", actualCtor.StartAddr)).Debugf("Emulating ctor function directly")

	var classes []Class
	var pending *pendingClass // tracks class metadata capture in progress
	var targetFound bool

	// Retrieve expected class count for early termination
	expectedCount := 0
	if val, ok := c.ctorClassCounts.Load(ctor.StartAddr); ok {
		expectedCount = val.(int)
		if expectedCount > 1 {
			log.Debugf("Ctor %#x: expecting %d classes, will early-terminate", ctor.StartAddr, expectedCount)
		}
	}
	if expectedCount == 0 {
		// Unknown - fallback to full emulation (disable early termination)
		log.Debugf("Ctor %#x: expected class count unknown, emulating to end", ctor.StartAddr)
		expectedCount = 1<<31 - 1 // MaxInt32
	}

	// Setup emulation config for ctor (much smaller limit needed!)
	emuCfg := emulate.DefaultEngineConfig()
	emuCfg.InitialPC = actualCtor.StartAddr
	emuCfg.MaxInstructions = c.cfg.MaxCtorInstructions
	emuCfg.StopOnError = false
	emuCfg.MemoryHandler = func(addr uint64, size int) ([]byte, error) {
		// Check function data cache first (always a hit for ctor code)
		if addr >= actualCtor.StartAddr && addr < actualCtor.StartAddr+uint64(len(funcData)) {
			c.memMetrics.cacheHits.Add(1)
			offset := addr - actualCtor.StartAddr
			if offset+uint64(size) <= uint64(len(funcData)) {
				return funcData[offset : offset+uint64(size)], nil
			}
		}

		// Check funcDataCache for other function data
		if cachedData, ok := c.fdCache.get(addr); ok && len(cachedData) >= size {
			c.memMetrics.cacheHits.Add(1)
			return cachedData[:size], nil
		}

		// Cache miss - need to read from file
		c.memMetrics.cacheMisses.Add(1)
		c.memMetrics.ioReads.Add(1)
		c.memMetrics.bytesRead.Add(uint64(size))

		buf := make([]byte, size)
		if _, err := c.root.ReadAtAddr(buf, addr); err != nil {
			return make([]byte, size), nil
		}
		return buf, nil
	}

	// Setup bounds guard to stop at end of function
	boundsGuard, err := emulate.NewBoundsGuard(actualCtor.StartAddr, actualCtor.EndAddr+4, emulate.WithStrictRange(false))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create bounds guard: %w", err)
	}

	engine := emulate.NewEngineWithConfig(emuCfg)

	// Pre-instruction hook to extract class metadata and capture x16 (pre-PAC metavtable pointer)
	instrCount := 0
	var metadataCaptureInsn int // Instruction count when we captured OSMetaClass metadata
	if err := engine.AddHook(core.HookPreInstruction, core.PreInstructionHook(func(state core.State, info core.InstructionInfo) core.HookResult {
		c.hookMetrics.preHookCalls.Add(1)
		instrCount++

		// Check if context was cancelled (target found by another worker)
		if ctx.Err() != nil {
			return core.HookResult{Halt: true}
		}

		// Check bounds first
		c.hookMetrics.boundsChecks.Add(1)
		if result := boundsGuard.Pre(state, info); result.Halt {
			log.Debugf("BoundsGuard halted at %#x (depth=%d)", info.Address, result.Halt)
			return result
		}

		if info.Instruction == nil {
			return core.HookResult{}
		}

		// PAC detection: Capture x16 BEFORE PAC instruction executes
		if pending != nil && pending.metaVtableAddr == 0 && instructions.IsPACInstruction(info.Instruction.Operation) {
			x16 := state.GetX(16)
			if x16 >= 0xfffffe0000000000 {
				pending.metaVtableAddr = x16
				log.Debugf("Captured pre-PAC MetaVtableAddr %#x at PAC instruction %#x (+%d ins from BL)",
					x16, info.Address, pending.instructionsPastBL)

				// Finalize class now that we have metavtable
				className, _ := c.root.GetCString(pending.namePtr)
				if className == "" {
					className = fmt.Sprintf("UnknownClass_%#x", pending.metaPtr)
				}
				class := Class{
					Ctor:           ctor.StartAddr,
					Name:           className,
					NamePtr:        pending.namePtr,
					Size:           uint32(pending.size),
					MetaPtr:        pending.metaPtr,
					SuperMeta:      pending.superMeta,
					Bundle:         entryID,
					DiscoveryPC:    pending.discoveryPC,
					MetaVtableAddr: x16, // Pre-PAC metavtable pointer!
					m:              m,
				}
				classes = append(classes, class)

				// Check for target match
				if c.cfg.ClassName != "" && strings.EqualFold(className, c.cfg.ClassName) {
					targetFound = true
				}

				// Check early termination
				allHaveMetavtab := true
				for _, cls := range classes {
					if cls.MetaVtableAddr == 0 {
						allHaveMetavtab = false
						break
					}
				}

				if len(classes) >= expectedCount && allHaveMetavtab {
					log.Debugf("Ctor %#x: captured %d/%d classes with metavtabs, halting",
						ctor.StartAddr, len(classes), expectedCount)
					c.earlyTermCount.Add(1)
					return core.HookResult{Halt: true}
				}

				// Reset for next class
				pending = nil
			}
		}

		// State machine: track x16 capture after BL to OSMetaClass
		// The post-hook will handle x16 capture, here we just track timeout
		if pending != nil && pending.metaVtableAddr == 0 {
			pending.instructionsPastBL++

			// Safety: don't wait forever for x16 (reduced timeout since PAC should be caught in pre-hook)
			if pending.instructionsPastBL > 20 { // PAC typically at instruction 6-8, give extra margin
				log.Warnf("Ctor %#x: no x16 found within 64 bytes of BL at %#x, using fallback",
					ctor.StartAddr, pending.discoveryPC)
				// Finalize class without metavtab (will be populated later via populateVtablesPhase)
				className, _ := c.root.GetCString(pending.namePtr)
				if className == "" {
					className = fmt.Sprintf("UnknownClass_%#x", pending.metaPtr)
				}
				class := Class{
					Ctor:           ctor.StartAddr,
					Name:           className,
					NamePtr:        pending.namePtr,
					Size:           uint32(pending.size),
					MetaPtr:        pending.metaPtr,
					SuperMeta:      pending.superMeta,
					Bundle:         entryID,
					DiscoveryPC:    pending.discoveryPC,
					MetaVtableAddr: 0, // Missing! Will be populated later
					m:              m,
				}
				classes = append(classes, class)
				pending = nil
			}
		}

		// Extract class info when we see the BL to OSMetaClass::OSMetaClass or a known wrapper
		if info.Instruction.Operation == disassemble.ARM64_BL {
			if len(info.Instruction.Operands) > 0 {
				target := info.Instruction.Operands[0].Immediate

				// Check if this is a call to a known wrapper function
				isWrapperCall := false
				c.wrapperMu.RLock()
				globalWrappers := c.wrappers
				c.wrapperMu.RUnlock()
				for _, wrapperAddr := range globalWrappers {
					if target == wrapperAddr {
						isWrapperCall = true
						log.Debugf("Detected BL to known wrapper %#x at %#x", target, info.Address)
						break
					}
				}

				// Check if this is a direct call to any OSMetaClass variant or a known wrapper
				if c.isOSMetaClassVariant(target) || isWrapperCall {
					// Validate register state before accepting this as a real constructor
					// This filters out helper functions that aren't actual class registrations
					var valid, wide uint32
					type validityChecker interface {
						GetValidityMask() (uint32, uint32, uint32)
					}
					if s, ok := state.(validityChecker); ok {
						valid, wide, _ = s.GetValidityMask()
					}

					// Check that x0-x3 are all valid and have correct widths
					// valid & 0xf == 0xf: all of x0, x1, x2, x3 are set
					// wide & 0xf == 0x7: x0, x1, x2 are 64-bit (pointers), x3 is 32-bit (size)
					// Allow slight tolerance: at least x1 and x2 must be valid (class name and super)
					if (valid & 0x6) != 0x6 { // Bits 1 and 2 (x1, x2)
						log.Debugf("Skipping constructor at %#x: insufficient register validity (valid=%#x, wide=%#x)", info.Address, valid, wide)
						return core.HookResult{SkipInstruction: true}
					}

					// Check if x0 is invalid - this might indicate we're in the actual ctor called by a stub/wrapper
					if (valid&0x1) == 0 && !isRetryWithStub && !c.cfg.DisableStubResolution {
						// x0 is invalid - try to find a stub or wrapper that calls this function
						c.stubAttempts.Add(1) // Track attempt even when disabled

						// First try stub resolution (fast, legacy stubs)
						wrapperAddr := c.resolveStubFunction(m, ctor.StartAddr)

						// If no stub found, try wrapper resolution (slower, but finds OSMetaClass wrappers)
						if wrapperAddr == 0 {
							wrapperAddr = c.resolveWrapperFunction(m, ctor.StartAddr)
						}

						if wrapperAddr != 0 {
							c.stubRetries.Add(1) // Instrument: retry triggered
							log.Debugf("x0 invalid at %#x, found wrapper/stub at %#x - retrying", info.Address, wrapperAddr)
							// Found a wrapper/stub - restart emulation with it
							wrapperFunc, err := m.GetFunctionForVMAddr(wrapperAddr)
							if err == nil {
								actualCtor = &wrapperFunc
								isRetryWithStub = true
								// Signal to halt current emulation and retry
								return core.HookResult{Halt: true}
							}
						}
					}

					// If we were still tracking a class, finalize it before starting another
					if pending != nil {
						// Previous class didn't get its metavtab - finalize it anyway
						className, _ := c.root.GetCString(pending.namePtr)
						if className == "" {
							className = fmt.Sprintf("UnknownClass_%#x", pending.metaPtr)
						}
						class := Class{
							Ctor:           ctor.StartAddr,
							Name:           className,
							NamePtr:        pending.namePtr,
							Size:           uint32(pending.size),
							MetaPtr:        pending.metaPtr,
							SuperMeta:      pending.superMeta,
							Bundle:         entryID,
							DiscoveryPC:    pending.discoveryPC,
							MetaVtableAddr: pending.metaVtableAddr, // May be 0 if not captured
							m:              m,
						}
						classes = append(classes, class)
					}

					// Extract parameters: x0=this, x1=className, x2=superMeta, x3=size
					thisPtr := state.GetX(0)
					namePtr := state.GetX(1)
					superMeta := state.GetX(2)
					size := state.GetX(3)

					className, err := c.root.GetCString(namePtr)
					if err != nil || className == "" {
						log.Errorf("Failed to read class name at %#x (namePtr=%#x) in ctor %#x: %v", info.Address, namePtr, ctor.StartAddr, err)
						return core.HookResult{Halt: true}
					}

					// Create pending class to track x16 capture
					pending = &pendingClass{
						metaPtr:            thisPtr,
						namePtr:            namePtr,
						superMeta:          superMeta,
						size:               size,
						discoveryPC:        info.Address,
						metaVtableAddr:     0, // Will be captured from x16
						instructionsPastBL: 0,
					}

					// Track when we captured metadata for early termination analysis
					metadataCaptureInsn = instrCount

					log.WithFields(log.Fields{
						"addr":  fmt.Sprintf("%#x", info.Address),
						"class": className,
					}).Debug("Found Class")
					log.Debugf("Created pending class for %s, will track x16", className)

					if c.cfg.ClassName != "" && strings.EqualFold(className, c.cfg.ClassName) {
						targetFound = true
					}

					// Skip executing the BL instruction since we've already extracted the class info
					return core.HookResult{SkipInstruction: true}
				}
			}
		}

		// Skip ALL branch instructions to prevent following them (except RET)
		if instructions.IsBranchOp(info.Instruction) && !instructions.IsReturnOp(info.Instruction) {
			return core.HookResult{SkipInstruction: true}
		}

		return core.HookResult{}
	})); err != nil {
		return nil, false, fmt.Errorf("failed to register pre-instruction hook: %w", err)
	}

	// Post-instruction hook to capture x16 value AFTER each instruction following BL
	// PAC-aware: track x16 writes and capture the value BEFORE any PAC instruction
	if err := engine.AddHook(core.HookPostInstruction, core.PostInstructionHook(func(state core.State, info core.InstructionInfo) core.HookResult {
		c.hookMetrics.postHookCalls.Add(1)

		// Post-hook is now simplified - PAC detection moved to pre-hook
		// This hook can be removed or used for future enhancements

		return core.HookResult{}
	})); err != nil {
		return nil, false, fmt.Errorf("failed to register post-instruction hook: %w", err)
	}

	// Run emulation (memory handler is already set in config)
	if err := engine.SetMemory(actualCtor.StartAddr, funcData); err != nil {
		return nil, false, fmt.Errorf("failed to load ctor function %#x into emulator: %w", actualCtor.StartAddr, err)
	}

	log.Debugf("Starting emulation for ctor %#x (PC=%#x)", actualCtor.StartAddr, emuCfg.InitialPC)
	if err := engine.Run(); err != nil {
		log.Debugf("Emulation error: %v (instrCount=%d, pending=%v)", err, instrCount, pending != nil)
		// Check if we at least found classes before the error
		if len(classes) == 0 {
			log.Debugf("Ctor emulation failed at %#x after %d instructions: %v", engine.GetPC(), instrCount, err)
			// Don't return error - just log it and continue
		} else {
			log.Debugf("Ctor emulation encountered error after %d instructions but %d class(es) found: %v", instrCount, len(classes), err)
		}
	} else {
		log.Debugf("Ctor emulation completed successfully after %d instructions", instrCount)
	}

	// Collect instruction count metrics (use engine's count as authoritative source)
	finalInsnCount := engine.GetInstructionCount()
	c.emuMetrics.mu.Lock()
	c.emuMetrics.instructionCounts = append(c.emuMetrics.instructionCounts, finalInsnCount)
	if metadataCaptureInsn > 0 {
		postCaptureCount := finalInsnCount - metadataCaptureInsn
		c.emuMetrics.postCaptureInsns = append(c.emuMetrics.postCaptureInsns, postCaptureCount)
		log.Debugf("Emulated %d instructions after capturing metadata (total=%d, capture_at=%d)", postCaptureCount, finalInsnCount, metadataCaptureInsn)
	}
	c.emuMetrics.mu.Unlock()

	// If we detected a stub and need to retry, do so now
	if isRetryWithStub && pending == nil {
		log.Debugf("Retrying emulation with stub function at %#x", actualCtor.StartAddr)
		isRetryWithStub = false // Reset flag for the retry
		goto retryWithStub
	}

	// Finalize any remaining pending class
	if pending != nil {
		className, _ := c.root.GetCString(pending.namePtr)
		if className == "" {
			className = fmt.Sprintf("UnknownClass_%#x", pending.metaPtr)
		}
		class := Class{
			Ctor:           ctor.StartAddr,
			Name:           className,
			NamePtr:        pending.namePtr,
			Size:           uint32(pending.size),
			MetaPtr:        pending.metaPtr,
			SuperMeta:      pending.superMeta,
			Bundle:         entryID,
			DiscoveryPC:    pending.discoveryPC,
			MetaVtableAddr: pending.metaVtableAddr, // May be 0 if not captured
			m:              m,
		}
		classes = append(classes, class)
		pending = nil
	}

	// Track whether we halted early or ran to completion
	// Count classes that have metavtable addresses captured
	classesWithMetavtab := 0
	for _, cls := range classes {
		if cls.MetaVtableAddr != 0 {
			classesWithMetavtab++
		}
	}

	// We halted early if we captured all expected classes with metavtables
	if len(classes) > 0 && len(classes) == expectedCount && classesWithMetavtab == len(classes) && expectedCount < (1<<31-1) {
		// earlyTermCount was already incremented in the post-hook
	} else if len(classes) > 0 {
		// Ran to completion (or hit instruction limit/error)
		c.fullEmulationCount.Add(1)
	}

	if len(classes) > 0 {
		log.Debugf("Successfully extracted %d class(es) from ctor %#x", len(classes), ctor.StartAddr)
	} else {
		log.Debugf("No class found in ctor %#x (emulated %d instructions)", ctor.StartAddr, instrCount)

		// If no classes found and we haven't already retried with a wrapper, try wrapper resolution
		if !isRetryWithStub && !c.cfg.DisableStubResolution {
			c.stubAttempts.Add(1) // Track attempt

			// Check if this constructor calls any known wrappers (from global wrapper list)
			c.wrapperMu.RLock()
			globalWrappers := c.wrappers
			c.wrapperMu.RUnlock()

			if len(globalWrappers) > 0 {
				// Scan constructor for BL instructions to known wrappers
				for offset := 0; offset < len(funcData)-3; offset += 4 {
					pc := actualCtor.StartAddr + uint64(offset)
					instr := binary.LittleEndian.Uint32(funcData[offset : offset+4])

					// Check for BL instruction
					if (instr >> 26) == 0b100101 {
						// Extract 26-bit signed immediate
						imm26 := int32(instr & 0x03FFFFFF)
						if imm26&0x02000000 != 0 {
							imm26 |= -0x04000000
						}
						blTarget := pc + uint64(imm26<<2)

						// Check if this calls a known wrapper
						for _, wrapperAddr := range globalWrappers {
							if blTarget == wrapperAddr {
								c.stubRetries.Add(1) // Instrument: retry triggered
								log.Debugf("Ctor %#x calls wrapper %#x - retrying with wrapper", ctor.StartAddr, wrapperAddr)
								// Found the wrapper - restart emulation with it
								wrapperFunc, err := c.root.GetFunctionForVMAddr(wrapperAddr)
								if err == nil {
									actualCtor = &wrapperFunc
									isRetryWithStub = true
									goto retryWithStub
								}
							}
						}
					}
				}
			}
		}
	}

	return classes, targetFound, nil
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

func (c *Cpp) ensureOSObjectClass(classes []Class) []Class {
	if len(classes) == 0 {
		return classes
	}

	kernel := c.root
	if kernel.Type == types.MH_FILESET {
		if mainKernel, err := c.root.GetFileSetFileByName("com.apple.kernel"); err == nil {
			kernel = mainKernel
		} else {
			log.Debugf("Failed to resolve main kernel fileset for OSObject lookup: %v", err)
		}
	}

	osObjectIdx := -1
	osMetaIdx := -1
	for i := range classes {
		switch classes[i].Name {
		case "OSObject":
			osObjectIdx = i
		case "OSMetaClass":
			osMetaIdx = i
		}
		if osObjectIdx != -1 && osMetaIdx != -1 {
			break
		}
	}

	if osObjectIdx == -1 {
		classes = append(classes, Class{
			Name:        "OSObject",
			Bundle:      "kernel",
			DiscoveryPC: 0,
			m:           kernel,
		})
		osObjectIdx = len(classes) - 1
		log.Debug("OSObject class not found in discovered classes; created placeholder")
	}

	osObject := &classes[osObjectIdx]

	if osMetaIdx != -1 && osObject.MetaVtableAddr == 0 && classes[osMetaIdx].MetaVtableAddr != 0 {
		osObject.MetaVtableAddr = classes[osMetaIdx].MetaVtableAddr
	}

	// Early exit: skip expensive lookups if OSObject already has complete metadata
	if osObject.VtableAddr != 0 && osObject.MetaVtableAddr != 0 {
		log.Debugf("OSObject already complete (vtable=%#x, metavtable=%#x); skipping expensive lookups",
			osObject.VtableAddr, osObject.MetaVtableAddr)
		return classes
	}

	if kernel != nil && (osObject.VtableAddr == 0 || osObject.MetaVtableAddr == 0) {
		if vtable, meta := c.findVtableBySymbol(kernel, osObject.Name); vtable != 0 || meta != 0 {
			if osObject.VtableAddr == 0 && vtable != 0 {
				osObject.VtableAddr = vtable
				log.Debug("OSObject vtable discovered via symbols/exports")
			}
			if osObject.MetaVtableAddr == 0 && meta != 0 {
				osObject.MetaVtableAddr = meta
			}
		}
	}

	var osObjectMeta uint64 = osObject.MetaPtr
	if osObjectMeta == 0 {
		log.Debug("OSObject meta pointer unavailable; skipping getMeta lookup")
	}

	var getMeta uint64
	var scanSection *types.Section
	if kernel != nil && osObjectMeta != 0 {
		getMeta = c.findOSObjectGetMetaClass(kernel, osObjectMeta)
		if getMeta != 0 {
			log.Debugf("OSObject::getMetaClass %#x", getMeta)
		}
	}

	if kernel != nil && getMeta != 0 {
		expectedIdx := -1
		if osObject.MetaVtableAddr != 0 {
			expectedIdx = c.findVtableEntryIndex(kernel, osObject.MetaVtableAddr, getMeta)
		}

		// Option B: Skip expensive vtable scan if index lookup failed
		if expectedIdx < 0 {
			log.Debug("OSObject getMetaClass not found in metavtable; skipping expensive vtable scan")
		} else {
			// Only proceed with vtable scan if we have a valid index
			if osObject.MetaVtableAddr != 0 {
				scanSection = kernel.FindSectionForVMAddr(osObject.MetaVtableAddr)
			}
			if scanSection == nil && osMetaIdx != -1 {
				scanSection = kernel.FindSectionForVMAddr(classes[osMetaIdx].MetaVtableAddr)
			}
			if scanSection == nil {
				scanSection = kernel.FindSectionForVMAddr(getMeta)
			}
			if vtable, idx := c.findOSObjectVtableViaGetMetaClass(kernel, getMeta, expectedIdx, scanSection); vtable != 0 {
				osObject.VtableAddr = vtable
				if idx >= 0 {
					log.Debugf("OSObject::getMetaClass index %d", idx)
				}
			}
		}
	}

	if osObject.VtableAddr == 0 {
		log.Debug("OSObject vtable not recovered; leaving unset")
	}

	if c.cfg != nil && c.cfg.WithMethods && osObject.VtableAddr != 0 && len(osObject.Methods) == 0 && kernel != nil {
		if methods, err := c.parseVtableMethods(kernel, osObject.VtableAddr-16, osObject.Name); err != nil {
			log.Debugf("Failed to parse OSObject vtable methods: %v", err)
		} else {
			osObject.Methods = methods
		}
	}

	return classes
}

func (c *Cpp) fileForClass(class *Class) *macho.File {
	if class.m != nil {
		return class.m
	}
	if class.Bundle != "" && class.Bundle != "kernel" && class.Bundle != "__kernel__" {
		if entry, ok := c.filesetCache[class.Bundle]; ok {
			class.m = entry
			return entry
		}
		if c.root.Type == types.MH_FILESET {
			if entry, err := c.root.GetFileSetFileByName(class.Bundle); err == nil {
				c.filesetCache[class.Bundle] = entry
				class.m = entry
				return entry
			}
		}
	}
	class.m = c.root
	return class.m
}

// fileForVMAddr returns the Mach-O file that owns the given virtual address.
// It first prefers cached fileset entries to avoid repeatedly re-parsing images.
func (c *Cpp) fileForVMAddr(addr uint64) *macho.File {
	if c.root == nil {
		return nil
	}

	// Non-fileset kernels can defer directly to the root image.
	if c.root.Type != types.MH_FILESET {
		if c.root.FindSegmentForVMAddr(addr) != nil {
			return c.root
		}
		return nil
	}

	// Prefer already cached fileset entries.
	for _, entry := range c.filesetCache {
		if entry == nil {
			continue
		}
		if entry.FindSegmentForVMAddr(addr) != nil {
			return entry
		}
	}

	// Fall back to parsing uncached entries (should be rare after prepareFilesetCache).
	for _, fs := range c.root.FileSets() {
		if _, ok := c.filesetCache[fs.EntryID]; ok {
			continue
		}
		entry, err := c.root.GetFileSetFileByName(fs.EntryID)
		if err != nil {
			continue
		}
		c.filesetCache[fs.EntryID] = entry
		if entry.FindSegmentForVMAddr(addr) != nil {
			return entry
		}
	}

	// As a final fallback, return the root image if it claims the address.
	if c.root.FindSegmentForVMAddr(addr) != nil {
		return c.root
	}

	return nil
}

// reportEmulationMetrics emits detailed profiling data about constructor emulation
func (c *Cpp) reportEmulationMetrics() {
	c.emuMetrics.mu.Lock()
	defer c.emuMetrics.mu.Unlock()

	if len(c.emuMetrics.instructionCounts) == 0 {
		log.Debug("No emulation metrics collected")
		return
	}

	// Calculate instruction count statistics
	sort.Ints(c.emuMetrics.instructionCounts)
	count := len(c.emuMetrics.instructionCounts)
	median := c.emuMetrics.instructionCounts[count/2]
	p95 := c.emuMetrics.instructionCounts[count*95/100]

	// Memory cache efficiency
	hits := c.memMetrics.cacheHits.Load()
	misses := c.memMetrics.cacheMisses.Load()
	totalAccess := hits + misses
	var hitRate float64
	if totalAccess > 0 {
		hitRate = float64(hits) / float64(totalAccess) * 100
	}

	// Report high-level emulation statistics
	log.Debugf("Emulation stats: %d ctors, median=%d P95=%d instructions", count, median, p95)
	log.Debugf("Cache hit rate: %.1f%% (%d hits, %d misses)", hitRate, hits, misses)

	// Early termination effectiveness
	earlyTerm := c.earlyTermCount.Load()
	fullEmu := c.fullEmulationCount.Load()
	totalEmu := earlyTerm + fullEmu
	if totalEmu > 0 {
		log.Debugf("Early termination: %d/%d ctors (%.1f%%)", earlyTerm, totalEmu, float64(earlyTerm)/float64(totalEmu)*100)
	}
}
