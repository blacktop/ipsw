package cpp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

const (
	defaultMaxCtorInstructions = 1000
	defaultMaxWrapperDepth     = 5
	defaultAllocIndex          = -1
	defaultGetMetaClassIndex   = 7
	kernelBundleName           = "com.apple.kernel"
	kernelAddrFloor            = 0xfffffe0000000000
	maxReasonableClassSize     = 1 << 20
)

// Config controls scanner behavior.
type Config struct {
	Entries             []string
	ClassName           string
	MaxCtorInstructions int
	MaxWrapperDepth     int
}

// Class is the phase-1 scanner output.
type Class struct {
	Name           string
	Bundle         string
	Size           uint32
	Ctor           uint64
	MetaPtr        uint64
	SuperMeta      uint64
	SuperIndex     int
	MetaVtableAddr uint64
	VtableAddr     uint64
}

// Scanner performs single-threaded class discovery for kernelcache Mach-Os.
type Scanner struct {
	root *macho.File
	cfg  Config

	decoder disassemble.Decoder

	targets         []scanTarget
	fileEntries     map[*macho.File]string
	functions       map[*macho.File][]types.Function
	functionData    map[fileFuncKey][]byte
	sectionData     map[sectionKey][]byte
	callerIndex     map[*macho.File]map[uint64][]uint64
	pointerIndex    map[*macho.File]map[uint64][]uint64
	forwardPointers map[*macho.File]map[uint64]uint64
	getMetaMap      map[*macho.File]map[uint64][]uint64
	getMetaCands    map[fileAddrKey][]uint64
	callsiteCtx     map[fileAddrKey]wrapperContext
	staticCalls     map[staticCallKey]cachedWrapperContext
	nameStrings     map[uint64]cachedCString
	symbolNames     map[fileAddrKey]cachedCString
	metaCtorIdx     map[*macho.File]map[uint64][]types.Function

	osMetaClassVariants map[uint64]struct{}
	cxaPureVirtual      uint64
	allocIndex          int
	getMetaClassIndex   int

	stats scanStats
}

type scanTarget struct {
	file    *macho.File
	entryID string
}

type fileFuncKey struct {
	file  *macho.File
	start uint64
}

type sectionKey struct {
	file *macho.File
	addr uint64
}

type fileAddrKey struct {
	file *macho.File
	addr uint64
}

type staticCallKey struct {
	file     *macho.File
	start    uint64
	callsite uint64
	target   uint64
}

type discoveredClass struct {
	Class
	file *macho.File
}

type ctorPath struct {
	fn      types.Function
	owner   *macho.File
	entryID string
	preload *wrapperContext
}

type pendingClass struct {
	metaPtr        uint64
	namePtr        uint64
	superMeta      uint64
	size           uint64
	ctor           uint64
	metaVtableAddr uint64
}

type wrapperContext struct {
	x0       uint64
	x1       uint64
	x2       uint64
	x3       uint64
	callsite uint64
	metaVtab uint64
}

type cachedWrapperContext struct {
	ctx wrapperContext
	ok  bool
}

type scanStats struct {
	discoveredClasses   int
	resolvedVtables     int
	resolvedParentMeta  int
	pointerIndexEntries int
	engineCreations     int
	ptrCacheHits        int
	ptrCacheMisses      int
}

type cachedCString struct {
	value string
	ok    bool
}

// NewScanner constructs a new phase-1 scanner.
func NewScanner(root *macho.File, cfg Config) *Scanner {
	if cfg.MaxCtorInstructions == 0 {
		cfg.MaxCtorInstructions = defaultMaxCtorInstructions
	}
	if cfg.MaxWrapperDepth == 0 {
		cfg.MaxWrapperDepth = defaultMaxWrapperDepth
	}
	cfg.ClassName = strings.TrimSpace(cfg.ClassName)

	s := &Scanner{
		root:                root,
		cfg:                 cfg,
		fileEntries:         make(map[*macho.File]string),
		functions:           make(map[*macho.File][]types.Function),
		functionData:        make(map[fileFuncKey][]byte),
		sectionData:         make(map[sectionKey][]byte),
		callerIndex:         make(map[*macho.File]map[uint64][]uint64),
		pointerIndex:        make(map[*macho.File]map[uint64][]uint64),
		forwardPointers:     make(map[*macho.File]map[uint64]uint64),
		getMetaMap:          make(map[*macho.File]map[uint64][]uint64),
		getMetaCands:        make(map[fileAddrKey][]uint64),
		callsiteCtx:         make(map[fileAddrKey]wrapperContext),
		staticCalls:         make(map[staticCallKey]cachedWrapperContext),
		nameStrings:         make(map[uint64]cachedCString),
		symbolNames:         make(map[fileAddrKey]cachedCString),
		metaCtorIdx:         make(map[*macho.File]map[uint64][]types.Function),
		osMetaClassVariants: make(map[uint64]struct{}),
		allocIndex:          defaultAllocIndex,
		getMetaClassIndex:   defaultGetMetaClassIndex,
	}
	s.fileEntries[root] = kernelBundleName
	return s
}

// Scan discovers classes from the current kernelcache.
func (s *Scanner) Scan() ([]Class, error) {
	if s.root == nil {
		return nil, fmt.Errorf("nil macho file")
	}

	targets, err := s.buildTargets()
	if err != nil {
		return nil, err
	}
	s.targets = targets

	if err := s.resolveAnchors(); err != nil {
		return nil, err
	}

	// Warm the forward pointer cache for every file we will scan so
	// that resolvePointerAt hits the in-memory map instead of doing
	// pread syscalls during constructor extraction.
	s.buildPointerIndex(s.root)
	for _, target := range targets {
		if target.file != nil && target.file != s.root {
			s.buildPointerIndex(target.file)
		}
	}

	seen := make(map[fileAddrKey]bool)
	discovered := make([]discoveredClass, 0, 512)

	for _, target := range targets {
		candidates, err := s.collectCtorCandidates(target)
		if err != nil {
			return nil, err
		}
		for _, candidate := range candidates {
			key := fileAddrKey{file: candidate.owner, addr: candidate.fn.StartAddr}
			if seen[key] {
				continue
			}
			seen[key] = true

			classes, err := s.extractClassesFromCtor(candidate)
			if err != nil {
				return nil, err
			}
			discovered = append(discovered, classes...)
		}
	}

	if len(discovered) == 0 {
		return nil, nil
	}

	discovered = s.dedupe(discovered)
	s.repairClassesFromCallsite(discovered)
	s.recoverSuperMetaFromModInit(discovered)
	s.validateSuperMeta(discovered)
	s.clearDiscoveryCaches()
	if err := s.resolveVtables(discovered); err != nil {
		return nil, err
	}
	discovered = s.recoverMissingParentClasses(discovered)
	discovered = s.dedupe(discovered)
	if err := s.resolveVtables(discovered); err != nil {
		return nil, err
	}
	s.repairClassesFromCallsite(discovered)
	s.validateSuperMeta(discovered)
	discovered = filterClearlyBogusClasses(discovered)

	out := make([]Class, len(discovered))
	for i, class := range discovered {
		class.SuperIndex = -1
		out[i] = class.Class
	}
	s.fillSingleCandidateVtableGaps(out)

	sort.Slice(out, func(i, j int) bool {
		if out[i].Bundle != out[j].Bundle {
			return out[i].Bundle < out[j].Bundle
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].MetaPtr < out[j].MetaPtr
	})

	reindexSuperIndices(out)

	s.stats.discoveredClasses = len(out)
	for _, c := range out {
		if c.VtableAddr != 0 {
			s.stats.resolvedVtables++
		}
		if c.SuperMeta != 0 {
			s.stats.resolvedParentMeta++
		}
	}
	log.Infof("scan stats: classes=%d vtables=%d parent_meta=%d ptr_index=%d engines=%d ptr_hits=%d ptr_misses=%d",
		s.stats.discoveredClasses, s.stats.resolvedVtables,
		s.stats.resolvedParentMeta, s.stats.pointerIndexEntries,
		s.stats.engineCreations, s.stats.ptrCacheHits, s.stats.ptrCacheMisses)

	if s.cfg.ClassName == "" {
		return out, nil
	}

	filtered := make([]Class, 0, 1)
	for _, class := range out {
		if class.Name == s.cfg.ClassName {
			filtered = append(filtered, class)
		}
	}
	reindexSuperIndices(filtered)
	return filtered, nil
}

func (s *Scanner) fillSingleCandidateVtableGaps(classes []Class) {
	for i := range classes {
		if classes[i].VtableAddr != 0 || classes[i].MetaPtr == 0 {
			continue
		}
		owner := s.fileForVMAddr(classes[i].MetaPtr)
		if owner == nil {
			continue
		}
		getMetaCandidates := s.findClassGetMetaClassCandidates(owner, classes[i].MetaPtr)
		if len(getMetaCandidates) != 1 || getMetaCandidates[0] == 0 {
			continue
		}
		if vt := s.findVtableViaGetMetaClass(owner, classes[i].MetaVtableAddr, getMetaCandidates[0]); vt != 0 && !s.isLikelyAbstractVtable(owner, vt) {
			classes[i].VtableAddr = vt
		}
	}
}

func reindexSuperIndices(classes []Class) {
	metaIndex := make(map[uint64]int, len(classes))
	for i := range classes {
		classes[i].SuperIndex = -1
		if classes[i].MetaPtr != 0 {
			metaIndex[classes[i].MetaPtr] = i
		}
	}
	for i := range classes {
		if classes[i].SuperMeta == 0 {
			continue
		}
		if idx, ok := metaIndex[classes[i].SuperMeta]; ok {
			classes[i].SuperIndex = idx
		}
	}
}

func filterClearlyBogusClasses(classes []discoveredClass) []discoveredClass {
	out := classes[:0]
	for _, class := range classes {
		unknown := strings.HasPrefix(class.Name, "UnknownClass_")
		hasVtable := class.VtableAddr != 0
		hasAnyVtable := hasVtable || class.MetaVtableAddr != 0
		hasParent := class.SuperMeta != 0
		if unknown && class.Size == 0 {
			continue
		}
		if class.Size > maxReasonableClassSize && !hasVtable {
			continue
		}
		if !hasParent && !hasAnyVtable {
			continue
		}
		if unknown && !hasVtable {
			continue
		}
		if unknown && class.MetaVtableAddr == 0 {
			continue
		}
		if !unknown && !looksLikeRecoveredClassName(class.Name) && !hasAnyVtable {
			continue
		}
		out = append(out, class)
	}
	return out
}
