package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/swift"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/symbols"
	"github.com/pkg/errors"
)

type rangeEntry struct {
	StartAddr  uint64
	FileOffset uint64
	Size       uint32
}

type Patch interface {
	GetName() string
	GetKind() string
	GetImplOffset() uint64
	GetClientIndex() uint32
	GetPatchLocations() any
	GetGotLocations() any
}

type PatchableExport struct {
	Name             string
	Kind             string
	OffsetOfImpl     uint32
	ClientIndex      uint32
	PatchLocations   []CachePatchableLocationV1
	PatchLocationsV2 []CachePatchableLocationV2
	PatchLocationsV4 []CachePatchableLocationV4
}

func (pe PatchableExport) GetName() string {
	return pe.Name
}
func (pe PatchableExport) GetKind() string {
	return pe.Kind
}
func (pe PatchableExport) GetImplOffset() uint64 {
	return uint64(pe.OffsetOfImpl)
}
func (pe PatchableExport) GetClientIndex() uint32 {
	return pe.ClientIndex
}
func (pe PatchableExport) GetPatchLocations() any {
	if len(pe.PatchLocations) > 0 {
		return pe.PatchLocations
	} else if len(pe.PatchLocationsV2) > 0 {
		return pe.PatchLocationsV2
	} else if len(pe.PatchLocationsV4) > 0 {
		return pe.PatchLocationsV4
	} else {
		return nil
	}
}
func (pe PatchableExport) GetGotLocations() any {
	return nil
}

type PatchableGotExport struct {
	Name           string
	Kind           string
	OffsetOfImpl   uint32
	ImageIndex     uint32
	GotLocationsV3 []CachePatchableLocationV3
	GotLocationsV4 []CachePatchableLocationV4Got
}

func (pg PatchableGotExport) GetName() string {
	return pg.Name
}

func (pg PatchableGotExport) GetKind() string {
	return pg.Kind
}
func (pg PatchableGotExport) GetImplOffset() uint64 {
	return uint64(pg.OffsetOfImpl)
}
func (pg PatchableGotExport) GetClientIndex() uint32 {
	return 0
}
func (pg PatchableGotExport) GetPatchLocations() any {
	return nil
}
func (pg PatchableGotExport) GetGotLocations() any {
	if len(pg.GotLocationsV3) > 0 {
		return pg.GotLocationsV3
	} else if len(pg.GotLocationsV4) > 0 {
		return pg.GotLocationsV4
	} else {
		return nil
	}
}

type astate struct {
	mu sync.Mutex

	Deps           bool
	Got            bool
	Stubs          bool
	Helpers        bool
	Exports        bool
	ParsingExports bool
	Privates       bool
	Starts         bool
	ObjC           bool
	Slide          bool
	Swift          bool
}

func (a *astate) SetDeps(done bool) {
	a.mu.Lock()
	a.Deps = done
	a.mu.Unlock()
}
func (a *astate) IsDepsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Deps
}

func (a *astate) SetGot(done bool) {
	a.mu.Lock()
	a.Got = done
	a.mu.Unlock()
}
func (a *astate) IsGotDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Got
}

func (a *astate) SetHelpers(done bool) {
	a.mu.Lock()
	a.Helpers = done
	a.mu.Unlock()
}
func (a *astate) IsHelpersDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Helpers
}

func (a *astate) SetStubs(done bool) {
	a.mu.Lock()
	a.Stubs = done
	a.mu.Unlock()
}
func (a *astate) IsStubsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Stubs
}

func (a *astate) SetExports(done bool) {
	a.mu.Lock()
	a.Exports = done
	a.ParsingExports = false
	a.mu.Unlock()
}
func (a *astate) IsExportsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Exports
}
func (a *astate) BeginExports() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Exports || a.ParsingExports {
		return false
	}
	a.ParsingExports = true
	return true
}
func (a *astate) FinishExports(done bool) {
	a.mu.Lock()
	a.Exports = done
	a.ParsingExports = false
	a.mu.Unlock()
}

func (a *astate) SetPrivates(done bool) {
	a.mu.Lock()
	a.Privates = done
	a.mu.Unlock()
}
func (a *astate) IsPrivatesDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Privates
}

func (a *astate) SetStarts(done bool) {
	a.mu.Lock()
	a.Starts = done
	a.mu.Unlock()
}

func (a *astate) IsStartsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Starts
}

func (a *astate) SetObjC(done bool) {
	a.mu.Lock()
	a.ObjC = done
	a.mu.Unlock()
}

func (a *astate) IsObjcDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ObjC
}

func (a *astate) SetSlideInfo(done bool) {
	a.mu.Lock()
	a.Slide = done
	a.mu.Unlock()
}

func (a *astate) IsSlideInfoDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Slide
}

func (a *astate) SetSwift(done bool) {
	a.mu.Lock()
	a.Swift = done
	a.mu.Unlock()
}

func (a *astate) IsSwiftDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Swift
}

type analysis struct {
	State        astate
	Dependencies []string
	GotPointers  map[uint64]uint64
	SymbolStubs  map[uint64]uint64
	Helpers      map[uint64]uint64
}

// CacheImage represents a dyld dylib image.
type CacheImage struct {
	Name     string
	Index    uint32
	Info     CacheImageInfo
	Mappings *cacheMappingsWithSlideInfo
	CacheLocalSymbolsEntry64
	CacheImageInfoExtra
	CacheImageTextInfo
	Initializer    uint64
	DOFSectionAddr uint64
	DOFSectionSize uint32

	SlideInfo        slideInfo
	RangeEntries     []rangeEntry
	PatchableExports []Patch
	PatchableGOTs    []Patch
	LocalSymbols     []*CacheLocalSymbol64
	PublicSymbols    []*Symbol
	ObjC             objcInfo

	Analysis analysis

	cache *File // pointer back to the dyld cache that the image belongs to
	cuuid types.UUID
	CacheReader
	m     *macho.File
	pm    *macho.File // partial macho
	sinfo map[uint64]uint64

	// Mappings are immutable after registration; misses still consult the cache
	// so mappings registered later remain visible. Concurrent readers may share
	// this image, so hints and their advisory replacement order must be atomic.
	lastMapping     atomic.Pointer[CacheMappingWithSlideInfo]
	previousMapping atomic.Pointer[CacheMappingWithSlideInfo]
	previousUseful  atomic.Bool
}

// NewCacheReader returns a CacheReader that reads from r
// starting at offset off and stops with EOF after n bytes.
// It also stubs out the MachoReader required SeekToAddr and ReadAtAddr
func NewCacheReader(off int64, n int64, u types.UUID) CacheReader {
	return CacheReader{off, off, off + n, u}
}

// CacheReader implements Read, Seek, and ReadAt on a section
// of an underlying ReaderAt.
type CacheReader struct {
	base  int64
	off   int64
	limit int64
	ruuid types.UUID
}

// Free frees the underlying data so the GC can reclaim it.
func (i *CacheImage) Free() {
	i.m = nil
	i.pm = nil
	i.sinfo = nil
	i.RangeEntries = nil
	i.PatchableExports = nil
	i.PatchableGOTs = nil
	i.LocalSymbols = nil
	i.PublicSymbols = nil
	i.ObjC = objcInfo{}
	i.Analysis = analysis{}
}

func (i *CacheImage) Read(p []byte) (n int, err error) {
	if i.off >= i.limit {
		return 0, io.EOF
	}
	if max := i.limit - i.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = i.cache.r[i.ruuid].ReadAt(p, i.off)
	i.off += int64(n)
	return
}

func (i *CacheImage) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, fmt.Errorf("Seek: invalid whence")
	case io.SeekStart:
		offset += i.base
	case io.SeekCurrent:
		offset += i.off
	case io.SeekEnd:
		offset += i.limit
	}
	// if scinfo := i.cache.GetSubCacheInfo(i.ruuid); scinfo != nil {
	// 	if offset > int64(scinfo.CacheVMOffset) {
	// 		if next := i.cache.GetNextSubCacheInfo(i.ruuid); next != nil {
	// 			if offset <= int64(next.CacheVMOffset) {
	// 				i.ruuid = next.UUID
	// 				offset = offset - int64(scinfo.CacheVMOffset)
	// 			}
	// 		} else {
	// 			return 0, fmt.Errorf("Seek: invalid offset")
	// 		}
	// 	}
	// } else {
	if offset < i.base {
		return 0, fmt.Errorf("Seek: invalid offset")
	}
	// }
	i.off = offset
	return offset - i.base, nil
}

// linkeditUUID returns the UUID of the cache file holding this image's
// __LINKEDIT segment, which is the file its LC_SYMTAB offsets are relative to.
func (i *CacheImage) linkeditUUID() (types.UUID, error) {
	pm, err := i.GetPartialMacho()
	if err != nil {
		return types.UUID{}, err
	}
	le := pm.Segment("__LINKEDIT")
	if le == nil {
		return types.UUID{}, fmt.Errorf("failed to get __LINKEDIT segment")
	}
	uuid, _, err := i.cache.GetOffset(le.Addr)
	return uuid, err
}

func (i *CacheImage) ReadAt(p []byte, off int64) (n int, err error) {
	if i.ruuid, err = i.linkeditUUID(); err != nil {
		return -1, err
	}
	if off < 0 || off >= i.limit-i.base {
		return 0, io.EOF
	}
	off += i.base
	if max := i.limit - off; int64(len(p)) > max {
		p = p[0:max]
		n, err = i.cache.r[i.ruuid].ReadAt(p, off)
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	// fmt.Printf("image.ReadAt: cache_uuid=%s, uuid=%s, off=%#x\n", i.cuuid, uuid, off)
	return i.cache.r[i.ruuid].ReadAt(p, off)
}

func (i *CacheImage) SeekToAddr(addr uint64) error {
	uuid, offset, err := i.cache.GetOffset(addr)
	if err != nil {
		return err
	}
	i.ruuid = uuid
	i.Seek(int64(offset), io.SeekStart)
	return nil
}

// ReadAtAddr reads data at a given virtual address
func (i *CacheImage) ReadAtAddr(buf []byte, addr uint64) (int, error) {
	uuid, off, err := i.cache.GetOffset(addr)
	if err != nil {
		return -1, err
	}
	i.ruuid = uuid
	// fmt.Printf("image.ReadAt: cache_uuid=%s, uuid=%s, off=%#x\n", i.cuuid, uuid, off)
	return i.cache.r[i.ruuid].ReadAt(buf, int64(off))
}

// GetOffset returns the offset for a given virtual address
func (i *CacheImage) GetOffset(address uint64) (uint64, error) {
	u, o, err := i.cache.GetOffset(address)
	if err != nil {
		return 0, err
	}
	i.ruuid = u
	// fmt.Printf("prim_uuid=%s, cache_uuid=%s, uuid=%s, off=%#x\n", i.cache.UUID, i.cuuid, u, o)
	return o, nil
}

// GetVMAddress returns the virtual address for a given offset
func (i *CacheImage) GetVMAddress(offset uint64) (uint64, error) {
	return i.cache.GetVMAddressForUUID(i.cuuid, offset)
}

func (i *CacheImage) SlidePointer(addr uint64) uint64 {
	return i.slidePointer(addr, i.cache.mappingForVMAddress)
}

// slidePointer accepts the fallback lookup so tests can count registry scans.
func (i *CacheImage) slidePointer(addr uint64, lookup func(uint64) (types.UUID, *CacheMappingWithSlideInfo)) uint64 {
	if addr == 0 {
		return addr
	}
	// check if addr is in the cache (not slid)
	last := i.lastMapping.Load()
	if last != nil && last.Address <= addr && addr < last.Address+last.Size {
		if i.previousUseful.Load() {
			i.previousUseful.Store(false)
		}
		return addr
	}
	if previous := i.previousMapping.Load(); previous != nil && previous.Address <= addr && addr < previous.Address+previous.Size {
		if !i.previousUseful.Load() {
			i.previousUseful.Store(true)
		}
		return addr
	}
	if _, mapping := lookup(addr); mapping != nil {
		// Keep the most recently useful hint when installing a new mapping.
		// Concurrent calls can lose locality, but every hit checks its range.
		if !i.previousUseful.Load() {
			i.previousMapping.Store(last)
		}
		i.lastMapping.Store(mapping)
		i.previousUseful.Store(false)
		return addr
	}
	// try and slide the encoded pointer
	return i.cache.SlideInfo.SlidePointer(addr)
}

func (i *CacheImage) relativeSelectorBase() (uint64, error) {
	return i.cache.relativeSelectorBase()
}

func (i *CacheImage) partialRelativeSelectorBase() (uint64, error) {
	// resolving the selector base opens libobjc; never re-enter from libobjc itself
	// (matched case-insensitively, like cacheImageByName)
	if strings.EqualFold(filepath.Base(i.Name), libObjCName) {
		return 0, nil
	}
	return i.relativeSelectorBase()
}

func (f *File) relativeSelectorBase() (uint64, error) {
	f.rsBaseOnce.Do(func() {
		if _, err := f.libObjCImage(); err != nil {
			if !errors.Is(err, ErrImageNotFound) {
				f.rsBaseErr = err
			}
			return
		}

		opt, err := f.GetOptimizations()
		if err != nil {
			f.rsBaseErr = err
			return
		}

		f.rsBase = f.relativeSelectorBaseForOptimization(opt)
	})

	return f.rsBase, f.rsBaseErr
}

func (f *File) relativeSelectorBaseForOptimization(opt Optimization) uint64 {
	base := opt.RelativeMethodListsBaseAddress(f.objcOptRoAddr)
	if _, ok := opt.(*ObjCOptimizationHeader); ok {
		base += f.Headers[f.UUID].SharedRegionStart // TODO: can I trust SharedRegionStart? should this be Mapping[0].Address?
	}
	return base
}

// GetMacho parses dyld image as a MachO (slow)
func (i *CacheImage) GetMacho() (*macho.File, error) {
	if i.m != nil {
		return i.m, nil
	}

	offset, err := i.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}

	rsBase, err := i.relativeSelectorBase()
	if err != nil {
		return nil, err
	}

	i.CacheReader = NewCacheReader(0, 1<<63-1, i.cuuid)
	vma := types.VMAddrConverter{
		Converter: func(addr uint64) uint64 {
			return i.SlidePointer(addr)
		},
		VMAddr2Offet: func(address uint64) (uint64, error) {
			return i.GetOffset(address)
		},
		Offet2VMAddr: func(offset uint64) (uint64, error) {
			return i.GetVMAddress(offset)
		},
	}
	i.m, err = macho.NewFile(io.NewSectionReader(i.cache.r[i.cuuid], int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
		Offset:               int64(offset),
		SectionReader:        types.NewCustomSectionReader(i.cache.r[i.cuuid], &vma, 0, 1<<63-1),
		CacheReader:          i,
		VMAddrConverter:      vma,
		RelativeSelectorBase: rsBase,
		StringTableLookup: func(off int64, size uint64) (func(uint64) string, error) {
			uuid, err := i.linkeditUUID()
			if err != nil {
				return nil, err
			}
			return i.cache.stringTableLookup(uuid, off, size)
		},
	})
	if err != nil {
		return nil, err
	}

	return i.m, nil
}

// GetPartialMacho parses dyld image as a partial MachO (fast)
func (i *CacheImage) GetPartialMacho() (*macho.File, error) {
	if i.pm != nil {
		return i.pm, nil
	}
	offset, err := i.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}
	i.CacheReader = NewCacheReader(0, 1<<63-1, i.cuuid)
	var rsBase uint64
	if base, err := i.partialRelativeSelectorBase(); err == nil {
		rsBase = base
	}
	vma := types.VMAddrConverter{
		Converter: func(addr uint64) uint64 {
			return i.SlidePointer(addr)
		},
		VMAddr2Offet: func(address uint64) (uint64, error) {
			return i.GetOffset(address)
		},
		Offet2VMAddr: func(offset uint64) (uint64, error) {
			return i.GetVMAddress(offset)
		},
	}
	i.pm, err = macho.NewFile(io.NewSectionReader(i.cache.r[i.cuuid], int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
		LoadIncluding: []types.LoadCmd{
			types.LC_SEGMENT,
			types.LC_SEGMENT_64,
			types.LC_DYLD_INFO,
			types.LC_DYLD_INFO_ONLY,
			types.LC_ID_DYLIB,
			types.LC_UUID,
			types.LC_BUILD_VERSION,
			types.LC_SOURCE_VERSION,
			types.LC_SUB_FRAMEWORK,
			types.LC_SUB_CLIENT,
			types.LC_REEXPORT_DYLIB,
			types.LC_LOAD_DYLIB,
			types.LC_LOAD_WEAK_DYLIB,
			types.LC_LOAD_UPWARD_DYLIB},
		Offset:               int64(offset),
		SectionReader:        types.NewCustomSectionReader(i.cache.r[i.cuuid], &vma, 0, 1<<63-1),
		CacheReader:          i,
		VMAddrConverter:      vma,
		RelativeSelectorBase: rsBase,
	})
	if err != nil {
		return nil, err
	}

	return i.pm, nil
}

// Analyze analyzes an image by parsing it's symbols, stubs and GOT
func (i *CacheImage) Analyze() error {

	if err := i.ParseObjC(); err != nil {
		log.Errorf("failed to parse objc data for image %s: %v", filepath.Base(i.Name), err)
		// return fmt.Errorf("failed to parse objc data for image %s: %v", filepath.Base(i.Name), err) FIXME: should this error out?
	}

	if err := i.ParsePublicSymbols(false); err != nil {
		log.Errorf("failed to parse exported symbols for %s: %w", i.Name, err)
	}

	if err := i.ParseLocalSymbols(false); err != nil {
		if !errors.Is(err, ErrNoLocals) {
			return fmt.Errorf("failed to parse local symbols for %s: %w", i.Name, err)
		}
	}

	if !i.cache.IsArm64() {
		utils.Indent(log.Warn, 2)("image analysis of stubs and GOT only works on arm64 architectures")
	}

	if !i.Analysis.State.IsSwiftDone() {
		// TODO: add more swift runtime metadata
		if i.cache.IsArm64() {
			if err := i.ParseSwiftStrings(); err != nil {
				return fmt.Errorf("failed to parse swift strings for %s: %w", i.Name, err)
			}
		}
		i.Analysis.State.SetSwift(true)
	}

	if !i.Analysis.State.IsSlideInfoDone() {
		if err := i.ParseSlideInfo(); err != nil {
			return fmt.Errorf("failed to parse slide info for %s: %w", i.Name, err)
		}
	}

	if !i.Analysis.State.IsHelpersDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s symbol stub helpers", i.Name)
		if err := i.ParseHelpers(); err != nil {
			if !errors.Is(err, macho.ErrMachOSectionNotFound) {
				return fmt.Errorf("failed to parse stub helpers for %s: %w", i.Name, err)
			}
		}

		for _, start := range slices.Sorted(maps.Keys(i.Analysis.Helpers)) {
			target := i.Analysis.Helpers[start]
			if slide, ok := i.sinfo[start]; ok {
				target = slide
			}
			if symName, ok := i.cache.AddressToSymbol.Get(target); ok {
				i.cache.AddressToSymbol.Set(start, fmt.Sprintf("%s%s", symbols.PrefixStubHelper, symName))
			} else {
				i.cache.AddressToSymbol.Set(start, fmt.Sprintf("%s%x", symbols.PrefixStubHelper, target))
			}
		}
	}

	if !i.Analysis.State.IsGotDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s global offset table", i.Name)
		if err := i.ParseGOT(); err != nil {
			return fmt.Errorf("failed to parse GOT for %s: %w", i.Name, err)
		}

		for _, entry := range slices.Sorted(maps.Keys(i.Analysis.GotPointers)) {
			target := i.Analysis.GotPointers[entry]
			if slide, ok := i.sinfo[entry]; ok {
				target = slide
			}
			if symName, ok := i.cache.AddressToSymbol.Get(target); ok {
				i.cache.AddressToSymbol.Set(entry, fmt.Sprintf("%s%s", symbols.PrefixGot, symName))
			} else {
				if img, err := i.cache.GetImageContainingVMAddr(target); err == nil {
					if err := img.Analyze(); err != nil {
						// FIXME: return fmt.Errorf("failed parse GOT target %#x: failed to analyze image %s: %w", target, img.Name, err)
						log.Errorf("failed parse GOT target %#x: failed to analyze image %s: %w", target, img.Name, err)
					}
					if symName, ok := i.cache.AddressToSymbol.Get(target); ok {
						i.cache.AddressToSymbol.Set(entry, fmt.Sprintf("%s%s", symbols.PrefixGot, symName))
					} else if laptr, ok := i.Analysis.GotPointers[target]; ok {
						if symName, ok := i.cache.AddressToSymbol.Get(laptr); ok {
							i.cache.AddressToSymbol.Set(entry, fmt.Sprintf("%s%s", symbols.PrefixGot, symName))
						}
					} else {
						utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for GOT entry %#x => %#x in %s", entry, target, img.Name))
						i.cache.AddressToSymbol.Set(entry, fmt.Sprintf("%s%x ; %s", symbols.PrefixGotFallback, target, filepath.Base(img.Name)))
					}
				} else {
					i.cache.AddressToSymbol.Set(entry, fmt.Sprintf("%s%x", symbols.PrefixGotFallback, target))
				}
			}
		}
	}

	if !i.Analysis.State.IsStubsDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s symbol stubs", i.Name)
		if err := i.ParseStubs(); err != nil {
			return fmt.Errorf("failed to parse stubs for %s: %w", i.Name, err)
		}

		for _, stub := range slices.Sorted(maps.Keys(i.Analysis.SymbolStubs)) {
			target := i.Analysis.SymbolStubs[stub]
			if slide, ok := i.sinfo[stub]; ok {
				target = slide
			}
			if symName, ok := i.cache.AddressToSymbol.Get(target); ok {
				if !strings.HasPrefix(symName, symbols.PrefixJump) {
					i.cache.AddressToSymbol.Set(stub, symbols.PrefixJump+strings.TrimPrefix(symName, symbols.PrefixStubHelper))
				} else {
					i.cache.AddressToSymbol.Set(stub, symName)
				}
			} else {
				img, err := i.cache.GetImageContainingVMAddr(target)
				if err != nil {
					return fmt.Errorf("failed to find image containing stub target %#x: %w", target, err)
				}
				if err := img.Analyze(); err != nil {
					return fmt.Errorf("failed to lookup symbol stub target %#x: failed to analyze image %s: %w", target, img.Name, err)
				}
				if symName, ok := i.cache.AddressToSymbol.Get(target); ok {
					i.cache.AddressToSymbol.Set(stub, fmt.Sprintf("%s%s", symbols.PrefixJump, symName))
				} else {
					utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for stub %#x => %#x in %s", stub, target, img.Name))
					i.cache.AddressToSymbol.Set(stub, fmt.Sprintf("%s%x ; %s", symbols.PrefixStubFallback, target, filepath.Base(img.Name)))
				}
			}
		}
	}

	if !i.Analysis.State.IsStartsDone() {
		i.ParseStarts()
	}

	return nil
}

// ParseSlideInfo parse the shared_cache slide info corresponding to the MachO
// SegmentRebases returns the cache rebases that land inside seg's file contents
func (i *CacheImage) SegmentRebases(seg *macho.Segment) ([]Rebase, error) {
	if seg.Filesz == 0 {
		return nil, nil
	}
	uuid, mapping, err := i.cache.GetMappingForVMAddress(seg.Addr)
	if err != nil {
		return nil, err
	}
	if mapping.SlideInfoOffset == 0 {
		return nil, nil
	}
	offset := seg.Addr - mapping.Address
	if seg.Filesz > mapping.Size-offset {
		return nil, fmt.Errorf("segment %s: file size %#x exceeds the %#x bytes left in its mapping",
			seg.Name, seg.Filesz, mapping.Size-offset)
	}
	cached, err := i.cache.loadSlideInfo(uuid, mapping, false)
	if err != nil {
		return nil, err
	}
	if cached.header == nil {
		return nil, fmt.Errorf("mapping %s has no supported slide info", mapping.Name)
	}
	pageSize := uint64(cached.header.GetPageSize())
	if pageSize == 0 {
		return nil, fmt.Errorf("mapping %s has zero slide page size", mapping.Name)
	}
	start, end := slidePagesForRange(offset, seg.Filesz, pageSize)
	rebases, err := i.cache.GetRebaseInfoForPages(uuid, mapping, start, end)
	if err != nil {
		return nil, err
	}
	// slide pages are shared with neighboring segments, so keep only pointers that
	// lie entirely inside this segment's file contents
	pointerSize := uint64(8)
	if !i.cache.Is64bit() {
		pointerSize = 4
	}
	if seg.Filesz < pointerSize {
		return nil, nil
	}
	lastPointer := seg.Filesz - pointerSize
	var inSegment []Rebase
	for _, rebase := range rebases {
		if rebase.CacheVMAddress >= seg.Addr && rebase.CacheVMAddress-seg.Addr <= lastPointer {
			inSegment = append(inSegment, rebase)
		}
	}
	return inSegment, nil
}

func (i *CacheImage) ParseSlideInfo() error {

	i.sinfo = make(map[uint64]uint64)

	m, err := i.GetPartialMacho()
	if err != nil {
		return err
	}

	for _, seg := range m.Segments() {
		rs, err := i.SegmentRebases(seg)
		if err != nil {
			return err
		}
		for _, r := range rs {
			i.sinfo[r.Pointer.Raw()] = r.Target
		}
	}

	i.Analysis.State.SetSlideInfo(true)

	return nil
}

// GetSlideInfo returns a slide info map for the image
func (i *CacheImage) GetSlideInfo() (map[uint64]uint64, error) {
	if !i.Analysis.State.IsSlideInfoDone() {
		if err := i.ParseSlideInfo(); err != nil {
			return nil, err
		}
	}
	return i.sinfo, nil
}

// ParseStarts parse function starts in MachO
func (i *CacheImage) ParseStarts() {
	if i.m != nil {
		for _, fn := range i.m.GetFunctions() {
			if ok := i.cache.AddressToSymbol.Has(fn.StartAddr); !ok {
				i.cache.AddressToSymbol.Set(fn.StartAddr, fmt.Sprintf("sub_%x", fn.StartAddr))
			}
		}
	}
	i.Analysis.State.SetStarts(true)
}

// ParseObjC parse ObjC runtime for MachO image
func (i *CacheImage) ParseObjC() error {
	if !i.Analysis.State.IsObjcDone() {
		if err := i.cache.CFStringsForImage(i.Name); err != nil {
			return fmt.Errorf("failed to parse objc cfstrings for image %s: %v", filepath.Base(i.Name), err)
		}
		// TODO: add objc methods in the -[Class sel:] form
		if err := i.cache.MethodsForImage(i.Name); err != nil {
			return fmt.Errorf("failed to parse objc methods for image %s: %v", filepath.Base(i.Name), err)
		}
		if strings.Contains(i.Name, libObjCName) {
			if _, err := i.cache.GetAllObjCSelectors(false); err != nil {
				return fmt.Errorf("failed to parse objc all selectors: %v", err)
			}
		} else {
			if err := i.cache.SelectorsForImage(i.Name); err != nil {
				return fmt.Errorf("failed to parse objc selectors for image %s: %v", filepath.Base(i.Name), err)
			}
		}
		if err := i.cache.ClassesForImage(i.Name); err != nil {
			return fmt.Errorf("failed to parse objc classes for image %s: %v", filepath.Base(i.Name), err)
		}
		if err := i.cache.CategoriesForImage(i.Name); err != nil {
			return fmt.Errorf("failed to parse objc categories for image %s: %v", filepath.Base(i.Name), err)
		}
		if err := i.cache.ProtocolsForImage(i.Name); err != nil {
			return fmt.Errorf("failed to parse objc protocols for image %s: %v", filepath.Base(i.Name), err)
		}
		if err := i.cache.GetObjCStubsForImage(i.Name); err != nil && !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return fmt.Errorf("failed to parse objc stubs for image %s: %v", filepath.Base(i.Name), err)
		}
		i.Analysis.State.SetObjC(true)
	}
	return nil
}

// ParseGOT parse global offset table in MachO
func (i *CacheImage) ParseGOT() error {

	i.Analysis.GotPointers = make(map[uint64]uint64)

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}
	defer m.Close()

	for _, secName := range []string{"__got", "__auth_got", "__auth_ptr"} {
		for _, sec := range m.Sections {
			if (sec.Seg == "__AUTH_CONST" || sec.Seg == "__DATA_CONST") && sec.Name == secName {
				dat := make([]byte, sec.Size)
				if _, err := i.ReadAtAddr(dat, sec.Addr); err != nil {
					return fmt.Errorf("failed to read GOT section %s: %v", secName, err)
				}
				ptrs := make([]uint64, sec.Size/8)
				if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
					return fmt.Errorf("failed to read %s.%s got pointers; %v", sec.Seg, sec.Name, err)
				}
				for idx, ptr := range ptrs {
					if ptr != 0 {
						i.Analysis.GotPointers[sec.Addr+uint64(idx*8)] = i.cache.SlideInfo.SlidePointer(ptr)
					}
				}
			}
		}
	}

	i.Analysis.State.SetGot(true)

	return nil
}

// ParseStubs parse symbol stubs in MachO
func (i *CacheImage) ParseStubs() error {

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}

	i.Analysis.SymbolStubs = make(map[uint64]uint64)
	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {
			dat := make([]byte, sec.Size)
			if _, err := i.ReadAtAddr(dat, sec.Addr); err != nil {
				return err
			}
			stubs, err := disass.ParseStubsASM(dat, sec.Addr, func(u uint64) (uint64, error) {
				return i.cache.ReadPointerAtAddress(u)
			})
			if err != nil {
				return err
			}
			for k, v := range stubs {
				i.Analysis.SymbolStubs[k] = i.cache.SlideInfo.SlidePointer(v)
			}
		}
	}

	i.Analysis.State.SetStubs(true)

	return nil
}

// ResolveStubAtAddr checks if addr is in a stub section (__stubs, __auth_stubs)
// and if so, uses ParseStubs to find the target, then resolves it to a symbol.
// Returns the target address and symbol name, or an error if not a stub or unresolvable.
func (i *CacheImage) ResolveStubAtAddr(addr uint64) (uint64, string, error) {
	if !i.Analysis.State.IsStubsDone() {
		if err := i.ParseStubs(); err != nil {
			return 0, "", err
		}
	}
	target, ok := i.Analysis.SymbolStubs[addr]
	if !ok {
		return 0, "", fmt.Errorf("address %#x is not a known stub", addr)
	}
	// Resolve target symbol: search the target image's symtab + local symbols
	if img, err := i.cache.GetImageContainingTextAddr(target); err == nil {
		tm, err := img.GetMacho()
		if err == nil {
			defer tm.Close()
			if syms, err := tm.FindAddressSymbols(target); err == nil {
				for _, s := range syms {
					if s.Name != "<redacted>" && s.Name != "" {
						return target, s.Name, nil
					}
				}
			}
			if name, err := img.FindLocalSymbolAtAddr(target); err == nil && name != "" {
				return target, name, nil
			}
		}
	}
	return target, "", fmt.Errorf("stub at %#x -> %#x: target symbol not found", addr, target)
}

// ParseHelpers parse symbol stub helpers in MachO
func (i *CacheImage) ParseHelpers() error {

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}

	i.Analysis.Helpers, err = disass.ParseHelpersASM(m)
	if err != nil {
		return err
	}

	i.Analysis.State.SetHelpers(true)

	return nil
}

func (i *CacheImage) ParseSwiftStrings() error {

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}

	text := m.Section("__TEXT", "__text")
	if text == nil {
		return fmt.Errorf("no __TEXT.__text section found")
	}

	data, err := text.Data()
	if err != nil {
		return fmt.Errorf("failed to get __TEXT.__text data: %v", err)
	}

	engine := disass.NewMachoDisass(m, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
		Middle:       text.Addr + text.Size,
	})

	strs, err := engine.FindSwiftStrings()
	if err != nil {
		return fmt.Errorf("failed to find swift strings: %v", err)
	}
	for addr, str := range strs {
		if len(str) > 0 {
			i.cache.AddressToSymbol.Set(addr, fmt.Sprintf("%v", str))
		}
	}

	return nil
}

// localNlistBuffer reads this image's entries from the cache's local-symbol nlist table
// and returns the cache file holding them and the serialized entry size.
// When section metadata is available, entries outside their section are discarded.
func (i *CacheImage) localNlistBuffer() (types.UUID, []byte, int, error) {
	uuid := i.cache.UUID
	if i.cache.IsDyld4 {
		uuid = i.cache.symUUID
	}
	if i.cache.Headers[uuid].LocalSymbolsOffset == 0 {
		return uuid, nil, 0, ErrNoLocals
	}
	count := int(i.cache.Images[i.Index].NlistCount)
	size := nlistSize(i.cache.Is64bit())
	offset := int64(i.cache.LocalSymInfo.NListFileOffset) +
		int64(i.cache.Images[i.Index].NlistStartIndex)*int64(size)
	buf := make([]byte, count*size)
	if _, err := i.cache.r[uuid].ReadAt(buf, offset); err != nil {
		return uuid, nil, 0, fmt.Errorf("failed to read nlist entries for %s: %w", filepath.Base(i.Name), err)
	}
	if len(buf) == 0 {
		return uuid, buf, size, nil
	}
	m, err := i.GetPartialMacho()
	if err != nil {
		log.Warnf("failed to get MachO for image %s; keeping unfiltered local symbols: %v", i.Name, err)
		return uuid, buf, size, nil
	}
	kept, skipped := 0, 0
	for off := 0; off < len(buf); off += size {
		nlist := parseNlist(buf[off : off+size])
		// Section ordinals are 1-based; zero is NO_SECT. Cache builders can
		// empty a section while leaving its old local symbols in .symbols.
		sect := int(nlist.Sect)
		if sect != 0 {
			if sect > len(m.Sections) {
				skipped++
				continue
			}
			section := m.Sections[sect-1]
			// Subtract only after checking the lower bound to avoid overflow
			// when the section's address and size are added.
			if nlist.Value < section.Addr || nlist.Value-section.Addr >= section.Size {
				skipped++
				continue
			}
		}
		copy(buf[kept:kept+size], buf[off:off+size])
		kept += size
	}
	if skipped > 0 {
		log.Debugf("skipped %d local symbols outside their section range or referring to nonexistent sections in %s", skipped, filepath.Base(i.Name))
	}
	return uuid, buf[:kept], size, nil
}

// FindLocalSymbolAtAddr searches only this image's DSC local symbol nlist entries
// for a symbol at the given address, without populating the full a2s cache.
// Returns the symbol name or an error if not found.
func (i *CacheImage) FindLocalSymbolAtAddr(addr uint64) (string, error) {
	uuid, nlistBuf, size, err := i.localNlistBuffer()
	if err != nil {
		return "", err
	}
	if len(nlistBuf) == 0 {
		return "", fmt.Errorf("no local symbols for image")
	}
	strPoolBase := int64(i.cache.LocalSymInfo.StringsFileOffset)
	strPoolSize := int64(i.cache.LocalSymInfo.StringsSize)
	for off := 0; off < len(nlistBuf); off += size {
		nlist := parseNlist(nlistBuf[off : off+size])
		if nlist.Value == addr {
			s, _, err := readStringPool(i.cache.r[uuid], strPoolBase, strPoolSize, int64(nlist.Name), nil)
			if err != nil {
				return "", err
			}
			return s, nil
		}
	}
	return "", fmt.Errorf("no local symbol at %#x", addr)
}

// ResolveLocalSymbolNames parses the image's local symbols and rewrites the
// "<redacted>" entries in m's symbol table with their real names, optionally
// demangling every Swift and C++ name, so Swift metadata dumps can label
// methods and witnesses.
func (i *CacheImage) ResolveLocalSymbolNames(m *macho.File, demangleNames bool) {
	i.ParseLocalSymbols(false)
	if m.Symtab == nil {
		return
	}
	for idx, sym := range m.Symtab.Syms {
		if sym.Value != 0 && sym.Name == "<redacted>" {
			if name, ok := i.cache.AddressToSymbol.Get(sym.Value); ok {
				m.Symtab.Syms[idx].Name = name
			}
		}
		if demangleNames {
			if swift.IsMangled(sym.Name) {
				m.Symtab.Syms[idx].Name, _ = swift.Demangle(sym.Name)
			} else if strings.HasPrefix(sym.Name, "__Z") || strings.HasPrefix(sym.Name, "_Z") {
				m.Symtab.Syms[idx].Name = demangle.Do(sym.Name, false, false)
			}
		}
	}
}

// ParseLocalSymbols parses and caches, with the option to dump, all the local/private symbols for an image
func (i *CacheImage) ParseLocalSymbols(dump bool) error {

	if !i.Analysis.State.IsPrivatesDone() {

		uuid, nlistBuf, size, err := i.localNlistBuffer()
		if errors.Is(err, ErrNoLocals) {
			i.Analysis.State.SetPrivates(true) // TODO: does this have any bad side-effects ?
			return fmt.Errorf("failed to parse local syms for image %s: %w", filepath.Base(i.Name), err)
		}
		if err != nil {
			return err
		}
		if len(nlistBuf) == 0 {
			i.Analysis.State.SetPrivates(true)
			return nil
		}

		// Read strings from string pool (reuse buffer across iterations)
		strPoolBase := int64(i.cache.LocalSymInfo.StringsFileOffset)
		strPoolSize := int64(i.cache.LocalSymInfo.StringsSize)
		var (
			strBuf  = make([]byte, 512)
			s       string
			readErr error
		)

		for off := 0; off < len(nlistBuf); off += size {
			nlist := parseNlist(nlistBuf[off : off+size])

			s, strBuf, readErr = readStringPool(i.cache.r[uuid], strPoolBase, strPoolSize, int64(nlist.Name), strBuf)
			if readErr != nil {
				log.Errorf("failed to read local symbol name for image %s: %v", filepath.Base(i.Name), readErr)
				continue
			}

			i.cache.AddressToSymbol.Set(nlist.Value, s)
			i.cache.Images[i.Index].LocalSymbols = append(i.cache.Images[i.Index].LocalSymbols, &CacheLocalSymbol64{
				Name:         s,
				Nlist64:      nlist,
				FoundInDylib: i.Name,
			})

			if dump {
				m, err := i.GetPartialMacho()
				if err != nil {
					return err
				}
				fmt.Println(CacheLocalSymbol64{
					Name:         s,
					Nlist64:      nlist,
					Macho:        m,
					FoundInDylib: filepath.Base(i.Name),
				}.String(utils.ColorAllowed()))
			}
		}

		sort.Slice(i.LocalSymbols, func(j, k int) bool {
			return i.LocalSymbols[j].Name < i.LocalSymbols[k].Name
		})

		i.Analysis.State.SetPrivates(true)
	}

	return nil
}

// GetLocalSymbol returns the local symbol matching the given name
func (i *CacheImage) GetLocalSymbol(name string) (*CacheLocalSymbol64, error) {
	i.ParseLocalSymbols(false)

	idx := sort.Search(len(i.LocalSymbols), func(idx int) bool { return i.LocalSymbols[idx].Name >= name })
	if idx < len(i.LocalSymbols) && i.LocalSymbols[idx].Name == name {
		return i.LocalSymbols[idx], nil
	}

	return nil, fmt.Errorf("local symbol %s not found in image %s", name, filepath.Base(i.Name))
}

// GetLocalSymbolsAsMachoSymbols converts all the dylibs private symbols into MachO symtab public symbols
func (i *CacheImage) GetLocalSymbolsAsMachoSymbols() []macho.Symbol {
	var syms []macho.Symbol
	for _, lsym := range i.LocalSymbols {
		syms = append(syms, macho.Symbol{
			Name:  lsym.Name,
			Type:  lsym.Type,
			Sect:  lsym.Sect,
			Desc:  lsym.Desc,
			Value: lsym.Value,
		})
	}
	return syms
}

// A resolved re-export names an address owned by another image.
func shouldPublishTrieAddress(sym trie.TrieExport) bool {
	return !sym.Flags.ReExport()
}

// Undefined values and indirect string-table offsets are not symbol addresses.
func shouldPublishSymtabAddress(sym macho.Symbol) bool {
	return !sym.Type.IsUndefinedSym() && !sym.Type.IsIndirectSym()
}

// ParsePublicSymbols parses and caches, with the option to dump, all the exports, symtab and dyld_info symbols in the image/dylib
func (i *CacheImage) ParsePublicSymbols(dump bool) error {

	if i.Analysis.State.BeginExports() {
		defer func() {
			if !i.Analysis.State.IsExportsDone() {
				i.Analysis.State.FinishExports(false)
			}
		}()

		var w *tabwriter.Writer
		if dump {
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		}
		// try to parse exports from the cache's export trie or the dylib's LC_DYLD_EXPORTS_TRIE
		if syms, err := i.cache.GetExportTrieSymbols(i); err == nil {
			for _, sym := range syms {
				if err := i.resolveReExport(&sym); err != nil {
					return err
				}
				if dump {
					fmt.Fprintf(w, "%s\n", sym)
				} else {
					if shouldPublishTrieAddress(sym) {
						i.cache.AddressToSymbol.Set(sym.Address, sym.Name)
					}
					i.PublicSymbols = append(i.PublicSymbols, &Symbol{
						Name:    sym.Name,
						Address: sym.Address,
						Type:    sym.Type(),
						Kind:    EXPORT,
					})
				}
			}
			if dump {
				w.Flush()
			}
		}
		// try to parse the dylib's symbol table
		m, err := i.GetMacho()
		if err != nil {
			return err
		}
		for _, sym := range m.Symtab.Syms {
			if sym.Name == "<redacted>" {
				continue
			}
			// TODO: Handle ReExports
			var sec string
			if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
				sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
			}
			if dump {
				fmt.Fprintf(w, "%#09x:\t(%s)\t%s\n", sym.Value, sym.Type.String(sec), sym.Name)
			} else {
				if shouldPublishSymtabAddress(sym) {
					i.cache.AddressToSymbol.Set(sym.Value, sym.Name)
				}
				i.PublicSymbols = append(i.PublicSymbols, &Symbol{
					Name:    sym.Name,
					Address: sym.Value,
					Type:    sym.Type.String(sec),
					Kind:    SYMTAB,
				})
			}
		}
		if dump {
			w.Flush()
		}
		// try to parse LC_DYLD_INFO binds
		if binds, err := m.GetBindInfo(); err == nil {
			for _, bind := range binds {
				if dump {
					fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.SegOffset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
				} else {
					i.cache.AddressToSymbol.Set(bind.Start+bind.SegOffset, bind.Name)
					i.PublicSymbols = append(i.PublicSymbols, &Symbol{
						Name:    bind.Name,
						Address: bind.Start + bind.SegOffset,
						Type:    fmt.Sprintf("%s|%s", bind.Kind, bind.Dylib),
						Kind:    BIND,
					})
				}
			}
			if dump {
				w.Flush()
			}
		}
		// try to parse LC_DYLD_INFO rebases TODO: this is slide info and not sym info
		// if rebases, err := m.GetRebaseInfo(); err == nil {
		// 	for _, rebase := range rebases {
		// 		rebase.
		// 	}
		// }
		// try to parse LC_DYLD_INFO exports TODO: is this redundant???
		if exports, err := m.GetExports(); err == nil {
			for _, export := range exports {
				if err := i.resolveReExport(&export); err != nil {
					return err
				}
				if dump {
					fmt.Fprintf(w, "%s\n", export)
				} else {
					i.cache.AddressToSymbol.Set(export.Address, export.Name)
					i.PublicSymbols = append(i.PublicSymbols, &Symbol{
						Name:    export.Name,
						Address: export.Address,
						Type:    export.Type(),
						Kind:    EXPORT,
					})
				}
			}
			if dump {
				w.Flush()
			}
		}

		sort.Slice(i.PublicSymbols, func(j, k int) bool {
			return i.PublicSymbols[j].Name < i.PublicSymbols[k].Name
		})

		i.Analysis.State.FinishExports(true)
	}

	return nil
}

// returns the public symbol matching the given name
func (i *CacheImage) GetPublicSymbol(name string) (*Symbol, error) {
	if err := i.ParsePublicSymbols(false); err != nil {
		return nil, err
	}

	if !i.Analysis.State.IsExportsDone() {
		for _, sym := range i.PublicSymbols {
			if sym.Name == name {
				return sym, nil
			}
		}
		return nil, fmt.Errorf("public symbols for image %s are still being parsed", filepath.Base(i.Name))
	}

	idx := sort.Search(len(i.PublicSymbols), func(idx int) bool { return i.PublicSymbols[idx].Name >= name })
	if idx < len(i.PublicSymbols) && i.PublicSymbols[idx].Name == name {
		return i.PublicSymbols[idx], nil
	}

	return nil, fmt.Errorf("public symbol %s not found in image %s", name, filepath.Base(i.Name))
}

func (i *CacheImage) resolveReExport(export *trie.TrieExport) error {
	if !export.Flags.ReExport() {
		return nil
	}

	m, err := i.GetPartialMacho()
	if err != nil {
		return err
	}

	export.FoundInDylib, err = reexportLibraryName(m.ImportedLibraries(), export.Other)
	if err != nil {
		return err
	}

	if len(export.ReExport) == 0 {
		return nil
	}

	reimg, err := i.cache.Image(export.FoundInDylib)
	if err != nil {
		return err
	}
	if resym, err := reimg.GetPublicSymbol(export.ReExport); err == nil {
		export.Address = resym.Address
	}

	return nil
}

func reexportLibraryName(importedLibraries []string, ordinal uint64) (string, error) {
	if ordinal == 0 || ordinal > uint64(len(importedLibraries)) {
		return "", fmt.Errorf("re-export ordinal %d outside imported library table with %d entries", ordinal, len(importedLibraries))
	}
	return importedLibraries[int(ordinal)-1], nil
}

// GetExport returns the trie export symbol matching the given name
func (i *CacheImage) GetExport(symbol string) (*trie.TrieExport, error) {
	var eTrieAddr, eTrieSize uint64

	if i.CacheImageInfoExtra.ExportsTrieAddr > 0 {
		eTrieAddr = i.CacheImageInfoExtra.ExportsTrieAddr
		eTrieSize = uint64(i.CacheImageInfoExtra.ExportsTrieSize)
	} else {
		m, err := i.GetMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to parse MachO for image %s: %v", filepath.Base(i.Name), err)
		}
		if m.DyldExportsTrie() != nil {
			return m.GetDyldExport(symbol)
		} else if m.DyldInfo() != nil {
			eTrieAddr, _ = i.GetVMAddress(uint64(m.DyldInfo().ExportOff))
			eTrieSize = uint64(m.DyldInfo().ExportSize)
		} else {
			return nil, fmt.Errorf("failed to get export trie data for image %s: %w", filepath.Base(i.Name), ErrNoExportTrieInMachO)
		}
	}

	uuid, eTrieOffset, err := i.cache.GetOffset(eTrieAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset of export trie addr")
	}

	sr := io.NewSectionReader(i.cache.r[uuid], 0, 1<<63-1)

	if _, err := sr.Seek(int64(eTrieOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to export trie offset in cache: %v", err)
	}

	exportTrie := make([]byte, eTrieSize)
	if err := binary.Read(sr, i.cache.ByteOrder, &exportTrie); err != nil {
		return nil, fmt.Errorf("failed to read export trie data: %v", err)
	}

	r := bytes.NewReader(exportTrie)

	if _, err = trie.WalkTrie(r, symbol); err != nil {
		return nil, err
	}
	return trie.ReadExport(r, symbol, i.LoadAddress)
}

// GetSymbol retuns a Symbol private or public matching a given name
func (i *CacheImage) GetSymbol(name string) (*Symbol, error) {
	// check local symbols
	if lsym, err := i.GetLocalSymbol(name); err == nil {
		m, err := i.GetPartialMacho()
		if err != nil {
			return nil, err
		}
		var sec string
		if lsym.Sect > 0 && int(lsym.Sect) <= len(m.Sections) {
			sec = fmt.Sprintf("%s.%s", m.Sections[lsym.Sect-1].Seg, m.Sections[lsym.Sect-1].Name)
		}
		return &Symbol{
			Name:    lsym.Name,
			Address: lsym.Value,
			Type:    lsym.Type.String(sec),
			Image:   i.Name,
			Kind:    LOCAL,
		}, nil
	}
	// check public symbols
	if sym, err := i.GetPublicSymbol(name); err == nil {
		sym.Image = i.Name
		return sym, nil
	} else {
		return nil, err
	}
}
