package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
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

	Deps     bool
	Got      bool
	Stubs    bool
	Helpers  bool
	Exports  bool
	Privates bool
	Starts   bool
	ObjC     bool
	Slide    bool
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
	a.mu.Unlock()
}
func (a *astate) IsExportsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Exports
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

func (i *CacheImage) ReadAt(p []byte, off int64) (n int, err error) {
	if i.m == nil {
		i.m, err = i.GetPartialMacho()
		if err != nil {
			return -1, err
		}
	}
	i.ruuid, _, err = i.cache.GetOffset(i.m.Segment("__LINKEDIT").Addr)
	// i.ruuid, offset, err = i.cache.GetOffset(addr)
	if err != nil {
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

// GetMacho parses dyld image as a MachO (slow)
func (i *CacheImage) GetMacho() (*macho.File, error) {
	if i.m != nil {
		return i.m, nil
	}

	offset, err := i.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}

	var rsBase uint64
	if _, err := i.cache.Image("/usr/lib/libobjc.A.dylib"); err == nil {
		opt, err := i.cache.GetOptimizations()
		if err != nil {
			return nil, err
		}

		if opt.GetVersion() == 16 {
			rsBase = opt.RelativeMethodListsBaseAddress(i.cache.objcOptRoAddr)
			rsBase += i.cache.Headers[i.cache.UUID].SharedRegionStart // TODO: can I trust SharedRegionStart? should this be Mapping[0].Address?
		}
	}

	i.CacheReader = NewCacheReader(0, 1<<63-1, i.cuuid)
	vma := types.VMAddrConverter{
		Converter: func(addr uint64) uint64 {
			return i.cache.SlideInfo.SlidePointer(addr)
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
	vma := types.VMAddrConverter{
		Converter: func(addr uint64) uint64 {
			return i.cache.SlideInfo.SlidePointer(addr)
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
		Offset:          int64(offset),
		SectionReader:   types.NewCustomSectionReader(i.cache.r[i.cuuid], &vma, 0, 1<<63-1),
		CacheReader:     i,
		VMAddrConverter: vma,
		// RelativeSelectorBase: rsBase,
	})
	if err != nil {
		return nil, err
	}

	return i.pm, nil
}

// Analyze analyzes an image by parsing it's symbols, stubs and GOT
func (i *CacheImage) Analyze() error {

	if err := i.ParsePublicSymbols(false); err != nil {
		log.Errorf("failed to parse exported symbols for %s: %w", i.Name, err)
	}

	if err := i.ParseLocalSymbols(false); err != nil {
		if !errors.Is(err, ErrNoLocals) {
			return fmt.Errorf("failed to parse local symbols for %s: %w", i.Name, err)
		}
	}

	if err := i.ParseObjC(); err != nil {
		log.Errorf("failed to parse objc data for image %s: %v", filepath.Base(i.Name), err)
		// return fmt.Errorf("failed to parse objc data for image %s: %v", filepath.Base(i.Name), err) FIXME: should this error out?
	}

	if !i.cache.IsArm64() {
		utils.Indent(log.Warn, 2)("image analysis of stubs and GOT only works on arm64 architectures")
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

		for start, target := range i.Analysis.Helpers {
			if slide, ok := i.sinfo[start]; ok {
				target = slide
			}
			if symName, ok := i.cache.AddressToSymbol[target]; ok {
				i.cache.AddressToSymbol[start] = fmt.Sprintf("__stub_helper.%s", symName)
			} else {
				i.cache.AddressToSymbol[start] = fmt.Sprintf("__stub_helper.%x", target)
			}
		}
	}

	if !i.Analysis.State.IsGotDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s global offset table", i.Name)
		if err := i.ParseGOT(); err != nil {
			return fmt.Errorf("failed to parse GOT for %s: %w", i.Name, err)
		}

		for entry, target := range i.Analysis.GotPointers {
			if slide, ok := i.sinfo[entry]; ok {
				target = slide
			}
			if symName, ok := i.cache.AddressToSymbol[target]; ok {
				i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
			} else {
				if img, err := i.cache.GetImageContainingVMAddr(target); err == nil {
					if err := img.Analyze(); err != nil {
						return fmt.Errorf("failed parse GOT target %#x: failed to analyze image %s: %w", target, img.Name, err)
					}
					if symName, ok := i.cache.AddressToSymbol[target]; ok {
						i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
					} else if laptr, ok := i.Analysis.GotPointers[target]; ok {
						if symName, ok := i.cache.AddressToSymbol[laptr]; ok {
							i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
						}
					} else {
						utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for GOT entry %#x => %#x in %s", entry, target, img.Name))
						i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got_%x ; %s", target, filepath.Base(img.Name))
					}
				} else {
					i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got_%x", target)
				}
			}
		}
	}

	if !i.Analysis.State.IsStubsDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s symbol stubs", i.Name)
		if err := i.ParseStubs(); err != nil {
			return fmt.Errorf("failed to parse stubs for %s: %w", i.Name, err)
		}

		for stub, target := range i.Analysis.SymbolStubs {
			if slide, ok := i.sinfo[stub]; ok {
				target = slide
			}
			if symName, ok := i.cache.AddressToSymbol[target]; ok {
				if !strings.HasPrefix(symName, "j_") {
					i.cache.AddressToSymbol[stub] = "j_" + strings.TrimPrefix(symName, "__stub_helper.")
				} else {
					i.cache.AddressToSymbol[stub] = symName
				}
			} else {
				img, err := i.cache.GetImageContainingVMAddr(target)
				if err != nil {
					return fmt.Errorf("failed to find image containing stub target %#x: %w", target, err)
				}
				if err := img.Analyze(); err != nil {
					return fmt.Errorf("failed to lookup symbol stub target %#x: failed to analyze image %s: %w", target, img.Name, err)
				}
				if symName, ok := i.cache.AddressToSymbol[target]; ok {
					i.cache.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
				} else {
					utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for stub %#x => %#x in %s", stub, target, img.Name))
					i.cache.AddressToSymbol[stub] = fmt.Sprintf("__stub_%x ; %s", target, filepath.Base(img.Name))
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
func (i *CacheImage) ParseSlideInfo() error {

	i.sinfo = make(map[uint64]uint64)

	m, err := i.GetPartialMacho()
	if err != nil {
		return err
	}

	for _, seg := range m.Segments() {
		uuid, mapping, err := i.cache.GetMappingForVMAddress(seg.Addr)
		if err != nil {
			return err
		}

		if mapping.SlideInfoOffset == 0 {
			continue
		}

		startAddr := seg.Addr - mapping.Address
		endAddr := ((seg.Addr + seg.Memsz) - mapping.Address) + uint64(i.cache.SlideInfo.GetPageSize())

		start := startAddr / uint64(i.cache.SlideInfo.GetPageSize())
		end := endAddr / uint64(i.cache.SlideInfo.GetPageSize())

		rs, err := i.cache.GetRebaseInfoForPages(uuid, mapping, start, end)
		if err != nil {
			return err
		}

		for _, r := range rs {
			i.sinfo[r.CacheVMAddress] = r.Target
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
			if _, ok := i.cache.AddressToSymbol[fn.StartAddr]; !ok {
				i.cache.AddressToSymbol[fn.StartAddr] = fmt.Sprintf("sub_%x", fn.StartAddr)
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
		if strings.Contains(i.Name, "libobjc.A.dylib") {
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

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}
	defer m.Close()

	i.Analysis.GotPointers, err = disass.ParseGotPtrs(m)
	if err != nil {
		return err
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

// ParseLocalSymbols parses and caches, with the option to dump, all the local/private symbols for an image
func (i *CacheImage) ParseLocalSymbols(dump bool) error {

	if !i.Analysis.State.IsPrivatesDone() {

		var uuid types.UUID

		if i.cache.IsDyld4 {
			uuid = i.cache.symUUID
		} else {
			uuid = i.cache.UUID
		}

		if i.cache.Headers[uuid].LocalSymbolsOffset == 0 {
			i.Analysis.State.SetPrivates(true) // TODO: does this have any bad side-effects ?
			return fmt.Errorf("failed to parse local syms for image %s: %w", filepath.Base(i.Name), ErrNoLocals)
		}

		sr := io.NewSectionReader(i.cache.r[uuid], 0, 1<<63-1)

		stringPool := io.NewSectionReader(sr, int64(i.cache.LocalSymInfo.StringsFileOffset), int64(i.cache.LocalSymInfo.StringsSize))
		sr.Seek(int64(i.cache.LocalSymInfo.NListFileOffset), io.SeekStart)

		// w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

		for idx := uint32(0); idx < i.cache.LocalSymInfo.EntriesCount; idx++ {
			// skip over other images
			if idx != i.Index {
				sr.Seek(int64(int(i.cache.Images[idx].NlistCount)*binary.Size(types.Nlist64{})), io.SeekCurrent)
				continue
			}

			for e := 0; e < int(i.cache.Images[idx].NlistCount); e++ {
				nlist := types.Nlist64{}
				if err := binary.Read(sr, i.cache.ByteOrder, &nlist); err != nil {
					return err
				}

				stringPool.Seek(int64(nlist.Name), io.SeekStart)

				s, err := bufio.NewReader(stringPool).ReadString('\x00')
				if err != nil {
					log.Error(errors.Wrapf(err, "failed to read string at: %d", i.cache.LocalSymInfo.StringsFileOffset+nlist.Name).Error())
				}

				s = strings.Trim(s, "\x00")
				i.cache.AddressToSymbol[nlist.Value] = s
				i.cache.Images[idx].LocalSymbols = append(i.cache.Images[idx].LocalSymbols, &CacheLocalSymbol64{
					Name:         s,
					Nlist64:      nlist,
					FoundInDylib: i.Name,
				})

				if dump {
					m, err := i.GetPartialMacho()
					if err != nil {
						return err
					}
					// fmt.Fprintf(w, "%s\n", CacheLocalSymbol64{
					// 	Name:    s,
					// 	Nlist64: nlist,
					// 	Macho:   m,
					// }.String(true))
					fmt.Println(CacheLocalSymbol64{
						Name:         s,
						Nlist64:      nlist,
						Macho:        m,
						FoundInDylib: filepath.Base(i.Name),
					}.String(true))
				}
			}

			// w.Flush()

			sort.Slice(i.LocalSymbols, func(j, k int) bool {
				return i.LocalSymbols[j].Name < i.LocalSymbols[k].Name
			})

			i.Analysis.State.SetPrivates(true)

			return nil
		}
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

// ParsePublicSymbols parses and caches, with the option to dump, all the exports, symtab and dyld_info symbols in the image/dylib
func (i *CacheImage) ParsePublicSymbols(dump bool) error {

	if !i.Analysis.State.IsExportsDone() {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		// try to parse exports from the cache's export trie or the dylib's LC_DYLD_EXPORTS_TRIE
		if syms, err := i.cache.GetExportTrieSymbols(i); err == nil {
			for _, sym := range syms {
				if sym.Flags.ReExport() {
					m, err := i.GetPartialMacho()
					if err != nil {
						return err
					}
					sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
					if len(sym.ReExport) > 0 {
						reimg, err := i.cache.Image(sym.FoundInDylib)
						if err != nil {
							return err
						}
						if resym, err := reimg.GetPublicSymbol(sym.ReExport); err == nil {
							sym.Address = resym.Address
						}
					}
				}
				if dump {
					fmt.Fprintf(w, "%s\n", sym)
				} else {
					i.cache.AddressToSymbol[sym.Address] = sym.Name
					i.PublicSymbols = append(i.PublicSymbols, &Symbol{
						Name:    sym.Name,
						Address: sym.Address,
						Type:    sym.Type(),
						Kind:    EXPORT,
					})
				}
			}
			w.Flush()
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
				i.cache.AddressToSymbol[sym.Value] = sym.Name
				i.PublicSymbols = append(i.PublicSymbols, &Symbol{
					Name:    sym.Name,
					Address: sym.Value,
					Type:    sym.Type.String(sec),
					Kind:    SYMTAB,
				})
			}
		}
		w.Flush()
		// try to parse LC_DYLD_INFO binds
		if binds, err := m.GetBindInfo(); err == nil {
			for _, bind := range binds {
				if dump {
					fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.SegOffset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
				} else {
					i.cache.AddressToSymbol[bind.Start+bind.SegOffset] = bind.Name
					i.PublicSymbols = append(i.PublicSymbols, &Symbol{
						Name:    bind.Name,
						Address: bind.Start + bind.SegOffset,
						Type:    fmt.Sprintf("%s|%s", bind.Kind, bind.Dylib),
						Kind:    BIND,
					})
				}
			}
			w.Flush()
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
				if export.Flags.ReExport() {
					m, err := i.GetPartialMacho()
					if err != nil {
						return err
					}
					export.FoundInDylib = m.ImportedLibraries()[export.Other-1]
					if len(export.ReExport) > 0 {
						reimg, err := i.cache.Image(export.FoundInDylib)
						if err != nil {
							return err
						}
						if resym, err := reimg.GetPublicSymbol(export.ReExport); err == nil {
							export.Address = resym.Address
						}
					}
				}
				if dump {
					fmt.Fprintf(w, "%s\n", export)
				} else {
					i.cache.AddressToSymbol[export.Address] = export.Name
					i.PublicSymbols = append(i.PublicSymbols, &Symbol{
						Name:    export.Name,
						Address: export.Address,
						Type:    export.Type(),
						Kind:    EXPORT,
					})
				}
			}
			w.Flush()
		}

		sort.Slice(i.PublicSymbols, func(j, k int) bool {
			return i.PublicSymbols[j].Name < i.PublicSymbols[k].Name
		})

		i.Analysis.State.SetExports(true)
	}

	return nil
}

// returns the public symbol matching the given name
func (i *CacheImage) GetPublicSymbol(name string) (*Symbol, error) {
	i.ParsePublicSymbols(false)

	idx := sort.Search(len(i.PublicSymbols), func(idx int) bool { return i.PublicSymbols[idx].Name >= name })
	if idx < len(i.PublicSymbols) && i.PublicSymbols[idx].Name == name {
		return i.PublicSymbols[idx], nil
	}

	return nil, fmt.Errorf("public symbol %s not found in image %s", name, filepath.Base(i.Name))
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
