package dyld

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
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

type patchableExport struct {
	Name           string
	OffsetOfImpl   uint32
	PatchLocations []CachePatchableLocation
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
	Name         string
	Index        uint32
	Info         CacheImageInfo
	LocalSymbols []*CacheLocalSymbol64
	Mappings     *cacheMappingsWithSlideInfo
	CacheLocalSymbolsEntry
	CacheImageInfoExtra
	CacheImageTextInfo
	Initializer      uint64
	DOFSectionAddr   uint64
	DOFSectionSize   uint32
	SlideInfo        slideInfo
	RangeEntries     []rangeEntry
	PatchableExports []patchableExport
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
	if offset < i.base {
		return 0, fmt.Errorf("Seek: invalid offset")
	}
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
	sec, opt, err := i.cache.getOptimizations()
	if err != nil {
		return nil, err
	}

	if opt.Version == 16 {
		rsBase = sec.Addr + opt.RelativeMethodSelectorBaseAddressCacheOffset
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
		LoadFilter: []types.LoadCmd{
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

func (i *CacheImage) GetLocalSymbols() []macho.Symbol {
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

// Analyze analyzes an image by parsing it's symbols, stubs and GOT
func (i *CacheImage) Analyze() error {

	if err := i.cache.GetAllExportedSymbolsForImage(i, false); err != nil {
		log.Errorf("failed to parse exported symbols for %s", i.Name)
	}

	if !i.Analysis.State.IsStartsDone() {
		i.ParseStarts()
	}

	if err := i.cache.GetLocalSymbolsForImage(i); err != nil {
		if !errors.Is(err, ErrNoLocals) {
			return err
		}
	}

	if err := i.ParseObjC(); err != nil {
		return fmt.Errorf("failed to parse objc data for image %s: %v", filepath.Base(i.Name), err)
	}

	if !i.cache.IsArm64() {
		utils.Indent(log.Warn, 2)("image analysis of stubs and GOT only works on arm64 architectures")
	}

	if !i.Analysis.State.IsSlideInfoDone() {
		if err := i.ParseSlideInfo(); err != nil {
			return err
		}
	}

	if !i.Analysis.State.IsHelpersDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s symbol stub helpers", i.Name)
		if err := i.ParseHelpers(); err != nil {
			if !errors.Is(err, macho.ErrMachOSectionNotFound) {
				return err
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
			return err
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
						return err
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
			return err
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
					return err
				}
				if err := img.Analyze(); err != nil {
					return err
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

	return nil
}

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
		if err := i.cache.ProtocolsForImage(i.Name); err != nil {
			return fmt.Errorf("failed to parse objc protocols for image %s: %v", filepath.Base(i.Name), err)
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

	i.Analysis.SymbolStubs, err = disass.ParseStubsASM(m)
	if err != nil {
		return err
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

func (i *CacheImage) GetSymbols(syms []string) ([]Symbol, error) {
	var symbols []Symbol

	if err := i.cache.GetLocalSymbolsForImage(i); err != nil {
		if !errors.Is(err, ErrNoLocals) {
			return nil, err
		}
	}

	for _, sym := range i.LocalSymbols {
		if utils.StrSliceHas(syms, sym.Name) {
			symbols = append(symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Image:   i.Name,
			})
			syms = utils.RemoveStrFromSlice(syms, sym.Name)
			if len(syms) == 0 {
				return symbols, nil
			}
		}
	}

	expSyms, err := i.cache.GetExportTrieSymbols(i)
	if err != nil {
		if !errors.Is(err, ErrNoExportTrieInMachO) {
			return nil, err
		}
	}

	for _, sym := range expSyms {
		if utils.StrSliceHas(syms, sym.Name) {
			if sym.Flags.ReExport() {
				m, err := i.GetPartialMacho()
				if err != nil {
					return nil, err
				}
				sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
				// lookup re-exported symbol
				if rexpSym, err := i.cache.FindExportedSymbolInImage(sym.FoundInDylib, sym.ReExport); err != nil {
					if errors.Is(err, ErrNoExportTrieInMachO) {
						image, err := i.cache.Image(sym.FoundInDylib)
						if err != nil {
							return nil, err
						}
						m, err = image.GetMacho()
						if err != nil {
							return nil, err
						}
						for _, s := range m.Symtab.Syms {
							if s.Name == sym.ReExport {
								symbols = append(symbols, Symbol{
									Name:    sym.Name,
									Address: s.Value,
									Image:   i.Name,
								})
								syms = utils.RemoveStrFromSlice(syms, sym.Name)
								if len(syms) == 0 {
									return symbols, nil
								}
							}
						}
					} else {
						return nil, err
					}
				} else {
					symbols = append(symbols, Symbol{
						Name:    sym.Name,
						Address: rexpSym.Address,
						Image:   i.Name,
					})
					syms = utils.RemoveStrFromSlice(syms, sym.Name)
					if len(syms) == 0 {
						return symbols, nil
					}
				}
			} else {
				symbols = append(symbols, Symbol{
					Name:    sym.Name,
					Address: sym.Address,
					Image:   i.Name,
				})
				syms = utils.RemoveStrFromSlice(syms, sym.Name)
				if len(syms) == 0 {
					return symbols, nil
				}
			}
		}
	}

	m, err := i.GetMacho()
	if err != nil {
		return nil, err
	}
	for _, sym := range m.Symtab.Syms {
		if utils.StrSliceHas(syms, sym.Name) {
			symbols = append(symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Image:   i.Name,
			})
			syms = utils.RemoveStrFromSlice(syms, sym.Name)
			if len(syms) == 0 {
				return symbols, nil
			}
		}
	}
	if binds, err := m.GetBindInfo(); err == nil {
		for _, bind := range binds {
			if utils.StrSliceHas(syms, bind.Name) {
				symbols = append(symbols, Symbol{
					Name:    bind.Name,
					Address: bind.Start + bind.Offset,
					Image:   i.Name,
				})
				syms = utils.RemoveStrFromSlice(syms, bind.Name)
				if len(syms) == 0 {
					return symbols, nil
				}
			}
		}
	}

	return symbols, nil
}
