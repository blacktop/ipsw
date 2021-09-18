package dyld

import (
	"fmt"
	"io"
	"sync"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
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
	Exports  bool
	Privates bool
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

type analysis struct {
	State        astate
	Dependencies []string
	GotPointers  map[uint64]uint64
	SymbolStubs  map[uint64]uint64
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

	cuuid types.UUID
	cache *File // pointer back to the dyld cache that the image belongs to
}

// ReadAt impliments the io.ReadAt interface requirement
func (i *CacheImage) ReadAt(buf []byte, off int64) (n int, err error) {
	m, err := i.GetPartialMacho()
	if err != nil {
		return -1, err
	}
	le := m.Segment("__LINKEDIT")
	if le == nil {
		return -1, fmt.Errorf("failed to read at offset %#x: failed to find __LINKEDIT segment", off)
	}
	uuid, _, err := i.cache.GetOffset(le.Addr)
	if err != nil {
		return -1, err
	}
	return i.cache.r[uuid].ReadAt(buf, off)
}

// GetOffset returns the offset for a given virtual address
func (i *CacheImage) GetOffset(address uint64) (uint64, error) {
	// u, o, e := i.cache.GetOffset(address)
	// if e != nil {
	// 	return 0, e
	// }
	// fmt.Printf("prim_uuid=%s, cache_uuid=%s, uuid=%s, off=%#x\n", i.cache.UUID, i.cuuid, u, o)
	return i.cache.GetOffsetForUUID(i.cuuid, address)
}

// GetVMAddress returns the virtual address for a given offset
func (i *CacheImage) GetVMAddress(offset uint64) (uint64, error) {
	return i.cache.GetVMAddressForUUID(i.cuuid, offset)
}

// GetMacho parses dyld image as a MachO (slow)
func (i *CacheImage) GetMacho() (*macho.File, error) {
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

	return macho.NewFile(io.NewSectionReader(i.cache.r[i.cuuid], int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
		Offset:             int64(offset),
		SectionReader:      io.NewSectionReader(i.cache.r[i.cuuid], 0, 1<<63-1),
		LinkEditDataReader: io.NewSectionReader(i, 0, 1<<63-1),
		VMAddrConverter: types.VMAddrConverter{
			Converter: func(addr uint64) uint64 {
				return i.cache.SlideInfo[i.cuuid].SlidePointer(addr)
			},
			VMAddr2Offet: func(address uint64) (uint64, error) {
				return i.GetOffset(address)
			},
			Offet2VMAddr: func(offset uint64) (uint64, error) {
				return i.GetVMAddress(offset)
			},
		},
		RelativeSelectorBase: rsBase,
	})
}

// GetPartialMacho parses dyld image as a partial MachO (fast)
func (i *CacheImage) GetPartialMacho() (*macho.File, error) {
	offset, err := i.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}
	return macho.NewFile(io.NewSectionReader(i.cache.r[i.cuuid], int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
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
		Offset:        int64(offset),
		SectionReader: io.NewSectionReader(i.cache.r[i.cuuid], 0, 1<<63-1),
		VMAddrConverter: types.VMAddrConverter{
			Converter: func(addr uint64) uint64 {
				return i.cache.SlideInfo[i.cuuid].SlidePointer(addr)
			},
			VMAddr2Offet: func(address uint64) (uint64, error) {
				return i.GetOffset(address)
			},
			Offet2VMAddr: func(offset uint64) (uint64, error) {
				return i.GetVMAddress(offset)
			},
		},
	})
}
