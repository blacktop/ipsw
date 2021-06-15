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

	cache *File // pointer back to the dyld cache that the image belongs to
}

// GetPartialMacho parses dyld image as a partial MachO (fast)
func (i *CacheImage) GetPartialMacho() (*macho.File, error) {
	offset, err := i.cache.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}
	return macho.NewFile(io.NewSectionReader(i.cache.r, int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
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
		Offset:    int64(offset),
		SrcReader: io.NewSectionReader(i.cache.r, 0, 1<<63-1),
		VMAddrConverter: types.VMAddrConverter{
			Converter: func(addr uint64) uint64 {
				return i.SlideInfo.SlidePointer(addr)
			},
			VMAddr2Offet: func(address uint64) (uint64, error) {
				for _, mapping := range i.cache.Mappings {
					if mapping.Address <= address && address < mapping.Address+mapping.Size {
						return (address - mapping.Address) + mapping.FileOffset, nil
					}
				}
				return 0, fmt.Errorf("address not within any mappings address range")
			},
			Offet2VMAddr: func(offset uint64) (uint64, error) {
				for _, mapping := range i.cache.Mappings {
					if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
						return (offset - mapping.FileOffset) + mapping.Address, nil
					}
				}
				return 0, fmt.Errorf("offset not within any mappings file offset range")
			},
		},
	})
}

// GetMacho parses dyld image as a MachO (slow)
func (i *CacheImage) GetMacho() (*macho.File, error) {
	offset, err := i.cache.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}
	return macho.NewFile(io.NewSectionReader(i.cache.r, int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
		Offset:    int64(offset),
		SrcReader: io.NewSectionReader(i.cache.r, 0, 1<<63-1),
		VMAddrConverter: types.VMAddrConverter{
			Converter: func(addr uint64) uint64 {
				return i.SlideInfo.SlidePointer(addr)
			},
			VMAddr2Offet: func(address uint64) (uint64, error) {
				for _, mapping := range i.cache.Mappings {
					if mapping.Address <= address && address < mapping.Address+mapping.Size {
						return (address - mapping.Address) + mapping.FileOffset, nil
					}
				}
				return 0, fmt.Errorf("address not within any mappings address range")
			},
			Offet2VMAddr: func(offset uint64) (uint64, error) {
				for _, mapping := range i.cache.Mappings {
					if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
						return (offset - mapping.FileOffset) + mapping.Address, nil
					}
				}
				return 0, fmt.Errorf("offset not within any mappings file offset range")
			},
		},
	})
}
