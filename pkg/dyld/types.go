package dyld

import (
	"fmt"
	"math/bits"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

type formatVersion uint32

const (
	DylibsExpectedOnDisk   formatVersion = 0x100
	IsSimulator            formatVersion = 0x200
	LocallyBuiltCache      formatVersion = 0x400
	BuiltFromChainedFixups formatVersion = 0x800
)

func (f formatVersion) Version() uint8 {
	return uint8(f & 0xff)
}

func (f formatVersion) IsDylibsExpectedOnDisk() bool {
	return (f & DylibsExpectedOnDisk) != 0
}

func (f formatVersion) IsSimulator() bool {
	return (f & IsSimulator) != 0
}

func (f formatVersion) IsLocallyBuiltCache() bool {
	return (f & LocallyBuiltCache) != 0
}

func (f formatVersion) IsBuiltFromChainedFixups() bool {
	return (f & BuiltFromChainedFixups) != 0
}

func (f formatVersion) String() string {
	var fStr []string
	if f.IsSimulator() {
		fStr = append(fStr, "Simulator")
	}
	if f.IsDylibsExpectedOnDisk() {
		fStr = append(fStr, "DylibsExpectedOnDisk")
	}
	if f.IsLocallyBuiltCache() {
		fStr = append(fStr, "LocallyBuiltCache")
	}
	if f.IsBuiltFromChainedFixups() {
		fStr = append(fStr, "BuiltFromChainedFixups")
	}
	if len(fStr) > 0 {
		return fmt.Sprintf("%d (%s)", f.Version(), strings.Join(fStr, "|"))
	}
	return fmt.Sprintf("%d", f.Version())
}

type maxSlide uint64

func (m maxSlide) PossibleSlideValues() uint32 {
	// TODO: detect arm or not and change page table size
	return uint32(m / 0x4000)
}

func (m maxSlide) EntropyBits() int {
	return 32 - bits.LeadingZeros32(uint32(m.PossibleSlideValues()-1))
}

func (m maxSlide) String() string {
	return fmt.Sprintf("0x%08X (ASLR entropy: %d-bits)", uint64(m), m.EntropyBits())
}

type magic [16]byte

func (m magic) String() string {
	return strings.Trim(string(m[:]), "\x00")
}

type CacheHeader struct {
	Magic                     magic          // e.g. "dyld_v0    i386"
	MappingOffset             uint32         // file offset to first dyld_cache_mapping_info
	MappingCount              uint32         // number of dyld_cache_mapping_info entries
	ImagesOffset              uint32         // file offset to first dyld_cache_image_info
	ImagesCount               uint32         // number of dyld_cache_image_info entries
	DyldBaseAddress           uint64         // base address of dyld when cache was built
	CodeSignatureOffset       uint64         // file offset of code signature blob
	CodeSignatureSize         uint64         // size of code signature blob (zero means to end of file)
	SlideInfoOffsetUnused     uint64         // unused.  Used to be file offset of kernel slid info
	SlideInfoSizeUnused       uint64         // unused.  Used to be size of kernel slid info
	LocalSymbolsOffset        uint64         // file offset of where local symbols are stored
	LocalSymbolsSize          uint64         // size of local symbols information
	UUID                      types.UUID     // unique value for each shared cache file
	CacheType                 uint64         // 0 for development, 1 for production
	BranchPoolsOffset         uint32         // file offset to table of uint64_t pool addresses
	BranchPoolsCount          uint32         // number of uint64_t entries
	AccelerateInfoAddr        uint64         // (unslid) address of optimization info
	AccelerateInfoSize        uint64         // size of optimization info
	ImagesTextOffset          uint64         // file offset to first dyld_cache_image_text_info
	ImagesTextCount           uint64         // number of dyld_cache_image_text_info entries
	PatchInfoAddr             uint64         // (unslid) address of dyld_cache_patch_info
	PatchInfoSize             uint64         // Size of all of the patch information pointed to via the dyld_cache_patch_info
	OtherImageGroupAddrUnused uint64         // unused
	OtherImageGroupSizeUnused uint64         // unused
	ProgClosuresAddr          uint64         // (unslid) address of list of program launch closures
	ProgClosuresSize          uint64         // size of list of program launch closures
	ProgClosuresTrieAddr      uint64         // (unslid) address of trie of indexes into program launch closures
	ProgClosuresTrieSize      uint64         // size of trie of indexes into program launch closures
	Platform                  types.Platform // platform number (macOS=1, etc)
	FormatVersion             formatVersion  /* : 8,  // dyld3::closure::kFormatVersion
	   dylibsExpectedOnDisk   : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
	   simulator              : 1,  // for simulator of specified platform
	   locallyBuiltCache      : 1,  // 0 for B&I built cache, 1 for locally built cache
	   builtFromChainedFixups : 1,  // some dylib in cache was built using chained fixups, so patch tables must be used for overrides
	   padding                : 20; // TBD */
	SharedRegionStart                 uint64   // base load address of cache if not slid
	SharedRegionSize                  uint64   // overall size of region cache can be mapped into
	MaxSlide                          maxSlide // runtime slide of cache can be between zero and this value
	DylibsImageArrayAddr              uint64   // (unslid) address of ImageArray for dylibs in this cache
	DylibsImageArraySize              uint64   // size of ImageArray for dylibs in this cache
	DylibsTrieAddr                    uint64   // (unslid) address of trie of indexes of all cached dylibs
	DylibsTrieSize                    uint64   // size of trie of cached dylib paths
	OtherImageArrayAddr               uint64   // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
	OtherImageArraySize               uint64   // size of ImageArray for dylibs and bundles with dlopen closures
	OtherTrieAddr                     uint64   // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
	OtherTrieSize                     uint64   // size of trie of dylibs and bundles with dlopen closures
	MappingWithSlideOffset            uint32   // file offset to first dyld_cache_mapping_and_slide_info
	MappingWithSlideCount             uint32   // number of dyld_cache_mapping_and_slide_info entries
	DataMappingStartAddr              uint64   // (unslid) address of the __DATA mapping of the first sub cache (w/ no ext .1,.2 etc)
	DylibsImageArrayWithSubCachesAddr uint64   // NOTICE: no Size, but you can calculate by progClosuresWithSubCachesAddr - dylibsImageArrayWithSubCachesAddr
	ProgClosuresWithSubCachesAddr     uint64
	ProgClosuresWithSubCachesSize     uint64
	ProgClosuresTrieWithSubCachesAddr uint64
	ProgClosuresTrieWithSubCachesSize uint32
	Dyld4FormatVersion                formatVersion
	Unknown8                          uint32
	Unknown9                          uint32
	NewFieldOffset                    uint64
	NewFieldSize                      uint64
	SubCachesInfoOffset               uint32
	NumSubCaches                      uint32     // number of dyld_shared_cache .1,.2,.3 files
	SymbolsSubCacheUUID               types.UUID // unique value for .symbols sub-cache
	IsZero1                           uint64
	IsZero2                           uint64
	IsZero3                           uint64
	IsZero4                           uint64
	ImagesWithSubCachesOffset         uint32 // file offset to first dyld_cache_image_info
	ImagesWithSubCachesCount          uint32 // number of dyld_cache_image_info entries
}

type CacheMappingInfo struct {
	Address    uint64
	Size       uint64
	FileOffset uint64
	MaxProt    types.VmProtection
	InitProt   types.VmProtection
}

type CacheMappingFlag uint64

const (
	DYLD_CACHE_MAPPING_NONE       CacheMappingFlag = 0
	DYLD_CACHE_MAPPING_AUTH_DATA  CacheMappingFlag = 1
	DYLD_CACHE_MAPPING_DIRTY_DATA CacheMappingFlag = 2
	DYLD_CACHE_MAPPING_CONST_DATA CacheMappingFlag = 4
)

func (f CacheMappingFlag) IsNone() bool {
	return f == DYLD_CACHE_MAPPING_NONE
}
func (f CacheMappingFlag) IsAuthData() bool {
	return (f & DYLD_CACHE_MAPPING_AUTH_DATA) != 0
}
func (f CacheMappingFlag) IsDirtyData() bool {
	return (f & DYLD_CACHE_MAPPING_DIRTY_DATA) != 0
}
func (f CacheMappingFlag) IsConstData() bool {
	return (f & DYLD_CACHE_MAPPING_CONST_DATA) != 0
}

type CacheMappingAndSlideInfo struct {
	Address         uint64             `json:"address,omitempty"`
	Size            uint64             `json:"size,omitempty"`
	FileOffset      uint64             `json:"file_offset,omitempty"`
	SlideInfoOffset uint64             `json:"slide_info_offset,omitempty"`
	SlideInfoSize   uint64             `json:"slide_info_size,omitempty"`
	Flags           CacheMappingFlag   `json:"flags,omitempty"`
	MaxProt         types.VmProtection `json:"max_prot,omitempty"`
	InitProt        types.VmProtection `json:"init_prot,omitempty"`
}

type CacheMapping struct {
	Name string
	CacheMappingInfo
}

type CacheMappingWithSlideInfo struct {
	Name string `json:"name,omitempty"`
	CacheMappingAndSlideInfo
}

type CacheImageInfo struct {
	Address        uint64
	ModTime        uint64
	Inode          uint64
	PathFileOffset uint32
	Pad            uint32
}

type slideInfo interface {
	GetVersion() uint32
	SlidePointer(uint64) uint64
}

// CacheSlideInfo is the dyld_cache_image_info struct
// The rebasing info is to allow the kernel to lazily rebase DATA pages of the
// dyld shared cache.  Rebasing is adding the slide to interior pointers.
type CacheSlideInfo struct {
	Version       uint32 // currently 1
	TocOffset     uint32
	TocCount      uint32
	EntriesOffset uint32
	EntriesCount  uint32
	EntriesSize   uint32 // currently 128
	// uint16_t toc[toc_count];
	// entrybitmap entries[entries_count];
}

func (i CacheSlideInfo) GetVersion() uint32 {
	return i.Version
}
func (i CacheSlideInfo) SlidePointer(ptr uint64) uint64 {
	return ptr // TODO: finish this
}

type CacheSlideInfoEntry struct {
	bits [4096 / (8 * 4)]uint8 // 128-byte bitmap
}

type CacheSlideInfo2 struct {
	Version          uint32 // currently 2
	PageSize         uint32 // currently 4096 (may also be 16384)
	PageStartsOffset uint32
	PageStartsCount  uint32
	PageExtrasOffset uint32
	PageExtrasCount  uint32
	DeltaMask        uint64 // which (contiguous) set of bits contains the delta to the next rebase location
	ValueAdd         uint64
	//uint16_t    page_starts[page_starts_count];
	//uint16_t    page_extras[page_extras_count];
}

func (i CacheSlideInfo2) GetVersion() uint32 {
	return i.Version
}
func (i CacheSlideInfo2) SlidePointer(ptr uint64) uint64 {
	if (ptr & ^i.DeltaMask) != 0 {
		return (ptr & ^i.DeltaMask) + i.ValueAdd
	}
	return 0
}

const (
	DYLD_CACHE_SLIDE_PAGE_ATTRS          = 0xC000 // high bits of uint16_t are flags
	DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA     = 0x8000 // index is into extras array (not starts array)
	DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000 // page has no rebasing
	DYLD_CACHE_SLIDE_PAGE_ATTR_END       = 0x8000 // last chain entry for page
)

type CacheSlideInfo3 struct {
	Version         uint32 // currently 3
	PageSize        uint32 // currently 4096 (may also be 16384)
	PageStartsCount uint32
	_               uint32 // padding for 64bit alignment
	AuthValueAdd    uint64
	// PageStarts      []uint16 /* len() = page_starts_count */
}

func (i CacheSlideInfo3) GetVersion() uint32 {
	return i.Version
}
func (i CacheSlideInfo3) SlidePointer(ptr uint64) uint64 {
	pointer := CacheSlidePointer3(ptr)
	if pointer.Authenticated() {
		return 0x180000000 + pointer.OffsetFromSharedCacheBase()
	}
	return pointer.SignExtend51()
}

const DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFFF // page has no rebasing

// CacheSlidePointer3 struct
// {
//     uint64_t  raw;
//     struct {
//         uint64_t    pointerValue        : 51,
//                     offsetToNextPointer : 11,
//                     unused              :  2;
//     }         plain;
//     struct {
//         uint64_t    offsetFromSharedCacheBase : 32,
//                     diversityData             : 16,
//                     hasAddressDiversity       :  1,
//                     key                       :  2,
//                     offsetToNextPointer       : 11,
//                     unused                    :  1,
//                     authenticated             :  1; // = 1;
//     }         auth;
// };
type CacheSlidePointer3 uint64

// SignExtend51 returns a regular pointer which needs to fit in 51-bits of value.
// C++ RTTI uses the top bit, so we'll allow the whole top-byte
// and the signed-extended bottom 43-bits to be fit in to 51-bits.
func (p CacheSlidePointer3) SignExtend51() uint64 {
	top8Bits := uint64(p & 0x007F80000000000)
	bottom43Bits := uint64(p & 0x000007FFFFFFFFFF)
	return (top8Bits << 13) | (((uint64)(bottom43Bits<<21) >> 21) & 0x00FFFFFFFFFFFFFF)
}

// Raw returns the chained pointer's raw uint64 value
func (p CacheSlidePointer3) Raw() uint64 {
	return uint64(p)
}

// Value returns the chained pointer's value
func (p CacheSlidePointer3) Value() uint64 {
	return types.ExtractBits(uint64(p), 0, 51)
}

// OffsetToNextPointer returns the offset to the next chained pointer
func (p CacheSlidePointer3) OffsetToNextPointer() uint64 {
	return types.ExtractBits(uint64(p), 51, 11)
}

// OffsetFromSharedCacheBase returns the chained pointer's offset from the base
func (p CacheSlidePointer3) OffsetFromSharedCacheBase() uint64 {
	return types.ExtractBits(uint64(p), 0, 32)
}

// DiversityData returns the chained pointer's diversity data
func (p CacheSlidePointer3) DiversityData() uint64 {
	return types.ExtractBits(uint64(p), 32, 16)
}

// HasAddressDiversity returns if the chained pointer has address diversity
func (p CacheSlidePointer3) HasAddressDiversity() bool {
	return types.ExtractBits(uint64(p), 48, 1) != 0
}

// Key returns the chained pointer's key
func (p CacheSlidePointer3) Key() uint64 {
	return types.ExtractBits(uint64(p), 49, 2)
}

// KeyName returns the chained pointer's key name
func KeyName(keyVal uint64) string {
	name := []string{"IA", "IB", "DA", "DB"}
	key := uint64(keyVal >> 49 & 0x3)
	if key >= 4 {
		return "ERROR"
	}
	return name[key]
}

// Authenticated returns if the chained pointer is authenticated
func (p CacheSlidePointer3) Authenticated() bool {
	return types.ExtractBits(uint64(p), 63, 1) != 0
}

func (p CacheSlidePointer3) String() string {
	if p.Authenticated() {
		return fmt.Sprintf("value: %#x, next: %02x, diversity: %04x, addr_div: %t, key: %s, auth: %t",
			p.Value(),
			p.OffsetToNextPointer(),
			p.DiversityData(),
			p.HasAddressDiversity(),
			KeyName(uint64(p)),
			p.Authenticated(),
		)
	}
	return fmt.Sprintf("value: %#x, next: %02x", p.Value(), p.OffsetToNextPointer())
}

type CacheSlideInfo4 struct {
	Version          uint32 // currently 4
	PageSize         uint32 // currently 4096 (may also be 16384)
	PageStartsOffset uint32
	PageStartsCount  uint32
	PageExtrasOffset uint32
	PageExtrasCount  uint32
	DeltaMask        uint64 // which (contiguous) set of bits contains the delta to the next rebase location (0xC0000000)
	ValueAdd         uint64 // base address of cache
	//uint16_t    page_starts[page_starts_count];
	//uint16_t    page_extras[page_extras_count];
}

func (i CacheSlideInfo4) GetVersion() uint32 {
	return i.Version
}
func (i CacheSlideInfo4) SlidePointer(ptr uint64) uint64 {
	value := ptr & ^i.DeltaMask

	if (value & 0xFFFF8000) == 0 {
		// small positive non-pointer, use as-is
	} else if (value & 0x3FFF8000) == 0x3FFF8000 {
		// small negative non-pointer
		value |= 0xC0000000
	} else {
		value += i.ValueAdd
	}
	return value
}

const (
	DYLD_CACHE_SLIDE4_PAGE_NO_REBASE = 0xFFFF // page has no rebasing
	DYLD_CACHE_SLIDE4_PAGE_INDEX     = 0x7FFF // mask of page_starts[] values
	DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA = 0x8000 // index is into extras array (not a chain start offset)
	DYLD_CACHE_SLIDE4_PAGE_EXTRA_END = 0x8000 // last chain entry for page
)

type CacheLocalSymbolsInfo struct {
	NlistOffset   uint32 // offset into this chunk of nlist entries
	NlistCount    uint32 // count of nlist entries
	StringsOffset uint32 // offset into this chunk of string pool
	StringsSize   uint32 // byte count of string pool
	EntriesOffset uint32 // offset into this chunk of array of dyld_cache_local_symbols_entry
	EntriesCount  uint32 // number of elements in dyld_cache_local_symbols_entry array
}

type CacheLocalSymbolsEntry struct {
	DylibOffset     uint64 // offset in cache file of start of dylib
	NlistStartIndex uint32 // start index of locals for this dylib
	NlistCount      uint32 // number of local symbols for this dylib
}

type preDyld4cacheLocalSymbolsEntry struct {
	DylibOffset     uint32 // offset in cache file of start of dylib
	NlistStartIndex uint32 // start index of locals for this dylib
	NlistCount      uint32 // number of local symbols for this dylib
}

type CacheLocalSymbol struct {
	types.Nlist32
	Name string
}

type CacheLocalSymbol64 struct {
	types.Nlist64
	Name         string
	FoundInDylib string
	Sections     []*macho.Section
}

func (s CacheLocalSymbol64) String() string {
	// ord := s.Nlist64.Desc.GetLibraryOrdinal() // TODO: how to handle ord ?
	var found string
	var sec string
	if len(s.FoundInDylib) > 0 {
		found = fmt.Sprintf(", %s", s.FoundInDylib)
	}
	if s.Sect > 0 && s.Sections != nil {
		sec = fmt.Sprintf("%s.%s", s.Sections[s.Sect-1].Seg, s.Sections[s.Sect-1].Name)
	}
	return fmt.Sprintf("%#016x:\t(%s)\t%s%s", s.Value, s.Type.String(sec), s.Name, found)
}

type CacheImageInfoExtra struct {
	ExportsTrieAddr           uint64 // address of trie in unslid cache
	WeakBindingsAddr          uint64
	ExportsTrieSize           uint32
	WeakBindingsSize          uint32
	DependentsStartArrayIndex uint32
	ReExportsStartArrayIndex  uint32
}

type CacheAcceleratorInfo struct {
	Version            uint32 // currently 1
	ImageExtrasCount   uint32 // does not include aliases
	ImagesExtrasOffset uint32 // offset into this chunk of first dyld_cache_image_info_extra
	BottomUpListOffset uint32 // offset into this chunk to start of 16-bit array of sorted image indexes
	DylibTrieOffset    uint32 // offset into this chunk to start of trie containing all dylib paths
	DylibTrieSize      uint32 // size of trie containing all dylib paths
	InitializersOffset uint32 // offset into this chunk to start of initializers list
	InitializersCount  uint32 // size of initializers list
	DofSectionsOffset  uint32 // offset into this chunk to start of DOF sections list
	DofSectionsCount   uint32 // size of initializers list
	ReExportListOffset uint32 // offset into this chunk to start of 16-bit array of re-exports
	ReExportCount      uint32 // size of re-exports
	DepListOffset      uint32 // offset into this chunk to start of 16-bit array of dependencies (0x8000 bit set if upward)
	DepListCount       uint32 // size of dependencies
	RangeTableOffset   uint32 // offset into this chunk to start of ss
	RangeTableCount    uint32 // size of dependencies
	DyldSectionAddr    uint64 // address of libdyld's __dyld section in unslid cache
}

type CacheAcceleratorInitializer struct {
	FunctionOffset uint32 // address offset from start of cache mapping
	ImageIndex     uint32
}

type CacheRangeEntry struct {
	StartAddress uint64 // unslid address of start of region
	Size         uint32
	ImageIndex   uint32
}

type CacheAcceleratorDof struct {
	SectionAddress uint64 // unslid address of start of region
	SectionSize    uint32
	ImageIndex     uint32
}

type CacheImageTextInfo struct {
	UUID            types.UUID
	LoadAddress     uint64 // unslid address of start of __TEXT
	TextSegmentSize uint32
	PathOffset      uint32 // offset from start of cache file
}

type CachePatchInfo struct {
	PatchTableArrayAddr     uint64 // (unslid) address of array for dyld_cache_image_patches for each image
	PatchTableArrayCount    uint64 // count of patch table entries
	PatchExportArrayAddr    uint64 // (unslid) address of array for patch exports for each image
	PatchExportArrayCount   uint64 // count of patch exports entries
	PatchLocationArrayAddr  uint64 // (unslid) address of array for patch locations for each patch
	PatchLocationArrayCount uint64 // count of patch location entries
	PatchExportNamesAddr    uint64 // blob of strings of export names for patches
	PatchExportNamesSize    uint64 // size of string blob of export names for patches
}

type CacheImagePatches struct {
	PatchExportsStartIndex uint32
	PatchExportsCount      uint32
}

type CachePatchableExport struct {
	CacheOffsetOfImpl        uint32
	PatchLocationsStartIndex uint32
	PatchLocationsCount      uint32
	ExportNameOffset         uint32
}

type CachePatchableLocation uint64

func (p CachePatchableLocation) CacheOffset() uint64 {
	return types.ExtractBits(uint64(p), 0, 32)
}
func (p CachePatchableLocation) High7() uint64 {
	return types.ExtractBits(uint64(p), 32, 7)
}
func (p CachePatchableLocation) Addend() uint64 {
	return types.ExtractBits(uint64(p), 39, 5) // 0..31
}
func (p CachePatchableLocation) Authenticated() bool {
	return types.ExtractBits(uint64(p), 44, 1) != 0
}
func (p CachePatchableLocation) UsesAddressDiversity() bool {
	return types.ExtractBits(uint64(p), 45, 1) != 0
}
func (p CachePatchableLocation) Key() uint64 {
	return types.ExtractBits(uint64(p), 46, 2)
}
func (p CachePatchableLocation) Discriminator() uint64 {
	return types.ExtractBits(uint64(p), 48, 16)
}

func (p CachePatchableLocation) String() string {
	var pStr string
	if p.Authenticated() && p.UsesAddressDiversity() {
		pStr = fmt.Sprintf("offset: 0x%08x, addend: %x, diversity: 0x%04x, key: %s, auth: %t",
			p.CacheOffset(),
			p.Addend(),
			p.Discriminator(),
			KeyName(uint64(p)),
			p.Authenticated(),
		)
	} else if p.Authenticated() && !p.UsesAddressDiversity() {
		pStr = fmt.Sprintf("offset: 0x%08x, addend: %x, key: %s, auth: %t",
			p.CacheOffset(),
			p.Addend(),
			KeyName(uint64(p)),
			p.Authenticated(),
		)
	} else {
		pStr = fmt.Sprintf("offset: 0x%08x", p.CacheOffset())
	}
	return pStr
}

type SubCacheInfo struct {
	UUID      types.UUID
	TotalSize uint64
}

type CacheExportFlag int

const (
	exportSymbolFlagsKindMask        CacheExportFlag = 0x03
	exportSymbolFlagsKindRegular     CacheExportFlag = 0x00
	exportSymbolFlagsKindThreadLocal CacheExportFlag = 0x01
	exportSymbolFlagsKindAbsolute    CacheExportFlag = 0x02
	exportSymbolFlagsWeakDefinition  CacheExportFlag = 0x04
	exportSymbolFlagsReexport        CacheExportFlag = 0x08
	exportSymbolFlagsStubAndResolver CacheExportFlag = 0x10
)

func (f CacheExportFlag) Regular() bool {
	return (f & exportSymbolFlagsKindMask) == exportSymbolFlagsKindRegular
}
func (f CacheExportFlag) ThreadLocal() bool {
	return (f & exportSymbolFlagsKindMask) == exportSymbolFlagsKindThreadLocal
}
func (f CacheExportFlag) Absolute() bool {
	return (f & exportSymbolFlagsKindMask) == exportSymbolFlagsKindAbsolute
}
func (f CacheExportFlag) WeakDefinition() bool {
	return f == exportSymbolFlagsWeakDefinition
}
func (f CacheExportFlag) ReExport() bool {
	return f == exportSymbolFlagsReexport
}
func (f CacheExportFlag) StubAndResolver() bool {
	return f == exportSymbolFlagsStubAndResolver
}
func (f CacheExportFlag) String() string {
	var fStr string
	if f.Regular() && !f.ReExport() {
		fStr += "Regular"
		if f.StubAndResolver() {
			fStr += "|Has Resolver Function"
		} else if f.WeakDefinition() {
			fStr += "|Weak Definition"
		}
	} else if f.ThreadLocal() {
		fStr += "Thread Local"
	} else if f.Absolute() {
		fStr += "Absolute"
	} else if f.ReExport() {
		fStr += "ReExport"
	}
	return strings.TrimSpace(fStr)
}

type CacheExportedSymbol struct {
	IsHeaderOffset     bool
	IsAbsolute         bool
	HasResolverOffset  bool
	IsThreadLocal      bool
	IsWeakDef          bool
	Flags              CacheExportFlag
	FoundInDylib       string
	Value              uint64
	Address            uint64
	ResolverFuncOffset uint32
	Name               string
}

func (es CacheExportedSymbol) String() string {
	// if !es.Flags.Absolute() {
	return fmt.Sprintf("0x%08x: %s [%s], %s", es.Address, es.Name, es.Flags, es.FoundInDylib)
	// }
	// return fmt.Sprintf("0x%8x: %s [%s]", es.Value, es.Name, es.Flags)
}
