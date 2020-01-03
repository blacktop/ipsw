package dyld

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/macho"
)

type formatVersion uint32

const (
	IsSimulator          formatVersion = 0x100
	DylibsExpectedOnDisk formatVersion = 0x200
	LocallyBuiltCache    formatVersion = 0x400
)

func (f formatVersion) Version() uint8 {
	return uint8(f & 0xff)
}

func (f formatVersion) IsSimulator() bool {
	return (f & IsSimulator) != 0
}

func (f formatVersion) IsDylibsExpectedOnDisk() bool {
	return (f & DylibsExpectedOnDisk) != 0
}

func (f formatVersion) IsLocallyBuiltCache() bool {
	return (f & LocallyBuiltCache) != 0
}

type CacheHeader struct {
	Magic                [16]byte       // e.g. "dyld_v0    i386"
	MappingOffset        uint32         // file offset to first dyld_cache_mapping_info
	MappingCount         uint32         // number of dyld_cache_mapping_info entries
	ImagesOffset         uint32         // file offset to first dyld_cache_image_info
	ImagesCount          uint32         // number of dyld_cache_image_info entries
	DyldBaseAddress      uint64         // base address of dyld when cache was built
	CodeSignatureOffset  uint64         // file offset of code signature blob
	CodeSignatureSize    uint64         // size of code signature blob (zero means to end of file)
	SlideInfoOffset      uint64         // file offset of kernel slid info
	SlideInfoSize        uint64         // size of kernel slid info
	LocalSymbolsOffset   uint64         // file offset of where local symbols are stored
	LocalSymbolsSize     uint64         // size of local symbols information
	UUID                 macho.UUID     // unique value for each shared cache file
	CacheType            uint64         // 0 for development, 1 for production
	BranchPoolsOffset    uint32         // file offset to table of uint64_t pool addresses
	BranchPoolsCount     uint32         // number of uint64_t entries
	AccelerateInfoAddr   uint64         // (unslid) address of optimization info
	AccelerateInfoSize   uint64         // size of optimization info
	ImagesTextOffset     uint64         // file offset to first dyld_cache_image_text_info
	ImagesTextCount      uint64         // number of dyld_cache_image_text_info entries
	DylibsImageGroupAddr uint64         // (unslid) address of ImageGroup for dylibs in this cache
	DylibsImageGroupSize uint64         // size of ImageGroup for dylibs in this cache
	OtherImageGroupAddr  uint64         // (unslid) address of ImageGroup for other OS dylibs
	OtherImageGroupSize  uint64         // size of oImageGroup for other OS dylibs
	ProgClosuresAddr     uint64         // (unslid) address of list of program launch closures
	ProgClosuresSize     uint64         // size of list of program launch closures
	ProgClosuresTrieAddr uint64         // (unslid) address of trie of indexes into program launch closures
	ProgClosuresTrieSize uint64         // size of trie of indexes into program launch closures
	Platform             macho.Platform // platform number (macOS=1, etc)
	FormatVersion        formatVersion  /* formatVersion        : 8,  // dyld3::closure::kFormatVersion
	   dylibsExpectedOnDisk : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
	   simulator            : 1,  // for simulator of specified platform
	   locallyBuiltCache    : 1,  // 0 for B&I built cache, 1 for locally built cache
	   TODO: I think there is a new flag here
	   padding              : 21; // TBD */
	SharedRegionStart    uint64 // base load address of cache if not slid
	SharedRegionSize     uint64 // overall size of region cache can be mapped into
	MaxSlide             uint64 // runtime slide of cache can be between zero and this value
	DylibsImageArrayAddr uint64 // (unslid) address of ImageArray for dylibs in this cache
	DylibsImageArraySize uint64 // size of ImageArray for dylibs in this cache
	DylibsTrieAddr       uint64 // (unslid) address of trie of indexes of all cached dylibs
	DylibsTrieSize       uint64 // size of trie of cached dylib paths
	OtherImageArrayAddr  uint64 // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
	OtherImageArraySize  uint64 // size of ImageArray for dylibs and bundles with dlopen closures
	OtherTrieAddr        uint64 // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
	OtherTrieSize        uint64 // size of trie of dylibs and bundles with dlopen closures
}

type CacheMappingInfo struct {
	Address    uint64
	Size       uint64
	FileOffset uint64
	MaxProt    macho.VmProtection
	InitProt   macho.VmProtection
}

type CacheMapping struct {
	Name string
	CacheMappingInfo
}

type CacheImageInfo struct {
	Address        uint64
	ModTime        uint64
	Inode          uint64
	PathFileOffset uint32
	Pad            uint32
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

const (
	DYLD_CACHE_SLIDE_PAGE_ATTRS          = 0xC000 // high bits of uint16_t are flags
	DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA     = 0x8000 // index is into extras array (not starts array)
	DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000 // page has no rebasing
	DYLD_CACHE_SLIDE_PAGE_ATTR_END       = 0x8000 // last chain entry for page
)

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

const DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFFF // page has no rebasing

type CacheSlideInfo3 struct {
	Version         uint32 // currently 3
	PageSize        uint32 // currently 4096 (may also be 16384)
	PageStartsCount uint32
	AuthValueAdd    uint64
	// PageStarts      []uint16 /* len() = page_starts_count */
}

const (
	DYLD_CACHE_SLIDE4_PAGE_NO_REBASE = 0xFFFF // page has no rebasing
	DYLD_CACHE_SLIDE4_PAGE_INDEX     = 0x7FFF // mask of page_starts[] values
	DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA = 0x8000 // index is into extras array (not a chain start offset)
	DYLD_CACHE_SLIDE4_PAGE_EXTRA_END = 0x8000 // last chain entry for page
)

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

// Value returns the chained pointer's value
func (p CacheSlidePointer3) Value() uint64 {
	return uint64(p & 0x7FFFFFFFFFFFF)
}

// OffsetToNextPointer returns the offset to the next chained pointer
func (p CacheSlidePointer3) OffsetToNextPointer() uint64 {
	return uint64(p & 0x3FF8000000000000 >> 51)
}

// OffsetFromSharedCacheBase returns the chained pointer's offset from the base
func (p CacheSlidePointer3) OffsetFromSharedCacheBase() uint64 {
	return uint64(p & 0x7FFFFFFFFFFFF)
}

// DiversityData returns the chained pointer's diversity data
func (p CacheSlidePointer3) DiversityData() uint64 {
	return uint64(p >> 32 & 0xFFFF)
}

// HasAddressDiversity returns if the chained pointer has address diversity
func (p CacheSlidePointer3) HasAddressDiversity() bool {
	return (p & 0x8000) != 0
}

// Key returns the chained pointer's key
func (p CacheSlidePointer3) Key() uint64 {
	return uint64(p >> 49 & 0x3)
}

// Authenticated returns if the chained pointer is authenticated
func (p CacheSlidePointer3) Authenticated() bool {
	return (p & 0x1) != 0
}

func (p CacheSlidePointer3) String() string {
	var pStr string
	if p.Authenticated() {
		pStr = fmt.Sprintf("value: %x, offset: %x, has_diversity: %t, diversity: %x, key: %x, auth: %t",
			p.Value(),
			p.OffsetToNextPointer(),
			p.HasAddressDiversity(),
			p.DiversityData(),
			p.Key(),
			p.Authenticated(),
		)
	} else {
		pStr = fmt.Sprintf("value: %x, offset: %x", p.Value(), p.OffsetToNextPointer())
	}
	return pStr
}

type CacheLocalSymbolsInfo struct {
	NlistOffset   uint32 // offset into this chunk of nlist entries
	NlistCount    uint32 // count of nlist entries
	StringsOffset uint32 // offset into this chunk of string pool
	StringsSize   uint32 // byte count of string pool
	EntriesOffset uint32 // offset into this chunk of array of dyld_cache_local_symbols_entry
	EntriesCount  uint32 // number of elements in dyld_cache_local_symbols_entry array
}

type CacheLocalSymbolsEntry struct {
	DylibOffset     uint32 // offset in cache file of start of dylib
	NlistStartIndex uint32 // start index of locals for this dylib
	NlistCount      uint32 // number of local symbols for this dylib
}

type CacheLocalSymbol struct {
	Name  string
	Image string
	CacheLocalSymbolsEntry
}

// This is the symbol table entry structure for 32-bit architectures.
type nlist32 struct {
	nStrx  uint32 // index into the string table
	nType  uint8  // type flag, see below
	nSect  uint8  // section number or NO_SECT
	nDesc  uint16 // see <mach-o/stab.h>
	nValue uint32 // value of this symbol (or stab offset)
}

// This is the symbol table entry structure for 64-bit architectures.
type nlist64 struct {
	Strx  uint32 // index into the string table
	Type  uint8  // type flag, see below
	Sect  uint8  // section number or NO_SECT
	Desc  uint16 // see <mach-o/stab.h>
	Value uint64 // value of this symbol (or stab offset)
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
	UUID            macho.UUID
	LoadAddress     uint64 // unslid address of start of __TEXT
	TextSegmentSize uint32
	PathOffset      uint32 // offset from start of cache file
}
