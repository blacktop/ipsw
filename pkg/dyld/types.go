package dyld

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

const (
	MacOSCacheFolder      = "System/Library/dyld/"
	IPhoneCacheFolder     = "System/Library/Caches/com.apple.dyld/"
	DriverKitCacheFolder  = "System/DriverKit/System/Library/dyld/"
	ExclavekitCacheFolder = "/System/ExclaveKit/System/Library/dyld/"

	CacheRegex                           = `System/Library/(dyld|Caches/com\.apple\.dyld)/dyld_shared_cache_`
	DriverKitCacheRegex                  = `System/DriverKit/System/Library/dyld/dyld_shared_cache_`
	CacheRegexEnding                     = `(\..*)?$`
	CacheUberRegex                       = `(System/DriverKit/)?System/Library/(dyld|Caches/com\.apple\.dyld)/dyld_shared_cache_(arm64e|x86_64)(\..*)?$`
	DYLD_SHARED_CACHE_DYNAMIC_DATA_MAGIC = "dyld_data    v0"
)

var cryptexPrefixes = []string{
	"/System/Volumes/Preboot/Cryptexes/OS/",
	"/private/preboot/Cryptexes/OS/",
	"/System/Cryptexes/OS",
}

type formatVersion uint32

const (
	DylibsExpectedOnDisk   formatVersion = 0x100
	IsSimulator            formatVersion = 0x200
	LocallyBuiltCache      formatVersion = 0x400
	BuiltFromChainedFixups formatVersion = 0x800
)

type cacheType uint64

const (
	CacheTypeDevelopment cacheType = 0
	CacheTypeProduction  cacheType = 1
	CacheTypeUniversal   cacheType = 2
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

func (m maxSlide) Size() uint64 {
	return uint64(m >> 20)
}

func (m maxSlide) String() string {
	return fmt.Sprintf("0x%08X (ASLR entropy: %d-bits, %dMB)", uint64(m), m.EntropyBits(), m.Size())
}

type magic [16]byte

func (m magic) String() string {
	return strings.Trim(string(m[:]), "\x00")
}

// CacheHeader is the header for a dyld_shared_cache file (struct dyld_cache_header)
type CacheHeader struct {
	Magic                                       magic          // e.g. "dyld_v0    i386"
	MappingOffset                               uint32         // file offset to first dyld_cache_mapping_info
	MappingCount                                uint32         // number of dyld_cache_mapping_info entries
	ImagesOffsetOld                             uint32         // UNUSED: moved to imagesOffset to prevent older dsc_extarctors from crashing
	ImagesCountOld                              uint32         // UNUSED: moved to imagesCount to prevent older dsc_extarctors from crashing
	DyldBaseAddress                             uint64         // base address of dyld when cache was built
	CodeSignatureOffset                         uint64         // file offset of code signature blob
	CodeSignatureSize                           uint64         // size of code signature blob (zero means to end of file)
	SlideInfoOffsetUnused                       uint64         // unused.  Used to be file offset of kernel slid info
	SlideInfoSizeUnused                         uint64         // unused.  Used to be size of kernel slid info
	LocalSymbolsOffset                          uint64         // file offset of where local symbols are stored
	LocalSymbolsSize                            uint64         // size of local symbols information
	UUID                                        types.UUID     // unique value for each shared cache file
	CacheType                                   cacheType      // 0 for development, 1 for production
	BranchPoolsOffset                           uint32         // file offset to table of uint64_t pool addresses
	BranchPoolsCount                            uint32         // number of uint64_t entries
	AccelerateInfoAddrUnusedOrDyldAddr          uint64         // unused. (unslid) address of optimization info NOTE: when cacheType=2 (unslid) address of mach_header of dyld in cache
	AccelerateInfoSizeUnusedOrDyldStartFuncAddr uint64         // unused. size of optimization info             NOTE: when cacheType=2 (unslid) address of entry point (_dyld_start) of dyld in cache
	ImagesTextOffset                            uint64         // file offset to first dyld_cache_image_text_info
	ImagesTextCount                             uint64         // number of dyld_cache_image_text_info entries
	PatchInfoAddr                               uint64         // (unslid) address of dyld_cache_patch_info
	PatchInfoSize                               uint64         // Size of all of the patch information pointed to via the dyld_cache_patch_info
	OtherImageGroupAddrUnused                   uint64         // unused
	OtherImageGroupSizeUnused                   uint64         // unused
	ProgClosuresAddr                            uint64         // (unslid) address of list of program launch closures
	ProgClosuresSize                            uint64         // size of list of program launch closures
	ProgClosuresTrieAddr                        uint64         // (unslid) address of trie of indexes into program launch closures
	ProgClosuresTrieSize                        uint64         // size of trie of indexes into program launch closures
	Platform                                    types.Platform // platform number (macOS=1, etc)
	FormatVersion                               formatVersion  /* : 8,  // dyld3::closure::kFormatVersion
	   dylibsExpectedOnDisk   : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
	   simulator              : 1,  // for simulator of specified platform
	   locallyBuiltCache      : 1,  // 0 for B&I built cache, 1 for locally built cache
	   builtFromChainedFixups : 1,  // some dylib in cache was built using chained fixups, so patch tables must be used for overrides
	   padding                : 20; // TBD */
	SharedRegionStart      uint64   // base load address of cache if not slid
	SharedRegionSize       uint64   // overall size of region cache can be mapped into
	MaxSlide               maxSlide // runtime slide of cache can be between zero and this value
	DylibsImageArrayAddr   uint64   // (unslid) address of ImageArray for dylibs in this cache
	DylibsImageArraySize   uint64   // size of ImageArray for dylibs in this cache
	DylibsTrieAddr         uint64   // (unslid) address of trie of indexes of all cached dylibs
	DylibsTrieSize         uint64   // size of trie of cached dylib paths
	OtherImageArrayAddr    uint64   // (unslid) address of ImageArray for dylibs and bundles with dlopen closures
	OtherImageArraySize    uint64   // size of ImageArray for dylibs and bundles with dlopen closures
	OtherTrieAddr          uint64   // (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
	OtherTrieSize          uint64   // size of trie of dylibs and bundles with dlopen closures
	MappingWithSlideOffset uint32   // file offset to first dyld_cache_mapping_and_slide_info
	MappingWithSlideCount  uint32   // number of dyld_cache_mapping_and_slide_info entries
	/* NEW dyld4 fields */
	DylibsPblStateArrayAddrUnused uint64         // unused
	DylibsPblSetAddr              uint64         // (unslid) address of PrebuiltLoaderSet of all cached dylibs
	ProgramsPblSetPoolAddr        uint64         // (unslid) address of pool of PrebuiltLoaderSet for each program
	ProgramsPblSetPoolSize        uint64         // size of pool of PrebuiltLoaderSet for each program
	ProgramTrieAddr               uint64         // (unslid) address of trie mapping program path to PrebuiltLoaderSet
	ProgramTrieSize               uint32         //
	OsVersion                     types.Version  // OS Version of dylibs in this cache for the main platform
	AltPlatform                   types.Platform // e.g. iOSMac on macOS
	AltOsVersion                  types.Version  // e.g. 14.0 for iOSMac
	SwiftOptsOffset               uint64         // VM offset from cache_header* to Swift optimizations header
	SwiftOptsSize                 uint64         // size of Swift optimizations header
	SubCacheArrayOffset           uint32         // file offset to first dyld_subcache_entry
	SubCacheArrayCount            uint32         // number of subCache entries
	SymbolFileUUID                types.UUID     // unique value for the shared cache file containing unmapped local symbols
	RosettaReadOnlyAddr           uint64         // (unslid) address of the start of where Rosetta can add read-only/executable data
	RosettaReadOnlySize           uint64         // maximum size of the Rosetta read-only/executable region
	RosettaReadWriteAddr          uint64         // (unslid) address of the start of where Rosetta can add read-write data
	RosettaReadWriteSize          uint64         // maximum size of the Rosetta read-write region
	ImagesOffset                  uint32         // file offset to first dyld_cache_image_info
	ImagesCount                   uint32         // number of dyld_cache_image_info entries
	CacheSubType                  uint32         // 0 for development, 1 for production, when cacheType is multi-cache(2)
	_                             uint32         // padding
	ObjcOptsOffset                uint64         // VM offset from cache_header* to ObjC optimizations header
	ObjcOptsSize                  uint64         // size of ObjC optimizations header
	CacheAtlasOffset              uint64         // VM offset from cache_header* to embedded cache atlas for process introspection
	CacheAtlasSize                uint64         // size of embedded cache atlas
	DynamicDataOffset             uint64         // VM offset from cache_header* to the location of dyld_cache_dynamic_data_header
	DynamicDataMaxSize            uint64         // maximum size of space reserved from dynamic data
	TPROMappingOffset             uint32         // file offset to TPRO mappings  NEW in iOS 18.0 beta1 (hi mrmacete :P)
	TPROMappingCount              uint32         // TPRO mappings count           NEW in iOS 18.0 beta1 (is 1 for now; protects OBJC_RO)
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
	DYLD_CACHE_MAPPING_NONE        CacheMappingFlag = 0
	DYLD_CACHE_MAPPING_AUTH_DATA   CacheMappingFlag = 1 << 0
	DYLD_CACHE_MAPPING_DIRTY_DATA  CacheMappingFlag = 1 << 1
	DYLD_CACHE_MAPPING_CONST_DATA  CacheMappingFlag = 1 << 2
	DYLD_CACHE_MAPPING_TEXT_STUBS  CacheMappingFlag = 1 << 3
	DYLD_CACHE_DYNAMIC_CONFIG_DATA CacheMappingFlag = 1 << 4
	DYLD_CACHE_MAPPING_UNKNOWN     CacheMappingFlag = 1 << 5
	DYLD_CACHE_MAPPING_TPRO        CacheMappingFlag = 1 << 6
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
func (f CacheMappingFlag) IsTextStubs() bool {
	return (f & DYLD_CACHE_MAPPING_TEXT_STUBS) != 0
}
func (f CacheMappingFlag) IsConfigData() bool {
	return (f & DYLD_CACHE_DYNAMIC_CONFIG_DATA) != 0
}
func (f CacheMappingFlag) IsUnknown() bool {
	return (f & DYLD_CACHE_MAPPING_UNKNOWN) != 0
}
func (f CacheMappingFlag) IsTPRO() bool {
	return (f & DYLD_CACHE_MAPPING_TPRO) != 0
}
func (f CacheMappingFlag) String() string {
	var fStr []string
	if f.IsAuthData() {
		fStr = append(fStr, "AUTH_DATA")
	}
	if f.IsDirtyData() {
		fStr = append(fStr, "DIRTY_DATA")
	}
	if f.IsTPRO() {
		fStr = append(fStr, "TPRO")
	}
	if f.IsConstData() {
		fStr = append(fStr, "CONST_DATA")
	}
	if f.IsTextStubs() {
		fStr = append(fStr, "TEXT_STUBS")
	}
	if f.IsConfigData() {
		fStr = append(fStr, "CONFIG_DATA")
	}
	if f.IsUnknown() {
		fStr = append(fStr, "UNKNOWN")
	}
	if len(fStr) > 0 {
		return strings.Join(fStr, " | ")
	}
	return ""
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
	SlideInfo slideInfo
	Pages     []map[uint64]uint64
}

type CacheImageInfo struct {
	Address        uint64
	ModTime        uint64
	Inode          uint64
	PathFileOffset uint32
	Pad            uint32
}

type Rebase struct {
	CacheFileOffset uint64 `json:"cache_file_offset,omitempty"`
	CacheVMAddress  uint64 `json:"cache_vm_address,omitempty"`
	Target          uint64 `json:"target,omitempty"`
	Pointer         any    `json:"pointer,omitempty"`
	Symbol          string `json:"symbol,omitempty"`
}

type slideInfo interface {
	GetVersion() uint32
	GetPageSize() uint32
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
func (i CacheSlideInfo) GetPageSize() uint32 {
	return 0
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
func (i CacheSlideInfo2) GetPageSize() uint32 {
	return i.PageSize
}
func (i CacheSlideInfo2) SlidePointer(ptr uint64) uint64 {
	shift := uint64(bits.Len64(i.ValueAdd))
	mask := uint64(1<<64-1) >> shift << shift
	if ptr > i.ValueAdd && (ptr&mask) == 0 {
		return ptr
	}
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
	Version         uint32 `json:"slide_version,omitempty"` // currently 3
	PageSize        uint32 `json:"page_size,omitempty"`     // currently 4096 (may also be 16384)
	PageStartsCount uint32 `json:"page_starts_count,omitempty"`
	_               uint32 // padding for 64bit alignment
	AuthValueAdd    uint64 `json:"auth_value_add,omitempty"`
	// PageStarts      []uint16 /* len() = page_starts_count */
}

func (i CacheSlideInfo3) GetVersion() uint32 {
	return i.Version
}
func (i CacheSlideInfo3) GetPageSize() uint32 {
	return i.PageSize
}
func (i CacheSlideInfo3) SlidePointer(ptr uint64) uint64 {
	if ptr == 0 {
		return 0
	} else if (ptr & 0xFFF8_0000_0000_0000) == 0 {
		return ptr
	}
	pointer := CacheSlidePointer3(ptr)
	if pointer.Authenticated() {
		return i.AuthValueAdd + pointer.OffsetFromSharedCacheBase()
	}
	return pointer.SignExtend51()
}

const DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFFF // page has no rebasing

// CacheSlidePointer3 struct
//
//	{
//	    uint64_t  raw;
//	    struct {
//	        uint64_t    pointerValue        : 51,
//	                    offsetToNextPointer : 11,
//	                    unused              :  2;
//	    }         plain;
//	    struct {
//	        uint64_t    offsetFromSharedCacheBase : 32,
//	                    diversityData             : 16,
//	                    hasAddressDiversity       :  1,
//	                    key                       :  2,
//	                    offsetToNextPointer       : 11,
//	                    unused                    :  1,
//	                    authenticated             :  1; // = 1;
//	    }         auth;
//	};
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

func (p CacheSlidePointer3) MarshalJSON() ([]byte, error) {
	if p.Authenticated() {
		return json.Marshal(&struct {
			Value               uint64 `json:"value"`
			OffsetToNextPointer uint64 `json:"next"`
			DiversityData       uint64 `json:"diversity"`
			HasAddressDiversity bool   `json:"addr_div"`
			KeyName             string `json:"key"`
			Authenticated       bool   `json:"authenticated"`
		}{
			Value:               p.Value(),
			OffsetToNextPointer: p.OffsetToNextPointer(),
			DiversityData:       p.DiversityData(),
			HasAddressDiversity: p.HasAddressDiversity(),
			KeyName:             KeyName(uint64(p)),
			Authenticated:       p.Authenticated(),
		})
	} else {
		return json.Marshal(&struct {
			Value               uint64 `json:"value"`
			OffsetToNextPointer uint64 `json:"next"`
		}{
			Value:               p.Value(),
			OffsetToNextPointer: p.OffsetToNextPointer(),
		})
	}
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
func (i CacheSlideInfo4) GetPageSize() uint32 {
	return i.PageSize
}
func (i CacheSlideInfo4) SlidePointer(ptr uint64) uint64 {
	// if ptr > i.ValueAdd { FIXME: do I need to add this ?
	// 	return ptr
	// }
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

type CacheSlideInfo5 struct {
	Version         uint32 `json:"slide_version,omitempty"` // currently 5
	PageSize        uint32 `json:"page_size,omitempty"`     //  currently 4096 (may also be 16384)
	PageStartsCount uint32 `json:"page_starts_count,omitempty"`
	_               uint32 // padding for 64bit alignment
	ValueAdd        uint64 `json:"value_add,omitempty"`
	// PageStarts      []uint16 /* len() = page_starts_count */
}

const DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE = 0xFFFF // page has no rebasing

func (i CacheSlideInfo5) GetVersion() uint32 {
	return i.Version
}
func (i CacheSlideInfo5) GetPageSize() uint32 {
	return i.PageSize
}
func (i CacheSlideInfo5) SlidePointer(ptr uint64) uint64 {
	if ptr == 0 {
		return 0
	}
	pointer := CacheSlidePointer5(ptr)
	if pointer.Authenticated() {
		return i.ValueAdd + pointer.Value()
	}
	return i.ValueAdd + pointer.SignExtend51()
}

// CacheSlidePointer5 struct
//
// The version 5 of the slide info uses a different compression scheme. Since
// only interior pointers (pointers that point within the cache) are rebased
// (slid), we know the possible range of the pointers and thus know there are
// unused bits in each pointer.  We use those bits to form a linked list of
// locations needing rebasing in each page.
//
// Definitions:
//
//	pageIndex = (pageAddress - startOfAllDataAddress)/info->page_size
//	pageStarts[] = info + info->page_starts_offset
//
// There are two cases:
//
//  1. pageStarts[pageIndex] == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE
//     The page contains no values that need rebasing.
//
//  2. otherwise...
//     All rebase locations are in one linked list. The offset of the first
//     rebase location in the page is pageStarts[pageIndex].
//
// A pointer is one of of the variants in dyld_cache_slide_pointer5
//
// The code for processing a linked list (chain) is:
//
//	uint32_t delta = pageStarts[pageIndex];
//	dyld_cache_slide_pointer5* loc = pageStart;
//	do {
//	    loc += delta;
//	    delta = loc->offsetToNextPointer;
//	    newValue = loc->regular.target + value_add + results->slide;
//	    if ( loc->auth.authenticated ) {
//	        newValue = sign_using_the_various_bits(newValue);
//	    }
//	    else {
//	        newValue = newValue | (loc->regular.high8 < 56);
//	    }
//	    loc->raw = newValue;
//	} while (delta != 0);
type CacheSlidePointer5 uint64

// SignExtend51 returns a regular pointer which needs to fit in 51-bits of value.
// C++ RTTI uses the top bit, so we'll allow the whole top-byte
// and the signed-extended bottom 43-bits to be fit in to 51-bits.
func (p CacheSlidePointer5) SignExtend51() uint64 {
	top8Bits := uint64(p & 0x007F80000000000)
	bottom43Bits := uint64(p & 0x000007FFFFFFFFFF)
	return (top8Bits << 13) | (((uint64)(bottom43Bits<<21) >> 21) & 0x00FFFFFFFFFFFFFF)
}

// Raw returns the chained pointer's raw uint64 value
func (p CacheSlidePointer5) Raw() uint64 {
	return uint64(p)
}

// Value returns the chained pointer's value
func (p CacheSlidePointer5) Value() uint64 {
	return types.ExtractBits(uint64(p), 0, 34) // runtimeOffset - offset from the start of the shared cache
}

func (p CacheSlidePointer5) High8() uint64 {
	return types.ExtractBits(uint64(p), 34, 8)
}

// OffsetToNextPointer returns the offset to the next chained pointer
func (p CacheSlidePointer5) OffsetToNextPointer() uint64 {
	return types.ExtractBits(uint64(p), 52, 11)
}

// OffsetFromSharedCacheBase returns the chained pointer's offset from the base
func (p CacheSlidePointer5) OffsetFromSharedCacheBase() uint64 {
	return types.ExtractBits(uint64(p), 0, 32)
}

// DiversityData returns the chained pointer's diversity data
func (p CacheSlidePointer5) DiversityData() uint64 {
	return types.ExtractBits(uint64(p), 34, 16)
}

// HasAddressDiversity returns if the chained pointer has address diversity
func (p CacheSlidePointer5) HasAddressDiversity() bool {
	return types.ExtractBits(uint64(p), 50, 1) != 0
}

// Key returns the chained pointer's key
func (p CacheSlidePointer5) Key() uint64 {
	return types.ExtractBits(uint64(p), 51, 1)
}

// Authenticated returns if the chained pointer is authenticated
func (p CacheSlidePointer5) Authenticated() bool {
	return types.ExtractBits(uint64(p), 63, 1) != 0
}

// KeyName returns the chained pointer's key name
func KeyNameV5(key uint64) string {
	name := []string{"IA", "DA"}
	if key >= 2 {
		return "ERROR"
	}
	return name[key]
}

func (p CacheSlidePointer5) String() string {
	if p.Authenticated() {
		return fmt.Sprintf("value: %#x, next: %02x, diversity: %04x, addr_div: %t, key: %s, auth: %t",
			p.Value(),
			p.OffsetToNextPointer(),
			p.DiversityData(),
			p.HasAddressDiversity(),
			KeyNameV5(p.Key()),
			p.Authenticated(),
		)
	}
	return fmt.Sprintf("value: %#x, next: %02x", p.Value(), p.OffsetToNextPointer())
}

func (p CacheSlidePointer5) MarshalJSON() ([]byte, error) {
	if p.Authenticated() {
		return json.Marshal(&struct {
			Value               uint64 `json:"value"`
			OffsetToNextPointer uint64 `json:"next"`
			DiversityData       uint64 `json:"diversity"`
			HasAddressDiversity bool   `json:"addr_div"`
			KeyName             string `json:"key"`
			Authenticated       bool   `json:"authenticated"`
		}{
			Value:               p.Value(),
			OffsetToNextPointer: p.OffsetToNextPointer(),
			DiversityData:       p.DiversityData(),
			HasAddressDiversity: p.HasAddressDiversity(),
			KeyName:             KeyNameV5(p.Key()),
			Authenticated:       p.Authenticated(),
		})
	} else {
		return json.Marshal(&struct {
			Value               uint64 `json:"value"`
			OffsetToNextPointer uint64 `json:"next"`
		}{
			Value:               p.Value(),
			OffsetToNextPointer: p.OffsetToNextPointer(),
		})
	}
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
	DylibOffset     uint32 // offset in cache file of start of dylib
	NlistStartIndex uint32 // start index of locals for this dylib
	NlistCount      uint32 // number of local symbols for this dylib
}

type CacheLocalSymbolsEntry64 struct {
	DylibOffset     uint64 // offset in cache file of start of dylib
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
	Macho        *macho.File
}

func (s CacheLocalSymbol64) String(color bool) string {
	var sec string
	var found string
	if s.Macho != nil {
		if s.Sect > 0 && s.Macho.Sections != nil {
			sec = fmt.Sprintf("%s.%s", s.Macho.Sections[s.Sect-1].Seg, s.Macho.Sections[s.Sect-1].Name)
		}
	}
	if len(s.FoundInDylib) > 0 {
		found = fmt.Sprintf("\t%s", filepath.Base(s.FoundInDylib))
	}
	if color {
		return fmt.Sprintf("%s:\t%s\t%s\t%s",
			symAddrColor("%#09x", s.Value),
			symTypeColor("(%s)", s.Type.String(sec)),
			symNameColor(s.Name),
			symImageColor(found))
	}
	// if s.Nlist64.Desc.GetLibraryOrdinal() != 0 { // TODO: I haven't seen this trigger in the iPhone14,2_D63AP_19D5026g/dyld_shared_cache_arm64e I tested
	// 	return fmt.Sprintf("%#09x:\t(%s|%s)\t%s%s", s.Value, s.Type.String(sec), s.Macho.LibraryOrdinalName(int(s.Nlist64.Desc.GetLibraryOrdinal())), s.Name, found)
	// }
	return fmt.Sprintf("%#09x:\t(%s)\t%s%s", s.Value, s.Type.String(sec), s.Name, found)
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

type CachePatchInfoV1 struct {
	PatchTableArrayAddr     uint64 // (unslid) address of array for dyld_cache_image_patches for each image
	PatchTableArrayCount    uint64 // count of patch table entries
	PatchExportArrayAddr    uint64 // (unslid) address of array for patch exports for each image
	PatchExportArrayCount   uint64 // count of patch exports entries
	PatchLocationArrayAddr  uint64 // (unslid) address of array for patch locations for each patch
	PatchLocationArrayCount uint64 // count of patch location entries
	PatchExportNamesAddr    uint64 // blob of strings of export names for patches
	PatchExportNamesSize    uint64 // size of string blob of export names for patches
}

type CacheImagePatchesV1 struct {
	PatchExportsStartIndex uint32
	PatchExportsCount      uint32
}

type CachePatchableExportV1 struct {
	CacheOffsetOfImpl        uint32
	PatchLocationsStartIndex uint32
	PatchLocationsCount      uint32
	ExportNameOffset         uint32
}

type CachePatchableLocationV1 struct {
	CacheOffset uint32
	// _           uint32 // padding TODO: FIXME do I need this padding or not
	Location uint64
}

func (p CachePatchableLocationV1) Address(cacheBase uint64) uint64 {
	return uint64(p.CacheOffset) + cacheBase
}
func (p CachePatchableLocationV1) High7() uint64 {
	return types.ExtractBits(uint64(p.Location), 0, 7)
}
func (p CachePatchableLocationV1) Addend() uint64 {
	return types.ExtractBits(uint64(p.Location), 7, 5) // 0..31
}
func (p CachePatchableLocationV1) Authenticated() bool {
	return types.ExtractBits(uint64(p.Location), 12, 1) != 0
}
func (p CachePatchableLocationV1) UsesAddressDiversity() bool {
	return types.ExtractBits(uint64(p.Location), 13, 1) != 0
}
func (p CachePatchableLocationV1) Key() uint64 {
	return types.ExtractBits(uint64(p.Location), 14, 2)
}
func (p CachePatchableLocationV1) Discriminator() uint64 {
	return types.ExtractBits(uint64(p.Location), 16, 16)
}

func (p CachePatchableLocationV1) String(cacheBase uint64) string {
	var detail []string
	if p.UsesAddressDiversity() {
		detail = append(detail, fmt.Sprintf("diversity: %#04x", p.Discriminator()))
	}
	if p.Addend() > 0 {
		detail = append(detail, fmt.Sprintf("addend: %#x", p.Addend()))
	}
	if p.Authenticated() {
		detail = append(detail, fmt.Sprintf("key: %s, auth: %t", KeyName(uint64(p.Key())), p.Authenticated()))
	}
	if len(detail) > 0 {
		return fmt.Sprintf("%#x: (%s)", p.Address(cacheBase), strings.Join(detail, ", "))
	}
	return fmt.Sprintf("%#x:", p.Address(cacheBase))
}

// Patches can be different kinds.  This lives in the high nibble of the exportNameOffset,
// so we restrict these to 4-bits
type PatchKind uint8

const (
	// Just a normal patch. Isn't one of ther other kinds
	Regular PatchKind = 0x0
	// One of { void* isa, uintptr_t }, from CF
	CfObj2 PatchKind = 0x1
	// objc patching was added before this enum exists, in just the high bit
	// of the 4-bit nubble.  This matches that bit layout
	ObjcClass PatchKind = 0x8
)

func (k PatchKind) String() string {
	switch k {
	case Regular:
		return ""
	case CfObj2:
		return "(CF obj2) "
	case ObjcClass:
		return "(objc class) "
	default:
		return fmt.Sprintf("(unknown(%d)) ", k)
	}
}

type CachePatchInfoV2 struct {
	TableVersion            uint32 // == 2
	LocationVersion         uint32 // == 0 for now
	TableArrayAddr          uint64 // (unslid) address of array for dyld_cache_image_patches_v2 for each image
	TableArrayCount         uint64 // count of patch table entries
	ImageExportsArrayAddr   uint64 // (unslid) address of array for dyld_cache_image_export_v2 for each image
	ImageExportsArrayCount  uint64 // count of patch table entries
	ClientsArrayAddr        uint64 // (unslid) address of array for dyld_cache_image_clients_v2 for each image
	ClientsArrayCount       uint64 // count of patch clients entries
	ClientExportsArrayAddr  uint64 // (unslid) address of array for patch exports for each client image
	ClientExportsArrayCount uint64 // count of patch exports entries
	LocationArrayAddr       uint64 // (unslid) address of array for patch locations for each patch
	LocationArrayCount      uint64 // count of patch location entries
	ExportNamesAddr         uint64 // blob of strings of export names for patches
	ExportNamesSize         uint64 // size of string blob of export names for patches
}

type CacheImagePatchesV2 struct {
	ClientsStartIndex uint32
	ClientsCount      uint32
	ExportsStartIndex uint32 // Points to dyld_cache_image_export_v2[]
	ExportsCount      uint32
}

type CacheImageExportV2 struct {
	DylibOffsetOfImpl uint32 // Offset from the dylib we used to find a dyld_cache_image_patches_v2
	ExportNameOffset  uint32
}

func (e CacheImageExportV2) GetExportNameOffset() uint32 {
	return uint32(types.ExtractBits(uint64(e.ExportNameOffset), 0, 28))
}
func (e CacheImageExportV2) GetPatchKind() PatchKind {
	return PatchKind(types.ExtractBits(uint64(e.ExportNameOffset), 28, 4))
}

type CacheImageClientsV2 struct {
	ClientDylibIndex       uint32
	PatchExportsStartIndex uint32 // Points to dyld_cache_patchable_export_v2[]
	PatchExportsCount      uint32
}

type CachePatchableExportV2 struct {
	ImageExportIndex         uint32 // Points to dyld_cache_image_export_v2
	PatchLocationsStartIndex uint32 // Points to dyld_cache_patchable_location_v2[]
	PatchLocationsCount      uint32
}

type CachePatchableLocationV2 struct {
	DylibOffsetOfUse uint32 // Offset from the dylib we used to get a dyld_cache_image_clients_v2
	Location         patchableLocationV2
}

func (p CachePatchableLocationV2) String(preferredLoadAddress uint64) string {
	var detail []string
	if p.Location.UsesAddressDiversity() {
		detail = append(detail, fmt.Sprintf("diversity: %#04x", p.Location.Discriminator()))
	}
	if p.Location.Addend() > 0 {
		detail = append(detail, fmt.Sprintf("addend: %#x", p.Location.Addend()))
	}
	if p.Location.Authenticated() {
		detail = append(detail, fmt.Sprintf("key: %s, auth: %t", KeyName(uint64(p.Location.Key())), p.Location.Authenticated()))
	}
	if len(detail) > 0 {
		return fmt.Sprintf("%#x: (%s)", preferredLoadAddress+uint64(p.DylibOffsetOfUse), strings.Join(detail, ", "))
	}
	return fmt.Sprintf("%#x:", preferredLoadAddress+uint64(p.DylibOffsetOfUse))
}

type patchableLocationV2 uint32

func (p patchableLocationV2) High7() uint32 {
	return uint32(types.ExtractBits(uint64(p), 0, 7))
}
func (p patchableLocationV2) Addend() uint64 {
	return types.ExtractBits(uint64(p), 7, 5) // 0..31
}
func (p patchableLocationV2) Authenticated() bool {
	return uint32(types.ExtractBits(uint64(p), 12, 1)) != 0
}
func (p patchableLocationV2) UsesAddressDiversity() bool {
	return uint32(types.ExtractBits(uint64(p), 13, 1)) != 0
}
func (p patchableLocationV2) Key() uint32 {
	return uint32(types.ExtractBits(uint64(p), 14, 2))
}
func (p patchableLocationV2) Discriminator() uint32 {
	return uint32(types.ExtractBits(uint64(p), 16, 16))
}

type CachePatchInfoV3 struct {
	CachePatchInfoV2                  // v2 fields with TableVersion == 3
	GotClientsArrayAddr        uint64 // (unslid) address of array for dyld_cache_image_got_clients_v3 for each image
	GotClientsArrayCount       uint64 // count of got clients entries.  Should always match the patchTableArrayCount
	GotClientExportsArrayAddr  uint64 // (unslid) address of array for patch exports for each GOT image
	GotClientExportsArrayCount uint64 // count of patch exports entries
	GotLocationArrayAddr       uint64 // (unslid) address of array for patch locations for each GOT patch
	GotLocationArrayCount      uint64 // count of patch location entries
}

type CacheImageGotClientsV3 struct {
	PatchExportsStartIndex uint32 // Points to dyld_cache_patchable_export_v3[]
	PatchExportsCount      uint32
}

type CachePatchableExportV3 struct {
	ImageExportIndex         uint32 // Points to dyld_cache_image_export_v2
	PatchLocationsStartIndex uint32 // Points to dyld_cache_patchable_location_v3[]
	PatchLocationsCount      uint32
}

type CachePatchableLocationV3 struct {
	CacheOffsetOfUse uint64 // Offset from the cache header
	Location         patchableLocationV2
	_                uint32 // padding
}

func (p CachePatchableLocationV3) String(o2a func(uint64) uint64) string {
	var detail []string
	if p.Location.UsesAddressDiversity() {
		detail = append(detail, fmt.Sprintf("diversity: %#04x", p.Location.Discriminator()))
	}
	if p.Location.Addend() > 0 {
		detail = append(detail, fmt.Sprintf("addend: %#x", p.Location.Addend()))
	}
	if p.Location.Authenticated() {
		detail = append(detail, fmt.Sprintf("key: %s, auth: %t", KeyName(uint64(p.Location.Key())), p.Location.Authenticated()))
	}
	if len(detail) > 0 {
		return fmt.Sprintf("%#x: (%s)", o2a(p.CacheOffsetOfUse), strings.Join(detail, ", "))
	}
	return fmt.Sprintf("%#x:", o2a(p.CacheOffsetOfUse))
}

type CachePatchInfoV4 CachePatchInfoV3

type CachePatchableLocationV4 struct {
	DylibOffsetOfUse uint32 // Offset from the dylib we used to get a dyld_cache_image_clients_v2
	Location         patchableLocationV4
}

func (p CachePatchableLocationV4) String(preferredLoadAddress uint64) string {
	var detail []string
	if p.Location.Authenticated() {
		if p.Location.UsesAddressDiversity() {
			detail = append(detail, fmt.Sprintf("diversity: %#04x", p.Location.Discriminator()))
		}
		key := "IA"
		if p.Location.IsDataKey() {
			key = "DA"
		}
		detail = append(detail, fmt.Sprintf("key: %s, auth: %t", key, p.Location.Authenticated()))
	}
	if p.Location.Addend() > 0 {
		detail = append(detail, fmt.Sprintf("addend: %#x", p.Location.Addend()))
	}
	if p.Location.IsWeakImport() {
		detail = append(detail, "weak_import")
	}
	if len(detail) > 0 {
		return fmt.Sprintf("%s: PATCH\t%s", symDarkAddrColor("%#09x", preferredLoadAddress+uint64(p.DylibOffsetOfUse)), symTypeColor("(%s)", strings.Join(detail, ", ")))
	}
	return fmt.Sprintf("%s: PATCH\t", symDarkAddrColor("%#09x", preferredLoadAddress+uint64(p.DylibOffsetOfUse)))
}

type patchableLocationV4 uint32

func (p patchableLocationV4) Authenticated() bool {
	return uint32(types.ExtractBits(uint64(p), 0, 1)) != 0
}
func (p patchableLocationV4) High7() uint32 {
	return uint32(types.ExtractBits(uint64(p), 1, 7))
}
func (p patchableLocationV4) IsWeakImport() bool {
	return uint32(types.ExtractBits(uint64(p), 8, 1)) != 0
}
func (p patchableLocationV4) Addend() uint64 {
	if p.Authenticated() {
		return types.ExtractBits(uint64(p), 9, 5) // 0..31
	}
	return types.ExtractBits(uint64(p), 9, 23)
}
func (p patchableLocationV4) UsesAddressDiversity() bool {
	return uint32(types.ExtractBits(uint64(p), 14, 1)) != 0
}
func (p patchableLocationV4) IsDataKey() bool {
	return uint32(types.ExtractBits(uint64(p), 15, 1)) != 0 // B keys are not permitted.  So this is just whether the A key is I or D (0 => I, 1 => D)
}
func (p patchableLocationV4) Discriminator() uint32 {
	return uint32(types.ExtractBits(uint64(p), 16, 16))
}

type CachePatchableLocationV4Got struct {
	CacheOffsetOfUse uint64 // Offset from the cache header
	Location         patchableLocationV4
	_                uint32 // padding
}

func (p CachePatchableLocationV4Got) String(o2a func(uint64) uint64) string {
	var detail []string
	if p.Location.Authenticated() {
		if p.Location.UsesAddressDiversity() {
			detail = append(detail, fmt.Sprintf("diversity: %#04x", p.Location.Discriminator()))
		}
		key := "IA"
		if p.Location.IsDataKey() {
			key = "DA"
		}
		detail = append(detail, fmt.Sprintf("key: %s, auth: %t", key, p.Location.Authenticated()))
	}
	if p.Location.Addend() > 0 {
		detail = append(detail, fmt.Sprintf("addend: %#x", p.Location.Addend()))
	}
	if p.Location.IsWeakImport() {
		detail = append(detail, "weak_import")
	}
	if len(detail) > 0 {
		return fmt.Sprintf("%s: GOT\t%s", symDarkAddrColor("%#09x", o2a(p.CacheOffsetOfUse)), symTypeColor("(%s)", strings.Join(detail, ", ")))
	}
	return fmt.Sprintf("%s: GOT\t", symDarkAddrColor("%#09x", o2a(p.CacheOffsetOfUse)))
}

type SubcacheEntry struct {
	UUID          types.UUID
	CacheVMOffset uint64
	Extention     string
}

type subcacheEntryV1 struct {
	UUID          types.UUID
	CacheVMOffset uint64
}

type subcacheEntry struct {
	UUID          types.UUID
	CacheVMOffset uint64
	FileSuffix    [32]byte
}

type TPROMapping struct {
	Addr uint64
	Size uint64
}

// This struct is a small piece of dynamic data that can be included in the shared region, and contains configuration
// data about the shared cache in use by the process. It is located
type CacheDynamicDataHeader struct {
	Magic   [16]uint8 // e.g. "dyld_data    v0"
	FsID    uint64    // The fsid_t of the shared cache being used by a process
	FsObjID uint64    // The fs_obj_id_t of the shared cache being used by a process
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
