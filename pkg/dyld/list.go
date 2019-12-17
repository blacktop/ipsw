package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/dustin/go-humanize"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
)

type DyldCache struct {
	header   DyldCacheHeader
	mappings []DyldCacheMappingInfo
	images   []DyldCacheImageInfo
}

type DyldCacheHeader struct {
	Magic                [16]byte // e.g. "dyld_v0    i386"
	MappingOffset        uint32   // file offset to first dyld_cache_mapping_info
	MappingCount         uint32   // number of dyld_cache_mapping_info entries
	ImagesOffset         uint32   // file offset to first dyld_cache_image_info
	ImagesCount          uint32   // number of dyld_cache_image_info entries
	DyldBaseAddress      uint64   // base address of dyld when cache was built
	CodeSignatureOffset  uint64   // file offset of code signature blob
	CodeSignatureSize    uint64   // size of code signature blob (zero means to end of file)
	SlideInfoOffset      uint64   // file offset of kernel slid info
	SlideInfoSize        uint64   // size of kernel slid info
	LocalSymbolsOffset   uint64   // file offset of where local symbols are stored
	LocalSymbolsSize     uint64   // size of local symbols information
	UUID                 UUID     // unique value for each shared cache file
	CacheType            uint64   // 0 for development, 1 for production
	BranchPoolsOffset    uint32   // file offset to table of uint64_t pool addresses
	BranchPoolsCount     uint32   // number of uint64_t entries
	AccelerateInfoAddr   uint64   // (unslid) address of optimization info
	AccelerateInfoSize   uint64   // size of optimization info
	ImagesTextOffset     uint64   // file offset to first dyld_cache_image_text_info
	ImagesTextCount      uint64   // number of dyld_cache_image_text_info entries
	DylibsImageGroupAddr uint64   // (unslid) address of ImageGroup for dylibs in this cache
	DylibsImageGroupSize uint64   // size of ImageGroup for dylibs in this cache
	OtherImageGroupAddr  uint64   // (unslid) address of ImageGroup for other OS dylibs
	OtherImageGroupSize  uint64   // size of oImageGroup for other OS dylibs
	ProgClosuresAddr     uint64   // (unslid) address of list of program launch closures
	ProgClosuresSize     uint64   // size of list of program launch closures
	ProgClosuresTrieAddr uint64   // (unslid) address of trie of indexes into program launch closures
	ProgClosuresTrieSize uint64   // size of trie of indexes into program launch closures
	Platform             Platform // platform number (macOS=1, etc)
	FormatVersion        uint8    // dyld3::closure::kFormatVersion
	Padding8             uint8
	Padding16            uint16
	// uint32_t    formatVersion        : 8,  // dyld3::closure::kFormatVersion
	//             dylibsExpectedOnDisk : 1,  // dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
	//             simulator            : 1,  // for simulator of specified platform
	//             locallyBuiltCache    : 1,  // 0 for B&I built cache, 1 for locally built cache
	//             padding              : 21; // TBD
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

type UUID [16]byte

func (self UUID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		self[0], self[1], self[2], self[3],
		self[4], self[5], self[6], self[7],
		self[8], self[9], self[10], self[11],
		self[12], self[13], self[14], self[15])
}

type Platform uint32

const (
	unknown          Platform = 0
	macOS            Platform = 1 // PLATFORM_MACOS
	iOS              Platform = 2 // PLATFORM_IOS
	tvOS             Platform = 3 // PLATFORM_TVOS
	watchOS          Platform = 4 // PLATFORM_WATCHOS
	bridgeOS         Platform = 5 // PLATFORM_BRIDGEOS
	iOSMac           Platform = 6 // PLATFORM_IOSMAC
	iOSSimulator     Platform = 7 // PLATFORM_IOSSIMULATOR
	tvOSSimulator    Platform = 8 // PLATFORM_TVOSSIMULATOR
	watchOSSimulator Platform = 9 // PLATFORM_WATCHOSSIMULATOR
)

func (p Platform) String() string {
	names := [...]string{
		"unknown",
		"macOS",
		"iOS",
		"tvOS",
		"watchOS",
		"bridgeOS",
		"iOSMac",
		"iOS Simulator",
		"tvOS Simulator",
		"watchOS Simulator"}
	return names[p]
}

type VMProtection int32

func (self VMProtection) Read() bool {
	return (self & 0x01) != 0
}

func (self VMProtection) Write() bool {
	return (self & 0x02) != 0
}

func (self VMProtection) Execute() bool {
	return (self & 0x04) != 0
}

func (self VMProtection) String() string {
	var protStr string
	if self.Read() {
		protStr += "r"
	} else {
		protStr += "-"
	}
	if self.Write() {
		protStr += "w"
	} else {
		protStr += "-"
	}
	if self.Execute() {
		protStr += "x"
	} else {
		protStr += "-"
	}
	return protStr
}

type DyldCacheMappingInfo struct {
	Address    uint64
	Size       uint64
	FileOffset uint64
	MaxProt    VMProtection
	InitProt   VMProtection
}

type DyldCacheImageInfo struct {
	Address        uint64
	ModTime        uint64
	Inode          uint64
	PathFileOffset uint32
	Pad            uint32
}

// The rebasing info is to allow the kernel to lazily rebase DATA pages of the
// dyld shared cache.  Rebasing is adding the slide to interior pointers.
type DyldCacheSlideInfo struct {
	Version       uint32 // currently 1
	TocOffset     uint32
	TocCount      uint32
	EntriesOffset uint32
	EntriesCount  uint32
	EntriesSize   uint32 // currently 128
	// uint16_t toc[toc_count];
	// entrybitmap entries[entries_count];
}

type DyldCacheLocalSymbolsInfo struct {
	NlistOffset   uint32 // offset into this chunk of nlist entries
	NlistCount    uint32 // count of nlist entries
	StringsOffset uint32 // offset into this chunk of string pool
	StringsSize   uint32 // byte count of string pool
	EntriesOffset uint32 // offset into this chunk of array of dyld_cache_local_symbols_entry
	EntriesCount  uint32 // number of elements in dyld_cache_local_symbols_entry array
}

type DyldCacheLocalSymbolsEntry struct {
	DylibOffset     uint32 // offset in cache file of start of dylib
	NlistStartIndex uint32 // start index of locals for this dylib
	NlistCount      uint32 // number of local symbols for this dylib
}

type DyldCacheImageInfoExtra struct {
	ExportsTrieAddr           uint64 // address of trie in unslid cache
	WeakBindingsAddr          uint64
	ExportsTrieSize           uint32
	WeakBindingsSize          uint32
	DependentsStartArrayIndex uint32
	ReExportsStartArrayIndex  uint32
}

type DyldCacheAcceleratorInfo struct {
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

type DyldCacheAcceleratorInitializer struct {
	FunctionOffset uint32 // address offset from start of cache mapping
	ImageIndex     uint32
}

type DyldCacheRangeEntry struct {
	StartAddress uint64 // unslid address of start of region
	Size         uint32
	ImageIndex   uint32
}

type DyldCacheAcceleratorDof struct {
	SectionAddress uint64 // unslid address of start of region
	SectionSize    uint32
	ImageIndex     uint32
}

type DyldCacheImageTextInfo struct {
	UUID            UUID
	LoadAddress     uint64 // unslid address of start of __TEXT
	TextSegmentSize uint32
	PathOffset      uint32 // offset from start of cache file
}

func (self DyldCacheHeader) String() string {
	var magicBytes []byte = self.Magic[:]

	return fmt.Sprintf(
		"Magic               = %s\n"+
			"MappingOffset       = %08X\n"+
			"MappingCount        = %d\n"+
			"ImagesOffset        = %08X\n"+
			"ImagesCount         = %d\n"+
			"DyldBaseAddress     = %08X\n"+
			"CodeSignatureOffset = %08X\n"+
			"CodeSignatureSize   = %08X\n"+
			"SlideInfoOffset     = %08X\n"+
			"SlideInfoSize       = %08X\n"+
			"LocalSymbolsOffset  = %08X\n"+
			"LocalSymbolsSize    = %08X\n"+
			"UUID                = %s\n"+
			"Platform            = %s\n"+
			"Format              = %d\n",
		bytes.Trim(magicBytes, "\x00"),
		self.MappingOffset,
		self.MappingCount,
		self.ImagesOffset,
		self.ImagesCount,
		self.DyldBaseAddress,
		self.CodeSignatureOffset,
		self.CodeSignatureSize,
		self.SlideInfoOffset,
		self.SlideInfoSize,
		self.LocalSymbolsOffset,
		self.LocalSymbolsSize,
		self.UUID.String(),
		self.Platform.String(),
		self.FormatVersion,
	)
}

func (self DyldCacheMappingInfo) String() string {
	return fmt.Sprintf(
		"Address    = %016X\n"+
			"Size       = %s\n"+
			"FileOffset = %X\n"+
			"MaxProt    = %s\n"+
			"InitProt   = %s\n",
		self.Address,
		humanize.Bytes(self.Size),
		self.FileOffset,
		self.MaxProt.String(),
		self.InitProt.String(),
	)
}

func (self DyldCacheImageInfo) String() string {
	return fmt.Sprintf(
		"Address        = %016X\n"+
			"ModTime        = %016X\n"+
			"Inode          = %d\n"+
			"PathFileOffset = %08X\n",
		self.Address,
		self.ModTime,
		self.Inode,
		self.PathFileOffset,
	)
}

func readNextBytes(file *os.File, number int) []byte {
	bytes := make([]byte, number)

	_, err := file.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}

// Parse parses a dyld_share_cache
func Parse(dsc string) error {

	dCache := DyldCache{}

	file, err := os.Open(dsc)
	if err != nil {
		return errors.Wrapf(err, "failed to open file: %s", dsc)
	}
	defer file.Close()

	// fileInfo, err := file.Stat()
	// if err != nil {
	// 	return errors.Wrapf(err, "failed to stat file: %s", dsc)
	// }

	data := readNextBytes(file, int(unsafe.Sizeof(dCache.header)))

	if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &dCache.header); err != nil {
		return err
	}
	fmt.Println("Header")
	fmt.Println("======")
	fmt.Println(dCache.header.String())

	fmt.Println("Mappings")
	fmt.Println("========")
	file.Seek(int64(dCache.header.MappingOffset), os.SEEK_SET)
	for i := uint32(0); i != dCache.header.MappingCount; i++ {
		mapping := DyldCacheMappingInfo{}
		data = readNextBytes(file, int(unsafe.Sizeof(mapping)))

		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &mapping); err != nil {
			return err
		}
		dCache.mappings = append(dCache.mappings, mapping)
	}

	mdata := [][]string{}
	for _, mapping := range dCache.mappings {
		mdata = append(mdata, []string{
			mapping.InitProt.String(),
			mapping.MaxProt.String(),
			fmt.Sprintf("%d MB", mapping.Size/(1024*1024)),
			// humanize.Bytes(mapping.Size),
			fmt.Sprintf("%016X", mapping.Address),
			fmt.Sprintf("%X", mapping.FileOffset),
		})
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"InitProt", "MaxProt", "Size", "Address", "File Offset"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(mdata)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render() // Send output

	file.Seek(int64(dCache.header.ImagesOffset), os.SEEK_SET)
	for i := uint32(0); i != dCache.header.ImagesCount; i++ {
		image := DyldCacheImageInfo{}
		data = readNextBytes(file, int(unsafe.Sizeof(image)))

		if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &image); err != nil {
			return err
		}
		dCache.images = append(dCache.images, image)
	}
	fmt.Println()
	fmt.Println("Images")
	fmt.Println("======")
	for idx, image := range dCache.images {
		file.Seek(int64(image.PathFileOffset), os.SEEK_SET)
		r := bufio.NewReader(file)
		if name, err := r.ReadString(byte(0)); err == nil {
			fmt.Printf("%d:\t%08x %s\n", idx+1, image.Address, bytes.Trim([]byte(name), "\x00"))
		}
	}

	return nil
}
