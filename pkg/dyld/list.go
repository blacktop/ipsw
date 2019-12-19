package dyld

import (
	"bufio"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/pkg/errors"
)

type DyldCache struct {
	header        DyldCacheHeader
	mappings      DyldCacheMappings
	images        DyldCacheImages
	codesignature []byte
	slideInfo     DyldCacheSlideInfo
	localSymInfo  DyldCacheLocalSymbolsInfo
}

type DyldCacheMappings []DyldCacheMappingInfo
type DyldCacheImages []DyldCacheImage

type DyldCacheImage struct {
	Name string
	Info DyldCacheImageInfo
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
	UUID                 uuid     // unique value for each shared cache file
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
	Platform             platform // platform number (macOS=1, etc)
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

type uuid [16]byte

type platform uint32

const (
	unknown          platform = 0
	macOS            platform = 1 // PLATFORM_MACOS
	iOS              platform = 2 // PLATFORM_IOS
	tvOS             platform = 3 // PLATFORM_TVOS
	watchOS          platform = 4 // PLATFORM_WATCHOS
	bridgeOS         platform = 5 // PLATFORM_BRIDGEOS
	iOSMac           platform = 6 // PLATFORM_IOSMAC
	iOSSimulator     platform = 7 // PLATFORM_IOSSIMULATOR
	tvOSSimulator    platform = 8 // PLATFORM_TVOSSIMULATOR
	watchOSSimulator platform = 9 // PLATFORM_WATCHOSSIMULATOR
)

type vmProtection int32

func (v vmProtection) Read() bool {
	return (v & 0x01) != 0
}

func (v vmProtection) Write() bool {
	return (v & 0x02) != 0
}

func (v vmProtection) Execute() bool {
	return (v & 0x04) != 0
}

type DyldCacheMappingInfo struct {
	Address    uint64
	Size       uint64
	FileOffset uint64
	MaxProt    vmProtection
	InitProt   vmProtection
}

type DyldCacheImageInfo struct {
	Address        uint64
	ModTime        uint64
	Inode          uint64
	PathFileOffset uint32
	Pad            uint32
}

// DyldCacheSlideInfo is the dyld_cache_image_info struct
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
	UUID            uuid
	LoadAddress     uint64 // unslid address of start of __TEXT
	TextSegmentSize uint32
	PathOffset      uint32 // offset from start of cache file
}

// Parse parses a dyld_share_cache
func Parse(dsc string, verbose bool) error {

	dCache := DyldCache{}

	file, err := os.Open(dsc)
	if err != nil {
		return errors.Wrapf(err, "failed to open file: %s", dsc)
	}
	defer file.Close()

	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &dCache.header); err != nil {
		return err
	}

	file.Seek(int64(dCache.header.MappingOffset), os.SEEK_SET)
	hr := bufio.NewReader(file)

	for i := uint32(0); i != dCache.header.MappingCount; i++ {
		mapping := DyldCacheMappingInfo{}
		if err := binary.Read(hr, binary.LittleEndian, &mapping); err != nil {
			return err
		}
		dCache.mappings = append(dCache.mappings, mapping)
	}

	file.Seek(int64(dCache.header.ImagesOffset), os.SEEK_SET)
	ir := bufio.NewReader(file)

	for i := uint32(0); i != dCache.header.ImagesCount; i++ {
		iinfo := DyldCacheImageInfo{}
		if err := binary.Read(ir, binary.LittleEndian, &iinfo); err != nil {
			return err
		}
		dCache.images = append(dCache.images, DyldCacheImage{Info: iinfo})
	}
	for idx, image := range dCache.images {
		file.Seek(int64(image.Info.PathFileOffset), os.SEEK_SET)

		r := bufio.NewReader(file)
		if name, err := r.ReadString(byte(0)); err == nil {
			dCache.images[idx].Name = fmt.Sprintf("%s", bytes.Trim([]byte(name), "\x00"))
		}
	}

	// file.Seek(int64(dCache.header.CodeSignatureOffset), os.SEEK_SET)

	// data := make([]byte, dCache.header.CodeSignatureSize)
	// if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
	// 	return err
	// }
	// dCache.codesignature = data

	// err = ioutil.WriteFile("dyld_codesignature.blob", data, 0644)
	// if err != nil {
	// 	return errors.Wrapf(err, "failed to open file: %s", dsc)
	// }

	// file.Seek(int64(dCache.header.SlideInfoOffset), os.SEEK_SET)
	// slide := DyldCacheSlideInfo{}
	// if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slide); err != nil {
	// 	return err
	// }
	// dCache.slideInfo = slide

	file.Seek(int64(dCache.header.LocalSymbolsOffset), os.SEEK_SET)
	lsInfo := DyldCacheLocalSymbolsInfo{}
	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &lsInfo); err != nil {
		return err
	}
	dCache.localSymInfo = lsInfo

	if verbose {
		nlistFileOffset := uint32(dCache.header.LocalSymbolsOffset) + dCache.localSymInfo.NlistOffset
		// nlistCount := dCache.localSymInfo.NlistCount
		// nlistByteSize = is64 ? nlistCount*16 : nlistCount*12;
		nlistByteSize := dCache.localSymInfo.NlistCount * 16
		stringsFileOffset := uint32(dCache.header.LocalSymbolsOffset) + dCache.localSymInfo.StringsOffset
		stringsSize := dCache.localSymInfo.StringsSize
		entriesCount := dCache.localSymInfo.EntriesCount
		fmt.Printf("local symbols nlist array:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", nlistByteSize/(1024*1024), nlistFileOffset, nlistFileOffset+nlistByteSize)
		fmt.Printf("local symbols string pool:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", stringsSize/(1024*1024), stringsFileOffset, stringsFileOffset+stringsSize)
		fmt.Printf("local symbols by dylib (count=%d):\n", entriesCount)

		file.Seek(int64(uint32(dCache.header.LocalSymbolsOffset)+dCache.localSymInfo.EntriesOffset), os.SEEK_SET)
		lsr := bufio.NewReader(file)

		var entries []DyldCacheLocalSymbolsEntry
		for i := 0; i < int(entriesCount); i++ {
			entry := DyldCacheLocalSymbolsEntry{}
			if err := binary.Read(lsr, binary.LittleEndian, &entry); err != nil {
				return err
			}
			entries = append(entries, entry)
			fmt.Printf("   nlistStartIndex=%5d, nlistCount=%5d, image=%s\n", entry.NlistStartIndex, entry.NlistCount, dCache.images[i].Name)
		}

		stringPool := io.NewSectionReader(file, int64(stringsFileOffset), int64(stringsSize))

		file.Seek(int64(nlistFileOffset), os.SEEK_SET)
		nlr := bufio.NewReader(file)

		for idx, entry := range entries {
			for e := 0; e < int(entry.NlistCount); e++ {
				nlist := nlist64{}
				if err := binary.Read(nlr, binary.LittleEndian, &nlist); err != nil {
					return err
				}

				stringPool.Seek(int64(nlist.Strx), os.SEEK_SET)
				s, err := bufio.NewReader(stringPool).ReadString('\x00')
				if err != nil {
					log.Error(errors.Wrapf(err, "failed to read string at: %d", stringsFileOffset+nlist.Strx).Error())
				}

				fmt.Printf("%s,value=0x%016X %s\n", dCache.images[idx].Name, nlist.Value, strings.Trim(s, "\x00"))
			}
		}

		if false {
			for idx, entry := range entries {
				file.Seek(int64(entry.DylibOffset), os.SEEK_SET)
				fmt.Printf("%s @ 0x%08X\n", dCache.images[idx].Name, entry.DylibOffset)
				mreader := bufio.NewReader(file)
				mcho, err := macho.NewFile(mreader.rea)
				if err != nil {
					log.Error(errors.Wrap(err, "failed to parse macho").Error())
				}
				fmt.Println(mcho.Symtab)
			}
			// file.Seek(int64(image.Info.Address-dCache.mappings[0].Address), os.SEEK_SET)

			// // if strings.Contains(dCache.images[idx].Name, "JavaScriptCore") {
			// fmt.Printf("%s @ 0x%08X\n", dCache.images[idx].Name, int64(image.Info.Address-dCache.mappings[0].Address))
			// sr := io.NewSectionReader(file, int64(image.Info.Address-dCache.mappings[0].Address), 1<<63-1)
			// mcho, err := macho.NewFile(sr)
			// if err != nil {
			// 	continue
			// 	// return errors.Wrap(err, "failed to create macho")
			// }

			// for _, sec := range mcho.Sections {
			// 	if strings.EqualFold("__cstring", sec.Name) {
			// 		fmt.Printf("%s %s\n", sec.Seg, sec.Name)
			// 		// csr := bufio.NewReader(sec.Open())
			// 		data := make([]byte, sec.Size)
			// 		// data, err := sec.Data()
			// 		// if err != nil {
			// 		// 	log.Fatal(err.Error())
			// 		// }
			// 		file.ReadAt(data, int64(sec.Offset))
			// 		csr := bytes.NewBuffer(data[:])

			// 		for {
			// 			s, err := csr.ReadString('\x00')

			// 			if err == io.EOF {
			// 				break
			// 			}

			// 			if err != nil {
			// 				log.Fatal(err.Error())
			// 			}

			// 			if len(s) > 0 {
			// 				fmt.Printf("%s: %#v\n", dCache.images[idx].Name, strings.Trim(s, "\x00"))
			// 			}
			// 		}
			// 	}
			// }
		}
	}

	dCache.header.Print()
	dCache.mappings.Print()
	dCache.images.Print()

	return nil
}
