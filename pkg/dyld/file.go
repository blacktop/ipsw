package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/macho"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
)

// Known good magic
var magic = []string{
	"dyld_v1    i386",
	"dyld_v1  x86_64",
	"dyld_v1 x86_64h",
	"dyld_v1   armv5",
	"dyld_v1   armv6",
	"dyld_v1   armv7",
	"dyld_v1  armv7",
	"dyld_v1   arm64",
	"dyld_v1arm64_32",
	"dyld_v1  arm64e",
}

type cacheMappings []*CacheMapping
type cacheImages []*CacheImage
type cacheTextInfos []*CacheImageTextInfo
type cacheLocalSymbols []*CacheLocalSymbol

// CacheImage represents a dyld dylib image.
type CacheImage struct {
	Name         string
	Index        uint32
	Info         CacheImageInfo
	LocalSymbols []*CacheLocalSymbol64
	CacheLocalSymbolsEntry
	CacheImageInfoExtra
	CacheImageTextInfo
	Initializer    uint64
	DOFSectionAddr uint64
	DOFSectionSize uint32
	RangeStartAddr uint64
	RangeSize      uint32

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Data reads and returns the contents of the dylib's Mach-O.
func (i *CacheImage) Data() ([]byte, error) {
	dat := make([]byte, i.sr.Size())
	n, err := i.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

// Open returns a new ReadSeeker reading the dylib's Mach-O data.
func (i *CacheImage) Open() io.ReadSeeker { return io.NewSectionReader(i.sr, 0, 1<<63-1) }

type localSymbolInfo struct {
	CacheLocalSymbolsInfo
	NListFileOffset   uint32
	NListByteSize     uint32
	StringsFileOffset uint32
}

// A File represents an open dyld file.
type File struct {
	CacheHeader
	ByteOrder binary.ByteOrder

	Mappings      cacheMappings
	Images        cacheImages
	CodeSignature []byte
	SlideInfo     interface{}
	LocalSymInfo  localSymbolInfo
	// LocalSymbols    cacheLocalSymbols
	BranchPools     []uint64
	AcceleratorInfo CacheAcceleratorInfo

	closer io.Closer
}

// FormatError is returned by some operations if the data does
// not have the correct format for an object file.
type FormatError struct {
	off int64
	msg string
	val interface{}
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" in record at byte %#x", e.off)
	return msg
}

// Open opens the named file using os.Open and prepares it for use as a Mach-O binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

// NewFile creates a new File for accessing a Mach-O binary in an underlying reader.
// The Mach-O binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt) (*File, error) {
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	// Read and decode dyld magic
	var ident [16]byte
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil, err
	}
	// Verify magic
	if !utils.StrSliceContains(magic, string(ident[:16])) {
		return nil, &FormatError{0, "invalid magic number", nil}
	}

	f.ByteOrder = binary.LittleEndian

	// Read entire file header.
	if err := binary.Read(sr, f.ByteOrder, &f.CacheHeader); err != nil {
		return nil, err
	}

	// Read dyld mappings.
	sr.Seek(int64(f.MappingOffset), os.SEEK_SET)

	for i := uint32(0); i != f.MappingCount; i++ {
		cmInfo := CacheMappingInfo{}
		if err := binary.Read(sr, f.ByteOrder, &cmInfo); err != nil {
			return nil, err
		}
		cm := &CacheMapping{CacheMappingInfo: cmInfo}
		if cmInfo.InitProt.Execute() {
			cm.Name = "__TEXT"
		} else if cmInfo.InitProt.Write() {
			cm.Name = "__DATA"
		} else if cmInfo.InitProt.Read() {
			cm.Name = "__LINKEDIT"
		}
		f.Mappings = append(f.Mappings, cm)
	}

	// Read dyld images.
	sr.Seek(int64(f.ImagesOffset), os.SEEK_SET)

	for i := uint32(0); i != f.ImagesCount; i++ {
		iinfo := CacheImageInfo{}
		if err := binary.Read(sr, f.ByteOrder, &iinfo); err != nil {
			return nil, err
		}
		f.Images = append(f.Images, &CacheImage{Index: i, Info: iinfo})
	}
	for idx, image := range f.Images {
		sr.Seek(int64(image.Info.PathFileOffset), os.SEEK_SET)
		r := bufio.NewReader(sr)
		if name, err := r.ReadString(byte(0)); err == nil {
			f.Images[idx].Name = fmt.Sprintf("%s", bytes.Trim([]byte(name), "\x00"))
		}
	}

	// Read dyld code signature.
	sr.Seek(int64(f.CodeSignatureOffset), os.SEEK_SET)

	cs := make([]byte, f.CodeSignatureSize)
	if err := binary.Read(sr, f.ByteOrder, &cs); err != nil {
		return nil, err
	}
	f.CodeSignature = cs

	/*****************************
	 * Read dyld kernel slid info
	 *****************************/
	log.Info("Parsing Slide Info...")
	f.parseSlideInfo(r)

	/**************************
	 * Read dyld local symbols
	 **************************/
	log.Info("Parsing Local Symbols...")
	f.parseLocalSyms(r)

	// Read dyld branch pool.
	if f.BranchPoolsOffset != 0 {
		sr.Seek(int64(f.BranchPoolsOffset), os.SEEK_SET)

		var bPools []uint64
		bpoolBytes := make([]byte, 8)
		for i := uint32(0); i != f.BranchPoolsCount; i++ {
			if err := binary.Read(sr, f.ByteOrder, &bpoolBytes); err != nil {
				return nil, err
			}
			bPools = append(bPools, binary.LittleEndian.Uint64(bpoolBytes))
		}
		f.BranchPools = bPools
	}

	// Read dyld optimization info.
	for _, mapping := range f.Mappings {
		if mapping.Address <= f.AccelerateInfoAddr && f.AccelerateInfoAddr < mapping.Address+mapping.Size {
			accelInfoPtr := int64(f.AccelerateInfoAddr - mapping.Address + mapping.FileOffset)
			sr.Seek(accelInfoPtr, os.SEEK_SET)
			if err := binary.Read(sr, f.ByteOrder, &f.AcceleratorInfo); err != nil {
				return nil, err
			}
			// Read dyld 16-bit array of sorted image indexes.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.BottomUpListOffset), os.SEEK_SET)
			bottomUpList := make([]uint16, f.AcceleratorInfo.ImageExtrasCount)
			if err := binary.Read(sr, f.ByteOrder, &bottomUpList); err != nil {
				return nil, err
			}
			// Read dyld 16-bit array of dependencies .
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DepListOffset), os.SEEK_SET)
			depList := make([]uint16, f.AcceleratorInfo.DepListCount)
			if err := binary.Read(sr, f.ByteOrder, &depList); err != nil {
				return nil, err
			}
			// Read dyld 16-bit array of re-exports
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.ReExportListOffset), os.SEEK_SET)
			reExportList := make([]uint16, f.AcceleratorInfo.ReExportCount)
			if err := binary.Read(sr, f.ByteOrder, &reExportList); err != nil {
				return nil, err
			}
			// Read dyld image info extras.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.ImagesExtrasOffset), os.SEEK_SET)
			for i := uint32(0); i != f.AcceleratorInfo.ImageExtrasCount; i++ {
				imgXtrInfo := CacheImageInfoExtra{}
				if err := binary.Read(sr, f.ByteOrder, &imgXtrInfo); err != nil {
					return nil, err
				}
				f.Images[i].CacheImageInfoExtra = imgXtrInfo
			}
			// Read dyld initializers list.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.InitializersOffset), os.SEEK_SET)
			for i := uint32(0); i != f.AcceleratorInfo.InitializersCount; i++ {
				accelInit := CacheAcceleratorInitializer{}
				if err := binary.Read(sr, f.ByteOrder, &accelInit); err != nil {
					return nil, err
				}
				// fmt.Printf("  image[%3d] 0x%X\n", accelInit.ImageIndex, f.Mappings[0].Address+uint64(accelInit.FunctionOffset))
				f.Images[accelInit.ImageIndex].Initializer = f.Mappings[0].Address + uint64(accelInit.FunctionOffset)
			}
			// Read dyld DOF sections list.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DofSectionsOffset), os.SEEK_SET)
			for i := uint32(0); i != f.AcceleratorInfo.DofSectionsCount; i++ {
				accelDOF := CacheAcceleratorDof{}
				if err := binary.Read(sr, f.ByteOrder, &accelDOF); err != nil {
					return nil, err
				}
				// fmt.Printf("  image[%3d] 0x%X -> 0x%X\n", accelDOF.ImageIndex, accelDOF.SectionAddress, accelDOF.SectionAddress+uint64(accelDOF.SectionSize))
				f.Images[accelDOF.ImageIndex].DOFSectionAddr = accelDOF.SectionAddress
				f.Images[accelDOF.ImageIndex].DOFSectionSize = accelDOF.SectionSize
			}
			// Read dyld offset to start of ss.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.RangeTableOffset), os.SEEK_SET)
			for i := uint32(0); i != f.AcceleratorInfo.RangeTableCount; i++ {
				rangeEntry := CacheRangeEntry{}
				if err := binary.Read(sr, f.ByteOrder, &rangeEntry); err != nil {
					return nil, err
				}
				// fmt.Printf("  0x%X -> 0x%X %s\n", rangeEntry.StartAddress, rangeEntry.StartAddress+uint64(rangeEntry.Size), f.Images[rangeEntry.ImageIndex].Name)
				f.Images[rangeEntry.ImageIndex].RangeStartAddr = rangeEntry.StartAddress
				f.Images[rangeEntry.ImageIndex].RangeSize = rangeEntry.Size
			}
			// Read dyld trie containing all dylib paths.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DylibTrieOffset), os.SEEK_SET)
			dylibTrie := make([]byte, f.AcceleratorInfo.DylibTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &dylibTrie); err != nil {
				return nil, err
			}
		}
	}

	// Read dyld text_info entries.
	sr.Seek(int64(f.ImagesTextOffset), os.SEEK_SET)
	for i := uint64(0); i != f.ImagesTextCount; i++ {
		if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheImageTextInfo); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// Is64bit returns if dyld is 64bit or not
func (f *File) Is64bit() bool {
	return strings.Contains(string(f.Magic[:16]), "64")
}

func (f *File) parseLocalSyms(r io.ReaderAt) error {
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	sr.Seek(int64(f.LocalSymbolsOffset), os.SEEK_SET)

	if err := binary.Read(sr, f.ByteOrder, &f.LocalSymInfo.CacheLocalSymbolsInfo); err != nil {
		return err
	}

	if f.Is64bit() {
		f.LocalSymInfo.NListByteSize = f.LocalSymInfo.NlistCount * 16
	} else {
		f.LocalSymInfo.NListByteSize = f.LocalSymInfo.NlistCount * 12
	}
	f.LocalSymInfo.NListFileOffset = uint32(f.LocalSymbolsOffset) + f.LocalSymInfo.NlistOffset
	f.LocalSymInfo.StringsFileOffset = uint32(f.LocalSymbolsOffset) + f.LocalSymInfo.StringsOffset

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)

	for i := 0; i < int(f.LocalSymInfo.EntriesCount); i++ {
		if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheLocalSymbolsEntry); err != nil {
			return err
		}
	}

	stringPool := io.NewSectionReader(r, int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return err
			}

			stringPool.Seek(int64(nlist.Strx), os.SEEK_SET)
			s, err := bufio.NewReader(stringPool).ReadString('\x00')
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to read string at: %d", f.LocalSymInfo.StringsFileOffset+nlist.Strx).Error())
			}
			f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
				Name:    strings.Trim(s, "\x00"),
				nlist64: nlist,
			})
		}
	}

	return nil
}

func (f *File) parseSlideInfo(r io.ReaderAt) error {
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	// textMapping := cache.mappings[0]
	// dataMapping := cache.mappings[1]
	// linkEditMapping := cache.mappings[2]

	// file.Seek(int64((f.SlideInfoOffset-linkEditMapping.FileOffset)+(linkEditMapping.Address-textMapping.Address)), os.SEEK_SET)

	sr.Seek(int64(f.SlideInfoOffset), os.SEEK_SET)

	slideInfoVersionData := make([]byte, 4)
	sr.Read(slideInfoVersionData)
	slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

	sr.Seek(int64(f.SlideInfoOffset), os.SEEK_SET)

	switch slideInfoVersion {
	case 1:
		slideInfo := CacheSlideInfo{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return err
		}
		f.SlideInfo = slideInfo
	case 2:
		slideInfo := CacheSlideInfo2{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return err
		}
		f.SlideInfo = slideInfo
	case 3:
		slideInfo := CacheSlideInfo3{}
		if err := binary.Read(sr, binary.LittleEndian, &slideInfo); err != nil {
			return err
		}
		f.SlideInfo = slideInfo
		// fmt.Printf("page_size         =%d\n", slideInfo.PageSize)
		// fmt.Printf("page_starts_count =%d\n", slideInfo.PageStartsCount)
		// fmt.Printf("auth_value_add    =0x%016X\n", slideInfo.AuthValueAdd)

	// 	// var PageStarts []uint16
	// 	// pStartBytes := make([]byte, 2)

	// 	// for i := uint32(0); i != slideInfo.PageStartsCount; i++ {
	// 	// 	if err := binary.Read(sr, binary.LittleEndian, &pStartBytes); err != nil {
	// 	// 		return err
	// 	// 	}
	// 	// 	PageStarts = append(PageStarts, binary.LittleEndian.Uint16(pStartBytes))
	// 	// }

	// 	// var pointer CacheSlidePointer3
	// 	// pointerBytes := make([]byte, 8)
	// 	// dataSegmentStart := dataMapping.FileOffset

	// 	// for i, start := range PageStarts {
	// 	// 	pageStart := dataSegmentStart + uint64(uint32(i)*slideInfo.PageSize)
	// 	// 	pointerBytes = make([]byte, 8)
	// 	// 	if start == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
	// 	// 		fmt.Printf("page[% 5d]: no rebasing\n", i)
	// 	// 		continue
	// 	// 	}
	// 	// 	// fmt.Printf("page[% 5d]: start=0x%04X, addr=0x%04X\n", i, start, pageStart)

	// 	// 	file.ReadAt(pointerBytes, int64(pageStart))

	// 	// 	pointer = CacheSlidePointer3(binary.LittleEndian.Uint64(pointerBytes))
	// 	// 	fmt.Println(pointer)

	// 	// 	rebaseLocation := pageStart
	// 	// 	delta := uint64(start)
	// 	// 	for {
	// 	// 		rebaseLocation += delta
	// 	// 		delta = pointer.OffsetToNextPointer() * 8

	// 	// 		// Regular pointer which needs to fit in 51-bits of value.
	// 	// 		// C++ RTTI uses the top bit, so we'll allow the whole top-byte
	// 	// 		// and the signed-extended bottom 43-bits to be fit in to 51-bits.
	// 	// 		top8Bits := pointer.Value() & 0x007F80000000000
	// 	// 		bottom43Bits := pointer.Value() & 0x000007FFFFFFFFFF
	// 	// 		targetValue := (top8Bits << 13) | (((bottom43Bits << 21) >> 21) & 0x00FFFFFFFFFFFFFF)
	// 	// 		fmt.Printf("    [% 5d + 0x%04X]: 0x%x\n", i, (uint64)(rebaseLocation-pageStart), targetValue)

	// 	// 		if delta == 0 {
	// 	// 			break
	// 	// 		}

	// 	// 		file.ReadAt(pointerBytes, int64(rebaseLocation))
	// 	// 		pointer = CacheSlidePointer3(binary.LittleEndian.Uint64(pointerBytes))
	// 	// 		// fmt.Println(pointer)
	// 	// 	}
	// 	// }
	case 4:
		slideInfo := CacheSlideInfo4{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return err
		}
		f.SlideInfo = slideInfo
	default:
		log.Fatalf("got unexpected dyld slide info version: %d", slideInfoVersion)
	}
	return nil
}

// Image returns the first Image with the given name, or nil if no such image exists.
func (f *File) Image(name string) *CacheImage {
	for _, i := range f.Images {
		if i.Name == name {
			return i
		}
	}
	return nil
}

// Strings returns all the dylib image's cstring literals
func (i *CacheImage) Strings() []string {

	var imgStrings []string

	imgData, err := i.Data()
	if err != nil {
		return nil
	}

	m, err := macho.NewFile(bytes.NewReader(imgData))
	if err != nil {
		log.Error(errors.Wrap(err, "failed to parse macho").Error())
	}
	defer m.Close()

	imgReader := i.Open()

	for _, sec := range m.Sections {

		if sec.Flags.IsCstringLiterals() {
			fmt.Printf("%s %s\n", sec.Seg, sec.Name)
			// csr := bufio.NewReader(sec.Open())
			data := make([]byte, sec.Size)

			imgReader.Seek(int64(sec.Offset), os.SEEK_SET)
			imgReader.Read(data)

			csr := bytes.NewBuffer(data[:])

			for {
				s, err := csr.ReadString('\x00')

				if err == io.EOF {
					break
				}

				if err != nil {
					log.Fatal(err.Error())
				}

				if len(s) > 0 {
					imgStrings = append(imgStrings, strings.Trim(s, "\x00"))
					// fmt.Printf("%s: %#v\n", i.Name, strings.Trim(s, "\x00"))
				}
			}
		}
	}

	return imgStrings
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[0:i])
}

// Parse parses a dyld_share_cache
// func Parse(dsc string, verbose bool) error {

// 	cache := Cache{}

// 	file, err := os.Open(dsc)
// 	if err != nil {
// 		return errors.Wrapf(err, "failed to open file: %s", dsc)
// 	}
// 	defer file.Close()

// 	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &cache.header); err != nil {
// 		return err
// 	}

// 	file.Seek(int64(cache.header.MappingOffset), os.SEEK_SET)
// 	hr := bufio.NewReader(file)

// 	for i := uint32(0); i != cache.header.MappingCount; i++ {
// 		mapping := CacheMappingInfo{}
// 		if err := binary.Read(hr, binary.LittleEndian, &mapping); err != nil {
// 			return err
// 		}
// 		cache.mappings = append(cache.mappings, mapping)
// 	}

// 	file.Seek(int64(cache.header.ImagesOffset), os.SEEK_SET)
// 	ir := bufio.NewReader(file)

// 	for i := uint32(0); i != cache.header.ImagesCount; i++ {
// 		iinfo := CacheImageInfo{}
// 		if err := binary.Read(ir, binary.LittleEndian, &iinfo); err != nil {
// 			return err
// 		}
// 		cache.images = append(cache.images, CacheImage{Info: iinfo})
// 	}
// 	for idx, image := range cache.images {
// 		file.Seek(int64(image.Info.PathFileOffset), os.SEEK_SET)

// 		r := bufio.NewReader(file)
// 		if name, err := r.ReadString(byte(0)); err == nil {
// 			cache.images[idx].Name = fmt.Sprintf("%s", bytes.Trim([]byte(name), "\x00"))
// 		}
// 	}

// 	// file.Seek(int64(cache.header.CodeSignatureOffset), os.SEEK_SET)

// 	// data := make([]byte, cache.header.CodeSignatureSize)
// 	// if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
// 	// 	return err
// 	// }
// 	// cache.codesignature = data

// 	// err = ioutil.WriteFile("dyld_codesignature.blob", data, 0644)
// 	// if err != nil {
// 	// 	return errors.Wrapf(err, "failed to open file: %s", dsc)
// 	// }

// 	// textMapping := cache.mappings[0]
// 	// dataMapping := cache.mappings[1]
// 	// linkEditMapping := cache.mappings[2]
// 	// file.Seek(int64((cache.header.SlideInfoOffset-linkEditMapping.FileOffset)+(linkEditMapping.Address-textMapping.Address)), os.SEEK_SET)
// 	file.Seek(int64(cache.header.SlideInfoOffset), os.SEEK_SET)
// 	slideInfoVersionData := make([]byte, 4)
// 	file.Read(slideInfoVersionData)
// 	slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

// 	file.Seek(int64(cache.header.SlideInfoOffset), os.SEEK_SET)

// 	switch slideInfoVersion {
// 	case 1:
// 		slideInfo := CacheSlideInfo{}
// 		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
// 			return err
// 		}
// 		cache.slideInfo = slideInfo
// 	case 2:
// 		slideInfo := CacheSlideInfo2{}
// 		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
// 			return err
// 		}
// 		cache.slideInfo = slideInfo
// 	case 3:
// 		slideInfo := CacheSlideInfo3{}

// 		sr := bufio.NewReader(file)
// 		if err := binary.Read(sr, binary.LittleEndian, &slideInfo); err != nil {
// 			return err
// 		}

// 		cache.slideInfo = slideInfo
// 		fmt.Printf("page_size         =%d\n", slideInfo.PageSize)
// 		fmt.Printf("page_starts_count =%d\n", slideInfo.PageStartsCount)
// 		fmt.Printf("auth_value_add    =0x%016X\n", slideInfo.AuthValueAdd)

// 		// var PageStarts []uint16
// 		// pStartBytes := make([]byte, 2)

// 		// for i := uint32(0); i != slideInfo.PageStartsCount; i++ {
// 		// 	if err := binary.Read(sr, binary.LittleEndian, &pStartBytes); err != nil {
// 		// 		return err
// 		// 	}
// 		// 	PageStarts = append(PageStarts, binary.LittleEndian.Uint16(pStartBytes))
// 		// }

// 		// var pointer CacheSlidePointer3
// 		// pointerBytes := make([]byte, 8)
// 		// dataSegmentStart := dataMapping.FileOffset

// 		// for i, start := range PageStarts {
// 		// 	pageStart := dataSegmentStart + uint64(uint32(i)*slideInfo.PageSize)
// 		// 	pointerBytes = make([]byte, 8)
// 		// 	if start == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
// 		// 		fmt.Printf("page[% 5d]: no rebasing\n", i)
// 		// 		continue
// 		// 	}
// 		// 	// fmt.Printf("page[% 5d]: start=0x%04X, addr=0x%04X\n", i, start, pageStart)

// 		// 	file.ReadAt(pointerBytes, int64(pageStart))

// 		// 	pointer = CacheSlidePointer3(binary.LittleEndian.Uint64(pointerBytes))
// 		// 	fmt.Println(pointer)

// 		// 	rebaseLocation := pageStart
// 		// 	delta := uint64(start)
// 		// 	for {
// 		// 		rebaseLocation += delta
// 		// 		delta = pointer.OffsetToNextPointer() * 8

// 		// 		// Regular pointer which needs to fit in 51-bits of value.
// 		// 		// C++ RTTI uses the top bit, so we'll allow the whole top-byte
// 		// 		// and the signed-extended bottom 43-bits to be fit in to 51-bits.
// 		// 		top8Bits := pointer.Value() & 0x007F80000000000
// 		// 		bottom43Bits := pointer.Value() & 0x000007FFFFFFFFFF
// 		// 		targetValue := (top8Bits << 13) | (((bottom43Bits << 21) >> 21) & 0x00FFFFFFFFFFFFFF)
// 		// 		fmt.Printf("    [% 5d + 0x%04X]: 0x%x\n", i, (uint64)(rebaseLocation-pageStart), targetValue)

// 		// 		if delta == 0 {
// 		// 			break
// 		// 		}

// 		// 		file.ReadAt(pointerBytes, int64(rebaseLocation))
// 		// 		pointer = CacheSlidePointer3(binary.LittleEndian.Uint64(pointerBytes))
// 		// 		// fmt.Println(pointer)
// 		// 	}
// 		// }
// 	case 4:
// 		slideInfo := CacheSlideInfo4{}
// 		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
// 			return err
// 		}
// 		cache.slideInfo = slideInfo
// 	default:
// 		log.Fatalf("got unexpected dyld slide info version: %d", slideInfoVersion)
// 	}

// 	file.Seek(int64(cache.header.LocalSymbolsOffset), os.SEEK_SET)
// 	lsInfo := CacheLocalSymbolsInfo{}
// 	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &lsInfo); err != nil {
// 		return err
// 	}
// 	cache.localSymInfo = lsInfo

// 	if verbose {

// 		nlistFileOffset := uint32(cache.header.LocalSymbolsOffset) + cache.localSymInfo.NlistOffset
// 		// nlistCount := cache.localSymInfo.NlistCount
// 		// nlistByteSize = is64 ? nlistCount*16 : nlistCount*12;
// 		nlistByteSize := cache.localSymInfo.NlistCount * 16
// 		stringsFileOffset := uint32(cache.header.LocalSymbolsOffset) + cache.localSymInfo.StringsOffset
// 		stringsSize := cache.localSymInfo.StringsSize
// 		entriesCount := cache.localSymInfo.EntriesCount
// 		fmt.Printf("local symbols nlist array:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", nlistByteSize/(1024*1024), nlistFileOffset, nlistFileOffset+nlistByteSize)
// 		fmt.Printf("local symbols string pool:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", stringsSize/(1024*1024), stringsFileOffset, stringsFileOffset+stringsSize)
// 		fmt.Printf("local symbols by dylib (count=%d):\n", entriesCount)

// 		file.Seek(int64(uint32(cache.header.LocalSymbolsOffset)+cache.localSymInfo.EntriesOffset), os.SEEK_SET)
// 		lsr := bufio.NewReader(file)

// 		var entries []CacheLocalSymbolsEntry
// 		for i := 0; i < int(entriesCount); i++ {
// 			entry := CacheLocalSymbolsEntry{}
// 			if err := binary.Read(lsr, binary.LittleEndian, &entry); err != nil {
// 				return err
// 			}
// 			entries = append(entries, entry)
// 			fmt.Printf("   nlistStartIndex=%5d, nlistCount=%5d, image=%s\n", entry.NlistStartIndex, entry.NlistCount, cache.images[i].Name)
// 		}
// 		if false {
// 			stringPool := io.NewSectionReader(file, int64(stringsFileOffset), int64(stringsSize))

// 			file.Seek(int64(nlistFileOffset), os.SEEK_SET)
// 			nlr := bufio.NewReader(file)

// 			for idx, entry := range entries {
// 				for e := 0; e < int(entry.NlistCount); e++ {
// 					nlist := nlist64{}
// 					if err := binary.Read(nlr, binary.LittleEndian, &nlist); err != nil {
// 						return err
// 					}

// 					stringPool.Seek(int64(nlist.Strx), os.SEEK_SET)
// 					s, err := bufio.NewReader(stringPool).ReadString('\x00')
// 					if err != nil {
// 						log.Error(errors.Wrapf(err, "failed to read string at: %d", stringsFileOffset+nlist.Strx).Error())
// 					}

// 					fmt.Printf("%s,value=0x%016X %s\n", cache.images[idx].Name, nlist.Value, strings.Trim(s, "\x00"))
// 				}
// 			}
// 		}

// 		if true {
// 			for idx, entry := range entries {
// 				file.Seek(int64(entry.DylibOffset), os.SEEK_SET)
// 				fmt.Printf("%s @ 0x%08X\n", cache.images[idx].Name, entry.DylibOffset)
// 				if strings.Contains(cache.images[idx].Name, "JavaScriptCore") {
// 					// if strings.Contains(cache.images[idx].Name, "Foundation") {
// 					m, err := macho.NewFile(io.NewSectionReader(file, int64(entry.DylibOffset), 1<<63-1))
// 					if err != nil {
// 						log.Error(errors.Wrap(err, "failed to parse macho").Error())
// 					}
// 					fmt.Println(m)
// 					m.Sections.Print()

// 					if verbose {
// 						for _, sec := range m.Sections {
// 							// if strings.EqualFold("__cstring", sec.Name) {
// 							if sec.Flags.IsCstringLiterals() {
// 								fmt.Printf("%s %s\n", sec.Seg, sec.Name)
// 								// csr := bufio.NewReader(sec.Open())
// 								data := make([]byte, sec.Size)
// 								// data, err := sec.Data()
// 								// if err != nil {
// 								// 	log.Fatal(err.Error())
// 								// }
// 								file.ReadAt(data, int64(sec.Offset))
// 								csr := bytes.NewBuffer(data[:])

// 								for {
// 									s, err := csr.ReadString('\x00')

// 									if err == io.EOF {
// 										break
// 									}

// 									if err != nil {
// 										log.Fatal(err.Error())
// 									}

// 									if len(s) > 0 {
// 										fmt.Printf("%s: %#v\n", cache.images[idx].Name, strings.Trim(s, "\x00"))
// 									}
// 								}
// 							}
// 						}
// 					}
// 					break
// 				}
// 			}
// 			// file.Seek(int64(image.Info.Address-cache.mappings[0].Address), os.SEEK_SET)

// 			// // if strings.Contains(cache.images[idx].Name, "JavaScriptCore") {
// 			// fmt.Printf("%s @ 0x%08X\n", cache.images[idx].Name, int64(image.Info.Address-cache.mappings[0].Address))
// 			// sr := io.NewSectionReader(file, int64(image.Info.Address-cache.mappings[0].Address), 1<<63-1)
// 			// mcho, err := macho.NewFile(sr)
// 			// if err != nil {
// 			// 	continue
// 			// 	// return errors.Wrap(err, "failed to create macho")
// 			// }

// 		}
// 	}

// 	cache.header.Print()
// 	cache.mappings.Print()
// 	// cache.images.Print()

// 	return nil
// }
