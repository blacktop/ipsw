package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/blacktop/ipsw/utils"
)

var magic = []string{
	"dyld_v1    i386",
	"dyld_v1  x86_64",
	"dyld_v1 x86_64h",
	"dyld_v1   armv",
	"dyld_v1  armv",
	"dyld_v1   arm64",
	"dyld_v1  arm64e",
	"dyld_v1arm64_32",
}

type cacheMappings []*CacheMapping
type cacheImages []*CacheImage
type cacheTextInfos []*CacheImageTextInfo
type cacheLocalSymbols []*CacheLocalSymbolsEntry

// CacheImage represents a dyld dylib image.
type CacheImage struct {
	Name string
	Info CacheImageInfo
}

// A File represents an open dyld file.
type File struct {
	CacheHeader
	ByteOrder binary.ByteOrder

	Mappings      cacheMappings
	Images        cacheImages
	CodeSignature []byte
	SlideInfo     interface{}
	LocalSymInfo  CacheLocalSymbolsInfo
	LocalSymbols  cacheLocalSymbols
	BranchPools   []uint64
	TextInfos     cacheTextInfos

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
		f.Images = append(f.Images, &CacheImage{Info: iinfo})
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
	f.parseSlideInfo()

	/**************************
	 * Read dyld local symbols
	 **************************/
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

	// Read dyld text_info entries.
	sr.Seek(int64(f.ImagesTextOffset), os.SEEK_SET)
	for i := uint64(0); i != f.ImagesTextCount; i++ {
		tinfo := CacheImageTextInfo{}
		if err := binary.Read(sr, f.ByteOrder, &tinfo); err != nil {
			return nil, err
		}
		f.TextInfos = append(f.TextInfos, &tinfo)
	}

	return f, nil
}

func (f *File) parseLocalSyms(r io.ReaderAt) error {
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	sr.Seek(int64(f.LocalSymbolsOffset), os.SEEK_SET)

	if err := binary.Read(sr, f.ByteOrder, &f.LocalSymInfo); err != nil {
		return err
	}

	nlistFileOffset := uint32(f.LocalSymbolsOffset) + f.LocalSymInfo.NlistOffset
	// nlistCount := f.LocalSymInfo.NlistCount
	// nlistByteSize = is64 ? nlistCount*16 : nlistCount*12;
	nlistByteSize := f.LocalSymInfo.NlistCount * 16
	stringsFileOffset := uint32(f.LocalSymbolsOffset) + f.LocalSymInfo.StringsOffset
	stringsSize := f.LocalSymInfo.StringsSize
	entriesCount := f.LocalSymInfo.EntriesCount
	fmt.Printf("local symbols nlist array:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", nlistByteSize/(1024*1024), nlistFileOffset, nlistFileOffset+nlistByteSize)
	fmt.Printf("local symbols string pool:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", stringsSize/(1024*1024), stringsFileOffset, stringsFileOffset+stringsSize)
	fmt.Printf("local symbols by dylib (count=%d):\n", entriesCount)

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)

	for i := 0; i < int(entriesCount); i++ {
		entry := CacheLocalSymbolsEntry{}
		if err := binary.Read(sr, f.ByteOrder, &entry); err != nil {
			return err
		}
		f.LocalSymbols = append(f.LocalSymbols, &entry)
		// fmt.Printf("   nlistStartIndex=%5d, nlistCount=%5d, image=%s\n", entry.NlistStartIndex, entry.NlistCount, f.Images[i].Name)
	}

	return nil
}

func (f *File) parseSlideInfo() error {
	// // textMapping := cache.mappings[0]
	// // dataMapping := cache.mappings[1]
	// // linkEditMapping := cache.mappings[2]
	// // file.Seek(int64((f.SlideInfoOffset-linkEditMapping.FileOffset)+(linkEditMapping.Address-textMapping.Address)), os.SEEK_SET)
	// file.Seek(int64(f.SlideInfoOffset), os.SEEK_SET)
	// slideInfoVersionData := make([]byte, 4)
	// file.Read(slideInfoVersionData)
	// slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

	// file.Seek(int64(f.SlideInfoOffset), os.SEEK_SET)

	// switch slideInfoVersion {
	// case 1:
	// 	slideInfo := CacheSlideInfo{}
	// 	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
	// 		return err
	// 	}
	// 	cache.slideInfo = slideInfo
	// case 2:
	// 	slideInfo := CacheSlideInfo2{}
	// 	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
	// 		return err
	// 	}
	// 	cache.slideInfo = slideInfo
	// case 3:
	// 	slideInfo := CacheSlideInfo3{}

	// 	sr := bufio.NewReader(file)
	// 	if err := binary.Read(sr, binary.LittleEndian, &slideInfo); err != nil {
	// 		return err
	// 	}

	// 	cache.slideInfo = slideInfo
	// 	fmt.Printf("page_size         =%d\n", slideInfo.PageSize)
	// 	fmt.Printf("page_starts_count =%d\n", slideInfo.PageStartsCount)
	// 	fmt.Printf("auth_value_add    =0x%016X\n", slideInfo.AuthValueAdd)

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
	// case 4:
	// 	slideInfo := CacheSlideInfo4{}
	// 	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
	// 		return err
	// 	}
	// 	f.SlideInfo = slideInfo
	// default:
	// 	log.Fatalf("got unexpected dyld slide info version: %d", slideInfoVersion)
	// }
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
