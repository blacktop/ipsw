package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/macho/types"
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

type localSymbolInfo struct {
	CacheLocalSymbolsInfo
	NListFileOffset   uint32
	NListByteSize     uint32
	StringsFileOffset uint32
}

type cacheMappings []*CacheMapping
type cacheImages []*CacheImage

// A File represents an open dyld file.
type File struct {
	CacheHeader
	ByteOrder binary.ByteOrder

	Mappings cacheMappings
	Images   cacheImages

	SlideInfo       interface{}
	LocalSymInfo    localSymbolInfo
	AcceleratorInfo CacheAcceleratorInfo

	BranchPools   []uint64
	CodeSignature []byte

	r      io.ReaderAt
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

// Open opens the named file using os.Open and prepares it for use as a dyld binary.
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

// NewFile creates a new File for accessing a dyld binary in an underlying reader.
// The dyld binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt) (*File, error) {
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	f.r = r

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
		f.Images = append(f.Images, &CacheImage{
			Index: i,
			Info:  iinfo,
			sr:    sr,
		})
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

	// Read dyld local symbol entries.
	if f.LocalSymbolsOffset != 0 {
		sr.Seek(int64(f.LocalSymbolsOffset), os.SEEK_SET)

		if err := binary.Read(sr, f.ByteOrder, &f.LocalSymInfo.CacheLocalSymbolsInfo); err != nil {
			return nil, err
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
				return nil, err
			}
			// f.Images[i].ReaderAt = io.NewSectionReader(r, int64(f.Images[i].DylibOffset), 1<<63-1)
		}
	}

	/*****************************
	 * Read dyld kernel slid info
	 *****************************/
	// log.Info("Parsing Slide Info...")
	// f.parseSlideInfo()

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
			// Read dyld 16-bit array of dependencies.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DepListOffset), os.SEEK_SET)
			depList := make([]uint16, f.AcceleratorInfo.DepListCount)
			if err := binary.Read(sr, f.ByteOrder, &depList); err != nil {
				return nil, err
			}
			// Read dyld 16-bit array of re-exports.
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
				rEntry := CacheRangeEntry{}
				if err := binary.Read(sr, f.ByteOrder, &rEntry); err != nil {
					return nil, err
				}
				// fmt.Printf("  0x%X -> 0x%X %s\n", rangeEntry.StartAddress, rangeEntry.StartAddress+uint64(rangeEntry.Size), f.Images[rangeEntry.ImageIndex].Name)
				offset, err := f.getOffset(rEntry.StartAddress)
				if err != nil {
					return nil, errors.Wrap(err, "failed to get range entry's file offset")
				}
				f.Images[rEntry.ImageIndex].RangeEntries = append(f.Images[rEntry.ImageIndex].RangeEntries, rangeEntry{
					StartAddr:  rEntry.StartAddress,
					FileOffset: offset,
					Size:       rEntry.Size,
				})
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

	// javaScriptCore := f.Image("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore")

	// sr.Seek(int64(javaScriptCore.DylibOffset), os.SEEK_SET)

	// textData := make([]byte, javaScriptCore.RangeSize)
	// if err := binary.Read(sr, f.ByteOrder, &textData); err != nil {
	// 	return nil, err
	// }

	// unoptMach, err := macho.NewFile(bytes.NewReader(textData))
	// if err != nil {
	// 	return nil, err
	// }

	// buf := utils.NewWriteBuffer(int(javaScriptCore.RangeSize), 1<<63-1)

	// if _, err := buf.WriteAt(textData, 0); err != nil {
	// 	return nil, err
	// }

	// dataConst := unoptMach.Segment("__DATA_CONST")
	// sr.Seek(int64(dataConst.SegmentHeader.Offset), os.SEEK_SET)

	// dataConstData := make([]byte, dataConst.SegmentHeader.Memsz)
	// if err := binary.Read(sr, f.ByteOrder, &dataConstData); err != nil {
	// 	return nil, err
	// }
	// if _, err := buf.WriteAt(dataConstData, int64(dataConst.SegmentHeader.Offset)); err != nil {
	// 	return nil, err
	// }

	// data := unoptMach.Segment("__DATA")
	// sr.Seek(int64(data.SegmentHeader.Offset), os.SEEK_SET)

	// dataData := make([]byte, data.SegmentHeader.Memsz)
	// if err := binary.Read(sr, f.ByteOrder, &dataData); err != nil {
	// 	return nil, err
	// }
	// if _, err := buf.WriteAt(dataData, int64(data.SegmentHeader.Offset)); err != nil {
	// 	return nil, err
	// }

	// dataDirty := unoptMach.Segment("__DATA_DIRTY")
	// sr.Seek(int64(dataDirty.SegmentHeader.Offset), os.SEEK_SET)

	// dataDirtyData := make([]byte, dataDirty.SegmentHeader.Memsz)
	// if err := binary.Read(sr, f.ByteOrder, &dataDirtyData); err != nil {
	// 	return nil, err
	// }
	// if _, err := buf.WriteAt(dataDirtyData, int64(dataDirty.SegmentHeader.Offset)); err != nil {
	// 	return nil, err
	// }

	// optMach, err := macho.NewFile(bytes.NewReader(buf.Bytes()))
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println(optMach.Symtab)
	// // linkEdit := unoptMach.Segment("__LINKEDIT")

	// if _, err := buf.WriteAt(textData, 0); err != nil {
	// 	return nil, err
	// }

	// file.Seek(int64(image.Info.Address-cache.mappings[0].Address), os.SEEK_SET)

	// // if strings.Contains(cache.images[idx].Name, "JavaScriptCore") {
	// fmt.Printf("%s @ 0x%08X\n", cache.images[idx].Name, int64(image.Info.Address-cache.mappings[0].Address))
	// sr := io.NewSectionReader(file, int64(image.Info.Address-cache.mappings[0].Address), 1<<63-1)
	// mcho, err := macho.NewFile(sr)
	// if err != nil {
	// 	continue
	// 	// return errors.Wrap(err, "failed to create macho")
	// }

	return f, nil
}

// Is64bit returns if dyld is 64bit or not
func (f *File) Is64bit() bool {
	return strings.Contains(string(f.Magic[:16]), "64")
}

func (f *File) getOffset(address uint64) (uint64, error) {
	for _, mapping := range f.Mappings {
		if mapping.Address <= address && address < mapping.Address+mapping.Size {
			return (address - mapping.Address) + mapping.FileOffset, nil
		}
	}
	return 0, fmt.Errorf("address not within any mappings adress range")
}

func (f *File) getVMAddress(offset uint64) (uint64, error) {
	for _, mapping := range f.Mappings {
		if mapping.FileOffset <= offset && offset < mapping.FileOffset+mapping.Size {
			return (offset - mapping.FileOffset) + mapping.Address, nil
		}
	}
	return 0, fmt.Errorf("offset not within any mappings file offset range")
}

// ParseLocalSyms parses dyld's private symbols
func (f *File) ParseLocalSyms() error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	stringPool := io.NewSectionReader(f.r, int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))
	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return err
			}
			stringPool.Seek(int64(nlist.Name), io.SeekStart)
			s, err := bufio.NewReader(stringPool).ReadString('\x00')
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to read string at: %d", f.LocalSymInfo.StringsFileOffset+nlist.Name).Error())
			}
			f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
				Name:    strings.Trim(s, "\x00"),
				Nlist64: nlist,
			})
		}
	}

	return nil
}

func (f *File) parseSlideInfo() error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	// textMapping := f.Mappings[0]
	dataMapping := f.Mappings[1]
	// linkEditMapping := f.Mappings[2]

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

		PageStarts := make([]uint16, slideInfo.PageStartsCount)
		if err := binary.Read(sr, binary.LittleEndian, &PageStarts); err != nil {
			return err
		}
		if false {
			var targetValue uint64
			var pointer CacheSlidePointer3

			for i, start := range PageStarts {
				pageAddress := dataMapping.Address + uint64(uint32(i)*slideInfo.PageSize)
				pageOffset := dataMapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)

				if start == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
					fmt.Printf("page[% 5d]: no rebasing\n", i)
					continue
				}

				rebaseLocation := pageOffset
				delta := uint64(start)

				for {
					rebaseLocation += delta

					sr.Seek(int64(pageOffset+delta), os.SEEK_SET)
					if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
						return err
					}

					if pointer.Authenticated() {
						// targetValue = f.CacheHeader.SharedRegionStart + pointer.OffsetFromSharedCacheBase()
						targetValue = slideInfo.AuthValueAdd + pointer.OffsetFromSharedCacheBase()
					} else {
						targetValue = pointer.SignExtend51()
					}

					var symName string
					sym := f.GetLocalSymAtAddress(targetValue)
					if sym == nil {
						symName = "?"
					} else {
						symName = sym.Name
					}

					fmt.Printf("    [% 5d + 0x%04X] 0x%x @ offset: %x => 0x%x, %s, sym: %s\n", i, (uint64)(rebaseLocation-pageOffset), (uint64)(pageAddress+delta), (uint64)(pageOffset+delta), targetValue, pointer, symName)

					if pointer.OffsetToNextPointer() == 0 {
						break
					}
					delta += pointer.OffsetToNextPointer() * 8
				}
			}
		}
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
		if strings.EqualFold(strings.ToLower(i.Name), strings.ToLower(name)) {
			return i
		}
		base := filepath.Base(i.Name)
		if strings.EqualFold(strings.ToLower(base), strings.ToLower(name)) {
			fmt.Println(base)
			return i
		}
	}
	return nil
}

func (f *File) HasImagePath(path string) (int, bool, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)
	var imageIndex uint64
	for _, mapping := range f.Mappings {
		if mapping.Address <= f.AccelerateInfoAddr && f.AccelerateInfoAddr < mapping.Address+mapping.Size {
			accelInfoPtr := int64(f.AccelerateInfoAddr - mapping.Address + mapping.FileOffset)
			// Read dyld trie containing all dylib paths.
			sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DylibTrieOffset), os.SEEK_SET)
			dylibTrie := make([]byte, f.AcceleratorInfo.DylibTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &dylibTrie); err != nil {
				return 0, false, err
			}
			imageNode, err := walkTrie(dylibTrie, path)
			if err != nil {
				return 0, false, err
			}
			imageIndex, _, err = readUleb128FromBuffer(bytes.NewBuffer(dylibTrie[imageNode:]))
			if err != nil {
				return 0, false, err
			}
		}
	}
	return int(imageIndex), true, nil
}

func (f *File) FindDlopenOtherImage(path string) error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	for _, mapping := range f.Mappings {
		if mapping.Address <= f.OtherTrieAddr && f.OtherTrieAddr < mapping.Address+mapping.Size {
			otherTriePtr := int64(f.OtherTrieAddr - mapping.Address + mapping.FileOffset)
			// Read dyld trie containing TODO
			sr.Seek(otherTriePtr, os.SEEK_SET)
			otherTrie := make([]byte, f.OtherTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &otherTrie); err != nil {
				return err
			}
			imageNode, err := walkTrie(otherTrie, path)
			if err != nil {
				return err
			}
			imageNum, _, err := readUleb128FromBuffer(bytes.NewBuffer(otherTrie[imageNode:]))
			if err != nil {
				return err
			}
			fmt.Println("imageNum:", imageNum)
			arrayAddrOffset := f.OtherImageArrayAddr - f.Mappings[0].Address
			fmt.Println("otherImageArray:", arrayAddrOffset)
		}
	}
	return nil
}

func (f *File) FindClosure(executablePath string) error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	for _, mapping := range f.Mappings {
		if mapping.Address <= f.ProgClosuresTrieAddr && f.ProgClosuresTrieAddr < mapping.Address+mapping.Size {
			progClosuresTriePtr := int64(f.ProgClosuresTrieAddr - mapping.Address + mapping.FileOffset)
			// Read dyld trie containing TODO
			sr.Seek(progClosuresTriePtr, os.SEEK_SET)
			progClosuresTrie := make([]byte, f.ProgClosuresTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &progClosuresTrie); err != nil {
				return err
			}
			imageNode, err := walkTrie(progClosuresTrie, executablePath)
			if err != nil {
				return err
			}
			closureOffset, _, err := readUleb128FromBuffer(bytes.NewBuffer(progClosuresTrie[imageNode:]))
			if err != nil {
				return err
			}
			if closureOffset < f.CacheHeader.ProgClosuresSize {
				closurePtr := f.CacheHeader.ProgClosuresAddr + closureOffset
				fmt.Println("closurePtr:", closurePtr)
			}
		}
	}

	return nil
}

func (f *File) GetLocalSymbolsForImage(imagePath string) error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	image := f.Image(imagePath)
	if image == nil {
		return fmt.Errorf("image not found: %s", imagePath)
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

	stringPool := io.NewSectionReader(sr, int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		// skip over other images
		if uint32(idx) != image.Index {
			sr.Seek(int64(int(f.Images[idx].NlistCount)*binary.Size(types.Nlist64{})), os.SEEK_CUR)
			continue
		}
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {

			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return err
			}

			stringPool.Seek(int64(nlist.Name), os.SEEK_SET)
			s, err := bufio.NewReader(stringPool).ReadString('\x00')
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to read string at: %d", f.LocalSymInfo.StringsFileOffset+nlist.Name).Error())
			}
			f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
				Name:    strings.Trim(s, "\x00"),
				Nlist64: nlist,
			})
		}
		return nil
	}

	return nil
}

func (f *File) FindLocalSymbol(symbol string) (*CacheLocalSymbol64, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return nil, fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)
	stringPool := make([]byte, f.LocalSymInfo.StringsSize)
	sr.ReadAt(stringPool, int64(f.LocalSymInfo.StringsFileOffset))
	nlistName := bytes.Index(stringPool, []byte(symbol))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)
	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return nil, err
			}
			if int(nlist.Name) == nlistName {
				return &CacheLocalSymbol64{
					Name:         symbol,
					FoundInDylib: f.Images[idx].Name,
					Nlist64:      nlist,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("symbol not found in private symbols")
}

func (f *File) FindLocalSymbolInImage(symbol, imageName string) (*CacheLocalSymbol64, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return nil, fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	image := f.Image(imageName)

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)

	stringPool := make([]byte, f.LocalSymInfo.StringsSize)
	sr.ReadAt(stringPool, int64(f.LocalSymInfo.StringsFileOffset))

	nlistName := bytes.Index(stringPool, []byte(symbol))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		// skip over other images
		if uint32(idx) != image.Index {
			sr.Seek(int64(int(f.Images[idx].NlistCount)*binary.Size(types.Nlist64{})), os.SEEK_CUR)
			continue
		}
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return nil, err
			}
			if int(nlist.Name) == nlistName {
				return &CacheLocalSymbol64{
					Name:         symbol,
					FoundInDylib: f.Images[idx].Name,
					Nlist64:      nlist,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("symbol not found in private symbols")
}

// GetLocalSymAtAddress returns the local symbol at a given address
func (f *File) GetLocalSymAtAddress(addr uint64) *CacheLocalSymbol64 {
	for _, image := range f.Images {
		for _, sym := range image.LocalSymbols {
			if sym.Value == addr {
				return sym
			}
		}
	}
	return nil
}

// GetLocalSymbol returns the local symbol that matches name
func (f *File) GetLocalSymbol(symbolName string) *CacheLocalSymbol64 {
	for _, image := range f.Images {
		for _, sym := range image.LocalSymbols {
			if sym.Name == symbolName {
				sym.FoundInDylib = image.Name
				return sym
			}
		}
	}
	return nil
}

// GetLocalSymbolInImage returns the local symbol that matches name in a given image
func (f *File) GetLocalSymbolInImage(imageName, symbolName string) *CacheLocalSymbol64 {
	image := f.Image(imageName)
	for _, sym := range image.LocalSymbols {
		if sym.Name == symbolName {
			return sym
		}
	}
	return nil
}

func (f *File) GetAllExportedSymbols() error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			log.Infof("Scanning Image: %s", image.Name)
			for _, mapping := range f.Mappings {
				start := image.CacheImageInfoExtra.ExportsTrieAddr
				end := image.CacheImageInfoExtra.ExportsTrieAddr + uint64(image.CacheImageInfoExtra.ExportsTrieSize)
				if mapping.Address <= start && end < mapping.Address+mapping.Size {
					sr.Seek(int64(image.CacheImageInfoExtra.ExportsTrieAddr-mapping.Address+mapping.FileOffset), os.SEEK_SET)
					exportTrie := make([]byte, image.CacheImageInfoExtra.ExportsTrieSize)
					if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
						return err
					}
					syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
					if err != nil {
						return err
					}
					for _, sym := range syms {
						fmt.Println(sym.Name)
					}
				}
			}
		}
	}
	return nil
}

func (f *File) FindExportedSymbol(symbolName string) (*trieEntry, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			log.Debugf("Scanning Image: %s", image.Name)
			for _, mapping := range f.Mappings {
				start := image.CacheImageInfoExtra.ExportsTrieAddr
				end := image.CacheImageInfoExtra.ExportsTrieAddr + uint64(image.CacheImageInfoExtra.ExportsTrieSize)
				if mapping.Address <= start && end < mapping.Address+mapping.Size {
					sr.Seek(int64(image.CacheImageInfoExtra.ExportsTrieAddr-mapping.Address+mapping.FileOffset), os.SEEK_SET)
					exportTrie := make([]byte, image.CacheImageInfoExtra.ExportsTrieSize)
					if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
						return nil, err
					}
					syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
					if err != nil {
						return nil, err
					}
					for _, sym := range syms {
						if sym.Name == symbolName {
							sym.FoundInDylib = image.Name
							return &sym, nil
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("symbol was not found in exports")
}

func (f *File) FindExportedSymbolInImage(imagePath, symbolName string) (*trieEntry, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	image := f.Image(imagePath)
	if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
		for _, mapping := range f.Mappings {
			start := image.CacheImageInfoExtra.ExportsTrieAddr
			end := image.CacheImageInfoExtra.ExportsTrieAddr + uint64(image.CacheImageInfoExtra.ExportsTrieSize)
			if mapping.Address <= start && end < mapping.Address+mapping.Size {
				sr.Seek(int64(image.CacheImageInfoExtra.ExportsTrieAddr-mapping.Address+mapping.FileOffset), os.SEEK_SET)
				exportTrie := make([]byte, image.CacheImageInfoExtra.ExportsTrieSize)
				if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
					return nil, err
				}
				syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
				if err != nil {
					return nil, err
				}
				for _, sym := range syms {
					if sym.Name == symbolName {
						return &sym, nil
					}
					// fmt.Println(sym.Name)
				}
			}
		}
	}

	return nil, fmt.Errorf("symbol was not found in exports")
}

// GetExportedSymbolAddress returns the address of an images exported symbol
func (f *File) GetExportedSymbolAddress(symbol string) (*CacheExportedSymbol, error) {
	for _, image := range f.Images {
		if exportSym, err := f.findSymbolInExportTrieForImage(symbol, image); err == nil {
			return exportSym, nil
		}
	}
	return nil, fmt.Errorf("symbol was not found in ExportsTrie")
}

// GetExportedSymbolAddressInImage returns the address of an given image's exported symbol
func (f *File) GetExportedSymbolAddressInImage(imagePath, symbol string) (*CacheExportedSymbol, error) {
	return f.findSymbolInExportTrieForImage(symbol, f.Image(imagePath))
}

func (f *File) findSymbolInExportTrieForImage(symbol string, image *CacheImage) (*CacheExportedSymbol, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	var reExportSymBytes []byte

	exportedSymbol := &CacheExportedSymbol{
		FoundInDylib: image.Name,
		Name:         symbol,
	}

	for _, mapping := range f.Mappings {
		start := image.CacheImageInfoExtra.ExportsTrieAddr
		end := image.CacheImageInfoExtra.ExportsTrieAddr + uint64(image.CacheImageInfoExtra.ExportsTrieSize)
		if mapping.Address <= start && end < mapping.Address+mapping.Size {
			sr.Seek(int64(image.CacheImageInfoExtra.ExportsTrieAddr-mapping.Address+mapping.FileOffset), os.SEEK_SET)
			exportTrie := make([]byte, image.CacheImageInfoExtra.ExportsTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
				return nil, err
			}

			symbolNode, err := walkTrie(exportTrie, symbol)
			if err != nil {
				// skip image
				continue
			}

			r := bytes.NewReader(exportTrie)

			r.Seek(int64(symbolNode), io.SeekStart)

			symFlagInt, err := readUleb128(r)
			if err != nil {
				return nil, err
			}

			exportedSymbol.Flags = CacheExportFlag(symFlagInt)

			if exportedSymbol.Flags.ReExport() {
				symOrdinalInt, err := readUleb128(r)
				if err != nil {
					return nil, err
				}
				log.Debugf("ReExport symOrdinal: %d", symOrdinalInt)
				for {
					s, err := r.ReadByte()
					if err == io.EOF {
						break
					}
					if s == '\x00' {
						break
					}
					reExportSymBytes = append(reExportSymBytes, s)
				}
			}

			symValueInt, err := readUleb128(r)
			if err != nil {
				return nil, err
			}
			exportedSymbol.Value = symValueInt

			if exportedSymbol.Flags.StubAndResolver() {
				symOtherInt, err := readUleb128(r)
				if err != nil {
					return nil, err
				}
				// TODO: handle stubs
				log.Debugf("StubAndResolver: %d", symOtherInt)
			}

			if exportedSymbol.Flags.Absolute() {
				exportedSymbol.Address = symValueInt
			} else {
				exportedSymbol.Address = symValueInt + image.CacheImageTextInfo.LoadAddress
			}

			if len(reExportSymBytes) > 0 {
				exportedSymbol.Name = fmt.Sprintf("%s (%s)", exportedSymbol.Name, string(reExportSymBytes))
			}

			return exportedSymbol, nil
		}
	}

	return nil, fmt.Errorf("symbol was not found in ExportsTrie")
}
