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
	"github.com/blacktop/go-macho/pkg/codesign"
	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/ipsw/internal/utils"
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

type cacheImages []*CacheImage
type cacheMappings []*CacheMapping
type cacheExtMappings []*CacheExtMapping
type codesignature *ctypes.CodeSignature

// A File represents an open dyld file.
type File struct {
	CacheHeader
	ByteOrder binary.ByteOrder

	Mappings    cacheMappings
	ExtMappings cacheExtMappings
	Images      cacheImages

	SlideInfo       interface{}
	PatchInfo       CachePatchInfo
	LocalSymInfo    localSymbolInfo
	AcceleratorInfo CacheAcceleratorInfo

	BranchPools   []uint64
	CodeSignature codesignature

	AddressToSymbol map[uint64]string

	r      io.ReaderAt
	closer io.Closer
}

// Config is the dyld file config
type Config struct {
	ParseSlideInfo bool
	ParsePatchInfo bool
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
func Open(name string, config ...*Config) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f, config...)
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
func NewFile(r io.ReaderAt, userConfig ...*Config) (*File, error) {
	var config Config
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	f.r = r
	f.AddressToSymbol = make(map[uint64]string, 7000000)

	if len(userConfig) > 0 {
		config = *userConfig[0]
	}
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
		if offset, err := f.GetOffset(image.Info.Address); err == nil {
			f.Images[idx].CacheLocalSymbolsEntry.DylibOffset = uint32(offset)
		}
	}

	// Read dyld code signature.
	sr.Seek(int64(f.CodeSignatureOffset), os.SEEK_SET)

	cs := make([]byte, f.CodeSignatureSize)
	if err := binary.Read(sr, f.ByteOrder, &cs); err != nil {
		return nil, err
	}

	csig, err := codesign.ParseCodeSignature(cs)
	if err != nil {
		return nil, err
	}
	f.CodeSignature = csig

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

	/***********************
	 * Read dyld slide info
	 ***********************/
	if f.SlideInfoOffset > 0 {
		if config.ParseSlideInfo {
			log.Debug("Parsing Slide Info...")
			f.ParseSlideInfo(f.SlideInfoOffset, false)
		}
	} else {
		// Read NEW (in iOS 14) dyld extended mappings.
		sr.Seek(int64(f.ExtMappingOffset), os.SEEK_SET)
		for i := uint32(0); i != f.ExtMappingCount; i++ {
			cxmInfo := CacheExtMappingInfo{}
			if err := binary.Read(sr, f.ByteOrder, &cxmInfo); err != nil {
				return nil, err
			}
			cm := &CacheExtMapping{CacheExtMappingInfo: cxmInfo}
			if cxmInfo.InitProt.Execute() {
				cm.Name = "__TEXT"
			} else if cxmInfo.InitProt.Write() && cm.Flags != 1 {
				cm.Name = "__DATA"
			} else if cxmInfo.InitProt.Write() && cm.Flags == 1 {
				cm.Name = "__AUTH"
			} else if cxmInfo.InitProt.Read() {
				cm.Name = "__LINKEDIT"
			}

			f.ExtMappings = append(f.ExtMappings, cm)
			if config.ParseSlideInfo {
				if cm.SlideInfoSize > 0 {
					log.Debug("Parsing Slide Info...")
					f.ParseSlideInfo(cm.SlideInfoOffset, false)
				}
			}
		}
	}

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
	if f.AccelerateInfoAddr != 0 {
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
					offset, err := f.GetOffset(rEntry.StartAddress)
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
	}

	// Read dyld text_info entries.
	sr.Seek(int64(f.ImagesTextOffset), os.SEEK_SET)
	for i := uint64(0); i != f.ImagesTextCount; i++ {
		if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheImageTextInfo); err != nil {
			return nil, err
		}
	}

	if config.ParsePatchInfo {
		if f.PatchInfoAddr > 0 {
			// Read dyld patch_info entries.
			patchInfoOffset, err := f.GetOffset(f.PatchInfoAddr)
			if err != nil {
				return nil, err
			}

			sr.Seek(int64(patchInfoOffset), io.SeekStart)
			if err := binary.Read(sr, f.ByteOrder, &f.PatchInfo); err != nil {
				return nil, err
			}

			// Read all the other patch_info structs
			patchTableArrayOffset, err := f.GetOffset(f.PatchInfo.PatchTableArrayAddr)
			if err != nil {
				return nil, err
			}

			sr.Seek(int64(patchTableArrayOffset), io.SeekStart)
			imagePatches := make([]CacheImagePatches, f.PatchInfo.PatchTableArrayCount)
			if err := binary.Read(sr, f.ByteOrder, &imagePatches); err != nil {
				return nil, err
			}

			patchExportNamesOffset, err := f.GetOffset(f.PatchInfo.PatchExportNamesAddr)
			if err != nil {
				return nil, err
			}

			exportNames := io.NewSectionReader(f.r, int64(patchExportNamesOffset), int64(f.PatchInfo.PatchExportNamesSize))

			patchExportArrayOffset, err := f.GetOffset(f.PatchInfo.PatchExportArrayAddr)
			if err != nil {
				return nil, err
			}

			sr.Seek(int64(patchExportArrayOffset), io.SeekStart)
			patchExports := make([]CachePatchableExport, f.PatchInfo.PatchExportArrayCount)
			if err := binary.Read(sr, f.ByteOrder, &patchExports); err != nil {
				return nil, err
			}

			patchLocationArrayOffset, err := f.GetOffset(f.PatchInfo.PatchLocationArrayAddr)
			if err != nil {
				return nil, err
			}

			sr.Seek(int64(patchLocationArrayOffset), io.SeekStart)
			patchableLocations := make([]CachePatchableLocation, f.PatchInfo.PatchLocationArrayCount)
			if err := binary.Read(sr, f.ByteOrder, &patchableLocations); err != nil {
				return nil, err
			}

			// Add patchabled export info to images
			for i, iPatch := range imagePatches {
				if iPatch.PatchExportsCount > 0 {
					for exportIndex := uint32(0); exportIndex != iPatch.PatchExportsCount; exportIndex++ {
						patchExport := patchExports[iPatch.PatchExportsStartIndex+exportIndex]
						var exportName string
						if uint64(patchExport.ExportNameOffset) < f.PatchInfo.PatchExportNamesSize {
							exportNames.Seek(int64(patchExport.ExportNameOffset), io.SeekStart)
							s, err := bufio.NewReader(exportNames).ReadString('\x00')
							if err != nil {
								return nil, errors.Wrapf(err, "failed to read string at: %x", uint32(patchExportNamesOffset)+patchExport.ExportNameOffset)
							}
							exportName = strings.Trim(s, "\x00")
						} else {
							exportName = ""
						}
						plocs := make([]CachePatchableLocation, patchExport.PatchLocationsCount)
						for locationIndex := uint32(0); locationIndex != patchExport.PatchLocationsCount; locationIndex++ {
							plocs[locationIndex] = patchableLocations[patchExport.PatchLocationsStartIndex+locationIndex]
						}
						f.Images[i].PatchableExports = append(f.Images[i].PatchableExports, patchableExport{
							Name:           exportName,
							OffsetOfImpl:   patchExport.CacheOffsetOfImpl,
							PatchLocations: plocs,
						})
					}
				}
			}
		}
	}

	return f, nil
}

// ParseSlideInfo parses dyld slide info
func (f *File) ParseSlideInfo(slideInfoOffset uint64, dump bool) error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	// textMapping := f.Mappings[0]
	dataMapping := f.Mappings[1]
	// linkEditMapping := f.Mappings[2]

	// file.Seek(int64((f.SlideInfoOffset-linkEditMapping.FileOffset)+(linkEditMapping.Address-textMapping.Address)), os.SEEK_SET)

	sr.Seek(int64(slideInfoOffset), os.SEEK_SET)

	slideInfoVersionData := make([]byte, 4)
	sr.Read(slideInfoVersionData)
	slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

	sr.Seek(int64(slideInfoOffset), os.SEEK_SET)

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
		if dump {
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
						targetValue = f.CacheHeader.SharedRegionStart + pointer.OffsetFromSharedCacheBase()
						// targetValue = slideInfo.AuthValueAdd + pointer.OffsetFromSharedCacheBase()
					} else {
						targetValue = pointer.SignExtend51()
					}

					var symName string
					sym, ok := f.AddressToSymbol[targetValue]
					if !ok {
						symName = "?"
					} else {
						symName = sym
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
		log.Errorf("got unexpected dyld slide info version: %d", slideInfoVersion)
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
			return i
		}
	}
	return nil
}

// GetImageContainingTextAddr returns a dylib whose __TEXT segment contains a given virtual address
func (f *File) GetImageContainingTextAddr(addr uint64) (*CacheImage, error) {
	for _, img := range f.Images {
		if img.CacheImageTextInfo.LoadAddress <= addr && addr < img.CacheImageTextInfo.LoadAddress+uint64(img.TextSegmentSize) {
			return img, nil
		}
	}
	return nil, fmt.Errorf("address not in any dylib __TEXT")
}

// HasImagePath returns the index of a given image path
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

// FindDlopenOtherImage returns the dlopen OtherImage for a given path
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

// FindClosure returns the closure for a given path
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
