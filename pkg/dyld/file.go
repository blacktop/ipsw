package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
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

type cacheMappings []*CacheMapping
type cacheMappingsV2 []*CacheMappingV2
type cacheImages []*CacheImage
type codesignature struct {
	ID            string
	Raw           []byte
	CodeDirectory types.CsCodeDirectory
	Requirements  types.CsRequirementsBlob
	CMSSignature  types.CsBlob
}

// A File represents an open dyld file.
type File struct {
	CacheHeader
	ByteOrder binary.ByteOrder

	Mappings   cacheMappings
	MappingsV2 cacheMappingsV2
	Images     cacheImages

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
	f.AddressToSymbol = make(map[uint64]string, 4450000)

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

	// Read NEW dyld mappings.
	sr.Seek(int64(f.MappingV2Offset), os.SEEK_SET)

	for i := uint32(0); i != f.MappingV2Count; i++ {
		cmInfoV2 := CacheMappingInfoV2{}
		if err := binary.Read(sr, f.ByteOrder, &cmInfoV2); err != nil {
			return nil, err
		}
		cm := &CacheMappingV2{CacheMappingInfoV2: cmInfoV2}
		if cmInfoV2.InitProt.Execute() {
			cm.Name = "__TEXT"

		} else if cmInfoV2.InitProt.Write() {
			cm.Name = "__DATA"

		} else if cmInfoV2.InitProt.Read() {
			cm.Name = "__LINKEDIT"
		}
		f.MappingsV2 = append(f.MappingsV2, cm)
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
	f.CodeSignature.Raw = cs

	if err := f.ParseCodeSignature(); err != nil {
		return nil, err
	}

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
	if f.SlideInfoOffset > 0 {
		f.ParseSlideInfo(false)
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
	}

	// Read dyld text_info entries.
	sr.Seek(int64(f.ImagesTextOffset), os.SEEK_SET)
	for i := uint64(0); i != f.ImagesTextCount; i++ {
		if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheImageTextInfo); err != nil {
			return nil, err
		}
	}
	// TODO: de-waterfall this
	// Read dyld patch_info entries.
	if patchInfoOffset, err := f.getOffset(f.PatchInfoAddr); err == nil {
		sr.Seek(int64(patchInfoOffset), io.SeekStart)
		if err := binary.Read(sr, f.ByteOrder, &f.PatchInfo); err != nil {
			return nil, err
		}
		// Read all the other patch_info structs
		if patchTableArrayOffset, err := f.getOffset(f.PatchInfo.PatchTableArrayAddr); err == nil {
			sr.Seek(int64(patchTableArrayOffset), io.SeekStart)
			imagePatches := make([]CacheImagePatches, f.PatchInfo.PatchTableArrayCount)
			if err := binary.Read(sr, f.ByteOrder, &imagePatches); err != nil {
				return nil, err
			}
			if patchExportNamesOffset, err := f.getOffset(f.PatchInfo.PatchExportNamesAddr); err == nil {
				exportNames := io.NewSectionReader(f.r, int64(patchExportNamesOffset), int64(f.PatchInfo.PatchExportNamesSize))

				if patchExportArrayOffset, err := f.getOffset(f.PatchInfo.PatchExportArrayAddr); err == nil {
					sr.Seek(int64(patchExportArrayOffset), io.SeekStart)
					patchExports := make([]CachePatchableExport, f.PatchInfo.PatchExportArrayCount)
					if err := binary.Read(sr, f.ByteOrder, &patchExports); err != nil {
						return nil, err
					}

					if patchLocationArrayOffset, err := f.getOffset(f.PatchInfo.PatchLocationArrayAddr); err == nil {
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
			}
		}
	}

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

func (f *File) ParseCodeSignature() error {
	// sr := io.NewSectionReader(f.r, 0, 1<<63-1)
	csr := bytes.NewReader(f.CodeSignature.Raw)

	cs := types.CsSuperBlob{}
	if err := binary.Read(csr, binary.BigEndian, &cs); err != nil {
		return err
	}

	csIndex := make([]types.CsBlobIndex, cs.Count)
	if err := binary.Read(csr, binary.BigEndian, &csIndex); err != nil {
		return err
	}

	for _, index := range csIndex {
		csr.Seek(int64(index.Offset), io.SeekStart)
		switch index.Type {
		case types.CSSLOT_CODEDIRECTORY:
			if err := binary.Read(csr, binary.BigEndian, &f.CodeSignature.CodeDirectory); err != nil {
				return err
			}
			csr.Seek(int64(index.Offset+f.CodeSignature.CodeDirectory.IdentOffset), io.SeekStart)
			id, err := bufio.NewReader(csr).ReadString('\x00')
			if err != nil {
				return errors.Wrapf(err, "failed to read string at: %d", index.Offset+f.CodeSignature.CodeDirectory.IdentOffset)
			}
			f.CodeSignature.ID = id
		case types.CSSLOT_REQUIREMENTS:
			if err := binary.Read(csr, binary.BigEndian, &f.CodeSignature.Requirements); err != nil {
				return err
			}
		case types.CSSLOT_CMS_SIGNATURE:
			cms := types.CsBlob{}
			if err := binary.Read(csr, binary.BigEndian, &f.CodeSignature.CMSSignature); err != nil {
				return err
			}
			cmsData := make([]byte, cms.Length)
			if err := binary.Read(csr, binary.BigEndian, &cmsData); err != nil {
				return err
			}
			log.Debug(hex.Dump(cmsData))
		}
	}

	return nil
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
			f.AddressToSymbol[nlist.Value] = strings.Trim(s, "\x00")
			f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
				Name:    strings.Trim(s, "\x00"),
				Nlist64: nlist,
			})
		}
	}

	return nil
}

// ParseSlideInfo parses dyld slide info
func (f *File) ParseSlideInfo(dump bool) error {
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
						// targetValue = f.CacheHeader.SharedRegionStart + pointer.OffsetFromSharedCacheBase()
						targetValue = slideInfo.AuthValueAdd + pointer.OffsetFromSharedCacheBase()
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

func (f *File) getExportTrieData(i *CacheImage) ([]byte, error) {
	var eTrieAddr, eTrieSize uint64
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if i.CacheImageInfoExtra.ExportsTrieAddr == 0 {
		m, err := i.GetPartialMacho()
		if err != nil {
			return nil, err
		}
		if m.DyldInfo() != nil {
			eTrieAddr, _ = f.getVMAddress(uint64(m.DyldInfo().ExportOff))
			eTrieSize = uint64(m.DyldInfo().ExportSize)
		}
	} else {
		eTrieAddr = i.CacheImageInfoExtra.ExportsTrieAddr
		eTrieSize = uint64(i.CacheImageInfoExtra.ExportsTrieSize)
	}

	for _, mapping := range f.Mappings {
		if mapping.Address <= eTrieAddr && (eTrieAddr+eTrieSize) < mapping.Address+mapping.Size {
			sr.Seek(int64(eTrieAddr-mapping.Address+mapping.FileOffset), os.SEEK_SET)
			exportTrie := make([]byte, eTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
				return nil, err
			}
			return exportTrie, nil
		}
	}

	return nil, fmt.Errorf("failed to find export trie for image %s", i.Name)
}

// GetAllExportedSymbols prints out all the exported symbols
func (f *File) GetAllExportedSymbols(dump bool) error {

	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			exportTrie, err := f.getExportTrieData(image)
			if err != nil {
				return err
			}
			syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
			if err != nil {
				return err
			}
			if dump {
				fmt.Printf("\n%s\n", image.Name)
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
				for _, sym := range syms {
					fmt.Fprintf(w, "0x%8x:\t[%s]\t%s\n", sym.Address, sym.Flags, sym.Name)
				}
				w.Flush()
			} else {
				for _, sym := range syms {
					f.AddressToSymbol[sym.Address] = sym.Name
				}
			}
		}
	}

	return nil
}

// SaveAddrToSymMap saves the dyld address-to-symbol map to disk
func (f *File) SaveAddrToSymMap(dest string) error {
	buff := new(bytes.Buffer)

	e := gob.NewEncoder(buff)

	// Encoding the map
	err := e.Encode(f.AddressToSymbol)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dest, buff.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (f *File) FindExportedSymbol(symbolName string) (*trieEntry, error) {

	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			log.Debugf("Scanning Image: %s", image.Name)
			exportTrie, err := f.getExportTrieData(image)
			if err != nil {
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
	return nil, fmt.Errorf("symbol was not found in exports")
}

func (f *File) FindExportedSymbolInImage(imagePath, symbolName string) (*trieEntry, error) {

	image := f.Image(imagePath)
	exportTrie, err := f.getExportTrieData(image)
	if err != nil {
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

	var reExportSymBytes []byte

	exportedSymbol := &CacheExportedSymbol{
		FoundInDylib: image.Name,
		Name:         symbol,
	}

	exportTrie, err := f.getExportTrieData(image)
	if err != nil {
		return nil, err
	}

	symbolNode, err := walkTrie(exportTrie, symbol)
	if err != nil {
		return nil, fmt.Errorf("symbol was not found in ExportsTrie")
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
