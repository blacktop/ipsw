package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/codesign"
	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	mtypes "github.com/blacktop/go-macho/types"
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
type cacheMappingsWithSlideInfo []*CacheMappingWithSlideInfo
type codesignature *ctypes.CodeSignature

// A File represents an open dyld file.
type File struct {
	CacheHeader
	ByteOrder binary.ByteOrder

	Mappings              cacheMappings
	MappingsWithSlideInfo cacheMappingsWithSlideInfo

	Images cacheImages

	SlideInfo       slideInfo
	PatchInfo       CachePatchInfo
	LocalSymInfo    localSymbolInfo
	AcceleratorInfo CacheAcceleratorInfo

	BranchPools            []uint64
	CodeSignature          codesignature
	subCacheCodeSignatures map[mtypes.UUID]codesignature

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
	if ff.ImagesOffset == 0 && ff.ImagesCount == 0 { // NEW iOS15 dyld4 style caches
		ff.subCacheCodeSignatures = make(map[mtypes.UUID]codesignature)
		lastFileOffset := ff.MappingsWithSlideInfo[len(ff.MappingsWithSlideInfo)-1].FileOffset + ff.MappingsWithSlideInfo[len(ff.MappingsWithSlideInfo)-1].Size
		for i := 1; i <= int(ff.NumSubCaches); i++ {
			log.WithFields(log.Fields{
				"cache": fmt.Sprintf("%s.%d", name, i),
			}).Debug("Parsing SubCache")
			f, err := os.Open(fmt.Sprintf("%s.%d", name, i))
			if err != nil {
				return nil, err
			}
			ffsc, err := NewFile(f)
			if err != nil {
				ffsc.Close()
				return nil, err
			}

			// if ffsc.SubCachesUUID != ff.SubCachesUUID {
			// 	return nil, fmt.Errorf("sub cache %s did not match expected UUID: %#x, got: %#x", fmt.Sprintf("%s.%d", name, i),
			// 		ff.SubCachesUUID,
			// 		ffsc.SubCachesUUID)
			// }

			ff.subCacheCodeSignatures[ffsc.UUID] = ffsc.CodeSignature

			for i := 0; i < int(ffsc.MappingWithSlideCount); i++ {
				ffsc.Mappings[i].FileOffset = ffsc.Mappings[i].FileOffset + lastFileOffset
				ffsc.MappingsWithSlideInfo[i].FileOffset = ffsc.MappingsWithSlideInfo[i].FileOffset + lastFileOffset
				ffsc.MappingsWithSlideInfo[i].SlideInfoOffset = ffsc.MappingsWithSlideInfo[i].SlideInfoOffset + lastFileOffset
				ff.Mappings = append(ff.Mappings, ffsc.Mappings[i])
				ff.MappingsWithSlideInfo = append(ff.MappingsWithSlideInfo, ffsc.MappingsWithSlideInfo[i])
			}
			ff.AppendData(io.NewSectionReader(ffsc.r, 0, 1<<63-1), lastFileOffset)
			ffsc.Close()
		}
		if ff.SymbolsSubCacheUUID != [16]byte{0} {
			log.WithFields(log.Fields{
				"cache": name + ".symbols",
			}).Debug("Parsing SubCache")
			f, err := os.Open(name + ".symbols")
			if err != nil {
				return nil, err
			}
			ffsym, err := NewFile(f)
			if err != nil {
				f.Close()
				return nil, err
			}
			lastFileOffset = ff.MappingsWithSlideInfo[len(ff.MappingsWithSlideInfo)-1].FileOffset + ff.MappingsWithSlideInfo[len(ff.MappingsWithSlideInfo)-1].Size
			ff.subCacheCodeSignatures[ffsym.UUID] = ffsym.CodeSignature
			// Copy local symbols info from .symbols sub cache
			ff.LocalSymbolsOffset = ffsym.LocalSymbolsOffset
			ff.LocalSymbolsSize = ffsym.LocalSymbolsSize
			ff.LocalSymInfo = ffsym.LocalSymInfo
			ff.LocalSymInfo.NListFileOffset = ffsym.LocalSymInfo.NListFileOffset + uint32(lastFileOffset)
			ff.LocalSymInfo.StringsFileOffset = ffsym.LocalSymInfo.StringsFileOffset + uint32(lastFileOffset)
			for idx, img := range ffsym.Images {
				ff.Images[idx].CacheLocalSymbolsEntry = img.CacheLocalSymbolsEntry
			}
			for i := 0; i < int(ffsym.MappingWithSlideCount); i++ {
				ffsym.Mappings[i].FileOffset = ffsym.Mappings[i].FileOffset + lastFileOffset
				ffsym.MappingsWithSlideInfo[i].FileOffset = ffsym.MappingsWithSlideInfo[i].FileOffset + lastFileOffset
				ffsym.MappingsWithSlideInfo[i].SlideInfoOffset = ffsym.MappingsWithSlideInfo[i].SlideInfoOffset + lastFileOffset
				ff.Mappings = append(ff.Mappings, ffsym.Mappings[i])
				ff.MappingsWithSlideInfo = append(ff.MappingsWithSlideInfo, ffsym.MappingsWithSlideInfo[i])
			}
			ff.AppendData(io.NewSectionReader(ffsym.r, 0, 1<<63-1), lastFileOffset)
			// if b, err := io.ReadAll(io.NewSectionReader(ff.r, 0, 1<<63-1)); err == nil {
			// 	ioutil.WriteFile(fmt.Sprintf("%s.BIGG", name), b, 0755)
			// }
			ffsym.Close()
		}
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

// ReadHeader opens a given cache and returns the dyld_shared_cache header
func ReadHeader(path string) (*CacheHeader, error) {
	var header CacheHeader

	cache, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(cache, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	return &header, nil
}

// NewFile creates a new File for accessing a dyld binary in an underlying reader.
// The dyld binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt) (*File, error) {
	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	f.r = r
	f.AddressToSymbol = make(map[uint64]string, 7000000)

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

	/***********************
	 * Read dyld slide info
	 ***********************/
	if f.SlideInfoOffsetUnused > 0 {
		f.ParseSlideInfo(CacheMappingAndSlideInfo{
			Address:         f.Mappings[1].Address,
			Size:            f.Mappings[1].Size,
			FileOffset:      f.Mappings[1].FileOffset,
			SlideInfoOffset: f.SlideInfoOffsetUnused,
			SlideInfoSize:   f.SlideInfoSizeUnused,
		}, false)
	} else {
		// Read NEW (in iOS 14) dyld mappings with slide info.
		sr.Seek(int64(f.MappingWithSlideOffset), os.SEEK_SET)
		for i := uint32(0); i != f.MappingWithSlideCount; i++ {
			cxmInfo := CacheMappingAndSlideInfo{}
			if err := binary.Read(sr, f.ByteOrder, &cxmInfo); err != nil {
				return nil, err
			}

			cm := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: cxmInfo, Name: "UNKNOWN"}

			if cxmInfo.MaxProt.Execute() {
				cm.Name = "__TEXT"
			} else if cxmInfo.MaxProt.Write() {
				if cm.Flags.IsAuthData() {
					cm.Name = "__AUTH"
				} else {
					cm.Name = "__DATA"
				}
				if cm.Flags.IsDirtyData() {
					cm.Name += "_DIRTY"
				} else if cm.Flags.IsConstData() {
					cm.Name += "_CONST"
				}
			} else if cxmInfo.InitProt.Read() {
				cm.Name = "__LINKEDIT"
			}

			if cm.SlideInfoSize > 0 {
				f.ParseSlideInfo(cm.CacheMappingAndSlideInfo, false)
			}

			f.MappingsWithSlideInfo = append(f.MappingsWithSlideInfo, cm)
		}
	}

	// Read dyld images.
	var imagesCount uint32
	if f.ImagesOffset > 0 {
		imagesCount = f.ImagesCount
		sr.Seek(int64(f.ImagesOffset), os.SEEK_SET)
	} else {
		imagesCount = f.ImagesWithSubCachesCount
		sr.Seek(int64(f.ImagesWithSubCachesOffset), os.SEEK_SET)
	}

	for i := uint32(0); i != imagesCount; i++ {
		iinfo := CacheImageInfo{}
		if err := binary.Read(sr, f.ByteOrder, &iinfo); err != nil {
			return nil, err
		}
		f.Images = append(f.Images, &CacheImage{
			Index: i,
			Info:  iinfo,
			cache: f,
		})
	}
	for idx, image := range f.Images {
		sr.Seek(int64(image.Info.PathFileOffset), os.SEEK_SET)
		r := bufio.NewReader(sr)
		if name, err := r.ReadString(byte(0)); err == nil {
			f.Images[idx].Name = fmt.Sprintf("%s", bytes.Trim([]byte(name), "\x00"))
		}
		// if offset, err := f.GetOffset(image.Info.Address); err == nil {
		// 	f.Images[idx].CacheLocalSymbolsEntry.DylibOffset = offset
		// }
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

		sr.Seek(int64(f.LocalSymbolsOffset+uint64(f.LocalSymInfo.EntriesOffset)), os.SEEK_SET)

		for i := 0; i < int(f.LocalSymInfo.EntriesCount); i++ {
			// if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheLocalSymbolsEntry); err != nil {
			// 	return nil, err
			// }
			var localSymEntry CacheLocalSymbolsEntry
			if f.ImagesOffset == 0 && f.ImagesCount == 0 { // NEW iOS15 dyld4 style caches
				if err := binary.Read(sr, f.ByteOrder, &localSymEntry); err != nil {
					return nil, err
				}
			} else {
				var preDyld4LSEntry preDyld4cacheLocalSymbolsEntry
				if err := binary.Read(sr, f.ByteOrder, &preDyld4LSEntry); err != nil {
					return nil, err
				}
				localSymEntry.DylibOffset = uint64(preDyld4LSEntry.DylibOffset)
				localSymEntry.NlistStartIndex = preDyld4LSEntry.NlistStartIndex
				localSymEntry.NlistCount = preDyld4LSEntry.NlistCount
			}

			if len(f.Images) > i {
				f.Images[i].CacheLocalSymbolsEntry = localSymEntry
			} else {
				f.Images = append(f.Images, &CacheImage{
					Index: uint32(i),
					// Info:      iinfo,
					cache:                  f,
					CacheLocalSymbolsEntry: localSymEntry,
				})
			}
			// f.Images[i].ReaderAt = io.NewSectionReader(r, int64(f.Images[i].DylibOffset), 1<<63-1)
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

	return f, nil
}

// ParseSlideInfo parses dyld slide info
func (f *File) ParseSlideInfo(mapping CacheMappingAndSlideInfo, dump bool) error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	sr.Seek(int64(mapping.SlideInfoOffset), os.SEEK_SET)

	slideInfoVersionData := make([]byte, 4)
	sr.Read(slideInfoVersionData)
	slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

	sr.Seek(int64(mapping.SlideInfoOffset), os.SEEK_SET)

	switch slideInfoVersion {
	case 1:
		slideInfo := CacheSlideInfo{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return err
		}

		f.SlideInfo = slideInfo

		if dump {
			fmt.Printf("slide info version = %d\n", slideInfo.Version)
			fmt.Printf("toc_count          = %d\n", slideInfo.TocCount)
			fmt.Printf("data page count    = %d\n", mapping.Size/4096)

			sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.EntriesOffset)), os.SEEK_SET)
			entries := make([]CacheSlideInfoEntry, int(slideInfo.EntriesCount))
			if err := binary.Read(sr, binary.LittleEndian, &entries); err != nil {
				return err
			}

			sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.TocOffset)), os.SEEK_SET)
			tocs := make([]uint16, int(slideInfo.TocCount))
			if err := binary.Read(sr, binary.LittleEndian, &tocs); err != nil {
				return err
			}

			for i, toc := range tocs {
				fmt.Printf("%#08x: [% 5d,% 5d] ", int(mapping.Address)+i*4096, i, tocs[i])
				for j := 0; i < int(slideInfo.EntriesSize); i++ {
					fmt.Printf("%02x", entries[toc].bits[j])
				}
				fmt.Printf("\n")
			}
		}
	case 2:
		slideInfo := CacheSlideInfo2{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return err
		}

		f.SlideInfo = slideInfo

		if dump {
			fmt.Printf("slide info version = %d\n", slideInfo.Version)
			fmt.Printf("page_size          = %d\n", slideInfo.PageSize)
			fmt.Printf("delta_mask         = %#016x\n", slideInfo.DeltaMask)
			fmt.Printf("value_add          = %#016x\n", slideInfo.ValueAdd)
			fmt.Printf("page_starts_count  = %d\n", slideInfo.PageStartsCount)
			fmt.Printf("page_extras_count  = %d\n", slideInfo.PageExtrasCount)

			var targetValue uint64
			var pointer uint64

			starts := make([]uint16, slideInfo.PageStartsCount)
			if err := binary.Read(sr, binary.LittleEndian, &starts); err != nil {
				return err
			}

			sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.PageExtrasOffset)), os.SEEK_SET)
			extras := make([]uint16, int(slideInfo.PageExtrasCount))
			if err := binary.Read(sr, binary.LittleEndian, &extras); err != nil {
				return err
			}

			for i, start := range starts {
				// pageAddress := mapping.Address + uint64(uint32(i)*slideInfo.PageSize)
				pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)
				rebaseChain := func(pageContent uint64, startOffset uint16) error {
					deltaShift := uint64(bits.TrailingZeros64(slideInfo.DeltaMask) - 2)
					pageOffset := uint32(startOffset)
					delta := uint32(1)
					for delta != 0 {
						sr.Seek(int64(pageContent+uint64(pageOffset)), os.SEEK_SET)
						if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
							return err
						}

						delta = uint32(pointer & slideInfo.DeltaMask >> deltaShift)
						targetValue = slideInfo.SlidePointer(pointer)

						var symName string
						sym, ok := f.AddressToSymbol[targetValue]
						if !ok {
							symName = "?"
						} else {
							symName = sym
						}

						fmt.Printf("    [% 5d + %#04x]: %#016x = %#016x, sym: %s\n", i, pageOffset, pointer, targetValue, symName)
						pageOffset += delta
					}

					return nil
				}

				if start == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE {
					fmt.Printf("page[% 5d]: no rebasing\n", i)
				} else if start&DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA != 0 {
					fmt.Printf("page[% 5d]: ", i)
					j := start & 0x3FFF
					done := false
					for !done {
						aStart := extras[j]
						fmt.Printf("start=%#04x ", aStart&0x3FFF)
						pageStartOffset := (aStart & 0x3FFF) * 4
						rebaseChain(pageOffset, pageStartOffset)
						done = (extras[j] & DYLD_CACHE_SLIDE_PAGE_ATTR_END) != 0
						j++
					}
					fmt.Printf("\n")
				} else {
					fmt.Printf("page[% 5d]: start=0x%04X\n", i, starts[i])
					rebaseChain(pageOffset, start*4)
				}
			}
		}
	case 3:
		slideInfo := CacheSlideInfo3{}
		if err := binary.Read(sr, binary.LittleEndian, &slideInfo); err != nil {
			return err
		}
		f.SlideInfo = slideInfo

		if dump {
			fmt.Printf("slide info version = %d\n", slideInfo.Version)
			fmt.Printf("page_size          = %d\n", slideInfo.PageSize)
			fmt.Printf("page_starts_count  = %d\n", slideInfo.PageStartsCount)
			fmt.Printf("auth_value_add     = %#016x\n", slideInfo.AuthValueAdd)

			var targetValue uint64
			var pointer CacheSlidePointer3

			PageStarts := make([]uint16, slideInfo.PageStartsCount)
			if err := binary.Read(sr, binary.LittleEndian, &PageStarts); err != nil {
				return err
			}

			for i, start := range PageStarts {
				pageAddress := mapping.Address + uint64(uint32(i)*slideInfo.PageSize)
				pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)

				delta := uint64(start)

				if delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
					fmt.Printf("page[% 5d]: no rebasing\n", i)
					continue
				}

				fmt.Printf("page[% 5d]: start=0x%04X\n", i, delta)

				rebaseLocation := pageOffset

				for {
					rebaseLocation += delta

					sr.Seek(int64(pageOffset+delta), os.SEEK_SET)
					if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
						return err
					}

					if pointer.Authenticated() {
						// fmt.Println(fixupchains.DyldChainedPtrArm64eAuthBind{Pointer: pointer.Raw()}.String())
						targetValue = slideInfo.AuthValueAdd + pointer.OffsetFromSharedCacheBase()
					} else {
						// fmt.Println(fixupchains.DyldChainedPtrArm64eRebase{Pointer: pointer.Raw()}.String())
						targetValue = pointer.SignExtend51()
					}

					var symName string
					sym, ok := f.AddressToSymbol[targetValue]
					if !ok {
						symName = "?"
					} else {
						symName = sym
					}

					fmt.Printf("    [% 5d + 0x%04X] (%#x @ offset %#x => %#x) %s, sym: %s\n", i, (uint64)(rebaseLocation-pageOffset), (uint64)(pageAddress+delta), (uint64)(pageOffset+delta), targetValue, pointer, symName)

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

		if dump {
			fmt.Printf("slide info version = %d\n", slideInfo.Version)
			fmt.Printf("page_size          = %d\n", slideInfo.PageSize)
			fmt.Printf("delta_mask         = %#016x\n", slideInfo.DeltaMask)
			fmt.Printf("value_add          = %#016x\n", slideInfo.ValueAdd)
			fmt.Printf("page_starts_count  = %d\n", slideInfo.PageStartsCount)
			fmt.Printf("page_extras_count  = %d\n", slideInfo.PageExtrasCount)

			var targetValue uint64
			var pointer uint32

			starts := make([]uint16, slideInfo.PageStartsCount)
			if err := binary.Read(sr, binary.LittleEndian, &starts); err != nil {
				return err
			}

			sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.PageExtrasOffset)), os.SEEK_SET)
			extras := make([]uint16, int(slideInfo.PageExtrasCount))
			if err := binary.Read(sr, binary.LittleEndian, &extras); err != nil {
				return err
			}

			for i, start := range starts {
				pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)
				rebaseChainV4 := func(pageContent uint64, startOffset uint16) error {
					deltaShift := uint64(bits.TrailingZeros64(slideInfo.DeltaMask) - 2)
					pageOffset := uint32(startOffset)
					delta := uint32(1)
					for delta != 0 {
						sr.Seek(int64(pageContent+uint64(pageOffset)), os.SEEK_SET)
						if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
							return err
						}

						delta = uint32(uint64(pointer) & slideInfo.DeltaMask >> deltaShift)
						targetValue = slideInfo.SlidePointer(uint64(pointer))

						var symName string
						sym, ok := f.AddressToSymbol[targetValue]
						if !ok {
							symName = "?"
						} else {
							symName = sym
						}

						fmt.Printf("    [% 5d + %#04x]: %#08x = %#08x, sym: %s\n", i, pageOffset, pointer, targetValue, symName)
						pageOffset += delta
					}

					return nil
				}
				if start == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE {
					fmt.Printf("page[% 5d]: no rebasing\n", i)
				} else if start&DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA != 0 {
					fmt.Printf("page[% 5d]: ", i)
					j := (start & DYLD_CACHE_SLIDE4_PAGE_INDEX)
					done := false
					for !done {
						aStart := extras[j]
						fmt.Printf("start=0x%04X ", aStart&DYLD_CACHE_SLIDE4_PAGE_INDEX)
						pageStartOffset := (aStart & DYLD_CACHE_SLIDE4_PAGE_INDEX) * 4
						rebaseChainV4(pageOffset, pageStartOffset)
						done = (extras[j] & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END) != 0
						j++
					}
					fmt.Printf("\n")
				} else {
					fmt.Printf("page[% 5d]: start=0x%04X\n", i, starts[i])
					rebaseChainV4(pageOffset, start*4)
				}
			}
		}

	default:
		log.Errorf("got unexpected dyld slide info version: %d", slideInfoVersion)
	}
	return nil
}

// ParsePatchInfo parses dyld patch info
func (f *File) ParsePatchInfo() error {
	if f.PatchInfoAddr > 0 {
		sr := io.NewSectionReader(f.r, 0, 1<<63-1)
		// Read dyld patch_info entries.
		patchInfoOffset, err := f.GetOffset(f.PatchInfoAddr + 8)
		if err != nil {
			return err
		}

		sr.Seek(int64(patchInfoOffset), io.SeekStart)
		if err := binary.Read(sr, f.ByteOrder, &f.PatchInfo); err != nil {
			return err
		}

		// Read all the other patch_info structs
		patchTableArrayOffset, err := f.GetOffset(f.PatchInfo.PatchTableArrayAddr)
		if err != nil {
			return err
		}

		sr.Seek(int64(patchTableArrayOffset), io.SeekStart)
		imagePatches := make([]CacheImagePatches, f.PatchInfo.PatchTableArrayCount)
		if err := binary.Read(sr, f.ByteOrder, &imagePatches); err != nil {
			return err
		}

		patchExportNamesOffset, err := f.GetOffset(f.PatchInfo.PatchExportNamesAddr)
		if err != nil {
			return err
		}

		exportNames := io.NewSectionReader(f.r, int64(patchExportNamesOffset), int64(f.PatchInfo.PatchExportNamesSize))

		patchExportArrayOffset, err := f.GetOffset(f.PatchInfo.PatchExportArrayAddr)
		if err != nil {
			return err
		}

		sr.Seek(int64(patchExportArrayOffset), io.SeekStart)
		patchExports := make([]CachePatchableExport, f.PatchInfo.PatchExportArrayCount)
		if err := binary.Read(sr, f.ByteOrder, &patchExports); err != nil {
			return err
		}

		patchLocationArrayOffset, err := f.GetOffset(f.PatchInfo.PatchLocationArrayAddr)
		if err != nil {
			return err
		}

		sr.Seek(int64(patchLocationArrayOffset), io.SeekStart)
		patchableLocations := make([]CachePatchableLocation, f.PatchInfo.PatchLocationArrayCount)
		if err := binary.Read(sr, f.ByteOrder, &patchableLocations); err != nil {
			return err
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
							return errors.Wrapf(err, "failed to read string at: %x", uint32(patchExportNamesOffset)+patchExport.ExportNameOffset)
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

		return nil
	}

	return fmt.Errorf("cache does NOT contain patch info")
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
// NOTE: this can be faster than GetImageContainingVMAddr as it avoids parsing the MachO
func (f *File) GetImageContainingTextAddr(addr uint64) (*CacheImage, error) {
	for _, img := range f.Images {
		if img.CacheImageTextInfo.LoadAddress <= addr && addr < img.CacheImageTextInfo.LoadAddress+uint64(img.TextSegmentSize) {
			return img, nil
		}
	}
	return nil, fmt.Errorf("address %#x not in any dylib __TEXT", addr)
}

// GetImageContainingVMAddr returns a dylib whose segment contains a given virtual address
func (f *File) GetImageContainingVMAddr(addr uint64) (*CacheImage, error) {
	for _, img := range f.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			return nil, err
		}
		if seg := m.FindSegmentForVMAddr(addr); seg != nil {
			return img, nil
		}
		m.Close()
	}
	return nil, fmt.Errorf("address %#x not in any dylib", addr)
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

// GetDylibIndex returns the index of a given dylib
func (f *File) GetDylibIndex(path string) (uint64, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	off, err := f.GetOffset(f.DylibsTrieAddr)
	if err != nil {
		return 0, err
	}

	sr.Seek(int64(off), io.SeekStart)

	dylibTrie := make([]byte, f.DylibsTrieSize)
	if err := binary.Read(sr, f.ByteOrder, &dylibTrie); err != nil {
		return 0, err
	}

	dylibs, err := parseTrie(dylibTrie, 0)
	if err != nil {
		return 0, err
	}

	for _, d := range dylibs {
		if d.Name == path {
			return uint64(d.Flags), nil
		}
	}

	return 0, fmt.Errorf("dylib not found in Dylibs Trie")
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

func (f *File) GetSubCacheCodeSignatures() map[mtypes.UUID]codesignature {
	return f.subCacheCodeSignatures
}
