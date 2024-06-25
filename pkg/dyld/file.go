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
	"github.com/blacktop/go-macho/pkg/trie"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
)

// Known good magic
var knownMagic = []string{
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
type codesignature *codesign.CodeSignature
type cacheMappingsWithSlideInfo []*CacheMappingWithSlideInfo

func (m cacheMappingsWithSlideInfo) Len() int {
	return len(m)
}
func (m cacheMappingsWithSlideInfo) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}
func (m cacheMappingsWithSlideInfo) Less(i, j int) bool {
	return m[i].Address < m[j].Address
}

// A File represents an open dyld file.
type File struct {
	UUID    mtypes.UUID
	Headers map[mtypes.UUID]CacheHeader

	ByteOrder binary.ByteOrder

	Mappings              map[mtypes.UUID]cacheMappings
	MappingsWithSlideInfo map[mtypes.UUID]cacheMappingsWithSlideInfo

	Images cacheImages

	SlideInfo        slideInfo
	PatchInfoVersion uint32
	LocalSymInfo     localSymbolInfo
	AcceleratorInfo  CacheAcceleratorInfo
	ImageArray       map[uint32]*CImage
	Closures         []*LaunchClosure

	BranchPools    []uint64
	CodeSignatures map[mtypes.UUID]codesignature

	AddressToSymbol map[uint64]string

	IsDyld4         bool
	symCacheLoaded  bool
	SubCacheInfo    []SubcacheEntry
	TPROMappings    []TPROMapping
	symUUID         mtypes.UUID
	dyldImageAddr   uint64
	dyldStartFnAddr uint64
	objcOptRoAddr   uint64
	islandStubs     map[uint64]uint64
	size            int64

	r       map[mtypes.UUID]io.ReaderAt
	closers map[mtypes.UUID]io.Closer
}

// FormatError is returned by some operations if the data does
// not have the correct format for an object file.
type FormatError struct {
	off int64
	msg string
	val any
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" in record at byte %#x", e.off)
	return msg
}

func getUUID(r io.ReaderAt) (mtypes.UUID, error) {
	var uuidBytes [16]byte
	var badUUID mtypes.UUID

	if _, err := r.ReadAt(uuidBytes[0:], 0x58); err != nil {
		return badUUID, err
	}

	uuid := mtypes.UUID(uuidBytes)

	if uuid.IsNull() {
		return badUUID, fmt.Errorf("file's UUID is empty") // FIXME: should this actually stop or continue
	}

	return uuid, nil
}

// Open opens the named file using os.Open and prepares it for use as a dyld binary.
func Open(name string) (*File, error) {

	log.WithFields(log.Fields{
		"cache": name,
	}).Debug("Parsing Cache")
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	ff.size = fi.Size()

	if ff.IsDyld4 {

		for i := 1; i <= int(ff.Headers[ff.UUID].SubCacheArrayCount); i++ {
			subCacheName := fmt.Sprintf("%s.%d", name, i)
			if len(ff.SubCacheInfo[i-1].Extention) > 0 {
				subCacheName = fmt.Sprintf("%s%s", name, ff.SubCacheInfo[i-1].Extention)
			}
			/* NOTE: removing because it feels too noisy */
			// log.WithFields(log.Fields{
			// 	"cache": subCacheName,
			// }).Debug("Parsing SubCache")

			fsub, err := os.Open(subCacheName)
			if err != nil {
				return nil, err
			}

			fi, err := fsub.Stat()
			if err != nil {
				return nil, err
			}

			ff.size += fi.Size()

			uuid, err := getUUID(fsub)
			if err != nil {
				return nil, err
			}

			ff.parseCache(fsub, uuid)

			ff.closers[uuid] = fsub

			if ff.Headers[uuid].UUID != ff.SubCacheInfo[i-1].UUID {
				return nil, fmt.Errorf("sub cache %s did not match expected UUID: %#x, got: %#x", subCacheName,
					ff.SubCacheInfo[i-1].UUID.String(),
					ff.Headers[uuid].UUID.String())
			}
		}

		if !ff.Headers[ff.UUID].SymbolFileUUID.IsNull() {
			// log.WithFields(log.Fields{
			// 	"cache": name + ".symbols",
			// }).Debug("Parsing SubCache")
			fsym, err := os.Open(name + ".symbols")
			if err != nil {
				return nil, err
			}

			uuid, err := getUUID(fsym)
			if err != nil {
				return nil, err
			}

			if uuid != ff.Headers[ff.UUID].SymbolFileUUID {
				return nil, fmt.Errorf("%s.symbols UUID %s did NOT match expected UUID %s", name, uuid.String(), ff.Headers[ff.UUID].SymbolFileUUID.String())
			}

			ff.symUUID = uuid

			ff.parseCache(fsym, uuid)

			ff.closers[uuid] = fsym
		}
	}

	ff.closers[ff.UUID] = f

	return ff, nil
}

// Close closes the File.
// If the File was created using NewFile directly instead of Open,
// Close has no effect.
func (f *File) Close() error {
	var err error
	for uuid, closer := range f.closers {
		if closer != nil {
			err = closer.Close()
			f.closers[uuid] = nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ReadHeader opens a given cache and returns the dyld_cache_header
func ReadHeader(name string) (*CacheHeader, error) {
	var header CacheHeader

	log.WithFields(log.Fields{
		"cache": name,
	}).Debug("Parsing Cache Header")

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	return &header, nil
}

// NewFile creates a new File for accessing a dyld binary in an underlying reader.
// The dyld binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt) (*File, error) {

	f := new(File)

	// init all maps
	f.Headers = make(map[mtypes.UUID]CacheHeader)
	f.Mappings = make(map[mtypes.UUID]cacheMappings)
	f.MappingsWithSlideInfo = make(map[mtypes.UUID]cacheMappingsWithSlideInfo)
	f.CodeSignatures = make(map[mtypes.UUID]codesignature)
	f.r = make(map[mtypes.UUID]io.ReaderAt)
	f.closers = make(map[mtypes.UUID]io.Closer)
	f.AddressToSymbol = make(map[uint64]string, 7000000)
	f.ImageArray = make(map[uint32]*CImage)
	f.islandStubs = make(map[uint64]uint64)

	// Read and decode dyld magic
	var ident [16]byte
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil, err
	}
	// Verify magic
	if !utils.StrSliceHas(knownMagic, strings.Trim(string(ident[:16]), "\x00")) {
		return nil, &FormatError{0, "invalid dyld_shared_cache magic", string(ident[:16])}
	}

	f.ByteOrder = binary.LittleEndian

	var uuidBytes [16]byte
	if _, err := r.ReadAt(uuidBytes[0:], 0x58); err != nil {
		return nil, err
	}

	f.UUID = mtypes.UUID(uuidBytes)

	if f.UUID.IsNull() {
		return nil, fmt.Errorf("file's UUID is empty") // FIXME: should this actually stop or continue
	}

	if err := f.parseCache(r, f.UUID); err != nil {
		return nil, fmt.Errorf("failed to parse cache %s: %v", f.UUID, err)
	}

	return f, nil
}

// parseCache parses dyld shared cache file
func (f *File) parseCache(r io.ReaderAt, uuid mtypes.UUID) error {

	sr := io.NewSectionReader(r, 0, 1<<63-1)

	// Read and decode dyld magic
	var ident [16]byte
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return err
	}
	// Verify magic
	if !utils.StrSliceHas(knownMagic, strings.Trim(string(ident[:16]), "\x00")) {
		return &FormatError{0, "invalid dyld_shared_cache magic", string(ident[:16])}
	}

	f.r[uuid] = r

	// Read entire file header.
	var hdr CacheHeader
	if err := binary.Read(sr, f.ByteOrder, &hdr); err != nil {
		return err
	}
	f.Headers[uuid] = hdr

	if f.Headers[f.UUID].ImagesOffsetOld == 0 && f.Headers[f.UUID].ImagesCountOld == 0 {
		f.IsDyld4 = true // NEW macOS12.5+/iOS15+ dyld4 style caches
	}

	// Read dyld mappings.
	sr.Seek(int64(f.Headers[uuid].MappingOffset), io.SeekStart)

	for i := uint32(0); i != f.Headers[uuid].MappingCount; i++ {
		cmInfo := CacheMappingInfo{}
		if err := binary.Read(sr, f.ByteOrder, &cmInfo); err != nil {
			return err
		}
		cm := &CacheMapping{CacheMappingInfo: cmInfo}
		if cmInfo.InitProt.Execute() {
			cm.Name = "__TEXT"
		} else if cmInfo.InitProt.Write() {
			cm.Name = "__DATA"
		} else if cmInfo.InitProt.Read() {
			cm.Name = "__LINKEDIT"
		}
		f.Mappings[uuid] = append(f.Mappings[uuid], cm)
	}

	/***********************
	 * Read dyld slide info
	 ***********************/
	if f.Headers[uuid].SlideInfoOffsetUnused > 0 {
		for _, m := range f.Mappings[uuid] {
			cm := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{
				Address:    m.Address,
				Size:       m.Size,
				FileOffset: m.FileOffset,
				MaxProt:    m.MaxProt,
				InitProt:   m.InitProt,
			}, Name: m.Name}
			if m.Name == "__DATA" {
				cm.SlideInfoOffset = f.Headers[uuid].SlideInfoOffsetUnused
				cm.SlideInfoSize = f.Headers[uuid].SlideInfoSizeUnused
				f.GetSlideInfo(uuid, cm)
			}
			f.MappingsWithSlideInfo[uuid] = append(f.MappingsWithSlideInfo[uuid], cm)
		}
	} else {
		// Read NEW (in iOS 14) dyld mappings with slide info.
		sr.Seek(int64(f.Headers[uuid].MappingWithSlideOffset), io.SeekStart)
		for i := uint32(0); i != f.Headers[uuid].MappingWithSlideCount; i++ {
			cxmInfo := CacheMappingAndSlideInfo{}
			if err := binary.Read(sr, f.ByteOrder, &cxmInfo); err != nil {
				return err
			}

			cm := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: cxmInfo, Name: "UNKNOWN"}
			if cxmInfo.MaxProt.Execute() {
				if cm.Flags.IsTextStubs() {
					cm.Name = "__TEXT_STUBS"
				} else {
					cm.Name = "__TEXT"
				}
			} else if cxmInfo.MaxProt.Write() {
				if cm.Flags.IsAuthData() {
					cm.Name = "__AUTH"
				} else if cm.Flags.IsTPRO() {
					cm.Name = "__TPRO"
				} else {
					cm.Name = "__DATA"
				}
				switch {
				case cm.Flags.IsDirtyData():
					cm.Name += "_DIRTY"
				case cm.Flags.IsConstData():
					cm.Name += "_CONST"
				case cm.Flags.IsConfigData():
					cm.Name += "_CONFIG"
				}
			} else if cxmInfo.InitProt.Read() {
				cm.Name = "__LINKEDIT"
			}

			if cm.SlideInfoSize > 0 {
				f.GetSlideInfo(uuid, cm)
			}

			f.MappingsWithSlideInfo[uuid] = append(f.MappingsWithSlideInfo[uuid], cm)
		}
	}

	// Read dyld images.
	var imagesCount uint32
	if f.Headers[uuid].ImagesOffsetOld > 0 {
		imagesCount = f.Headers[uuid].ImagesCountOld
		sr.Seek(int64(f.Headers[uuid].ImagesOffsetOld), io.SeekStart)
	} else {
		imagesCount = f.Headers[uuid].ImagesCount
		sr.Seek(int64(f.Headers[uuid].ImagesOffset), io.SeekStart)
	}

	if len(f.Images) == 0 {
		for i := uint32(0); i != imagesCount; i++ {
			iinfo := CacheImageInfo{}
			if err := binary.Read(sr, f.ByteOrder, &iinfo); err != nil {
				return fmt.Errorf("failed to read %T: %v", iinfo, err)
			}
			f.Images = append(f.Images, &CacheImage{
				Index: i,
				Info:  iinfo,
				cache: f,
			})
		}
		for idx, image := range f.Images {
			sr.Seek(int64(image.Info.PathFileOffset), io.SeekStart)
			r := bufio.NewReader(sr)
			if name, err := r.ReadString(byte(0)); err == nil {
				f.Images[idx].Name = strings.Trim(name, "\x00")
			}
			// if offset, err := f.GetOffset(image.Info.Address); err == nil {
			// 	f.Images[idx].CacheLocalSymbolsEntry.DylibOffset = offset
			// }
		}
	}
	for idx, img := range f.Images {
		if f.IsAddressInCache(uuid, img.Info.Address) {
			f.Images[idx].cuuid = uuid
		}
	}

	// Read dyld code signature.
	sr.Seek(int64(f.Headers[uuid].CodeSignatureOffset), io.SeekStart)

	cs := make([]byte, f.Headers[uuid].CodeSignatureSize)
	if err := binary.Read(sr, f.ByteOrder, &cs); err != nil {
		return err
	}

	csig, err := codesign.ParseCodeSignature(cs)
	if err != nil {
		return err
	}
	f.CodeSignatures[uuid] = csig

	// Read dyld local symbol entries.
	if f.Headers[uuid].LocalSymbolsOffset != 0 {
		sr.Seek(int64(f.Headers[uuid].LocalSymbolsOffset), io.SeekStart)

		if err := binary.Read(sr, f.ByteOrder, &f.LocalSymInfo.CacheLocalSymbolsInfo); err != nil {
			return err
		}

		if f.Is64bit() {
			f.LocalSymInfo.NListByteSize = f.LocalSymInfo.NlistCount * 16
		} else {
			f.LocalSymInfo.NListByteSize = f.LocalSymInfo.NlistCount * 12
		}
		f.LocalSymInfo.NListFileOffset = uint32(f.Headers[uuid].LocalSymbolsOffset) + f.LocalSymInfo.NlistOffset
		f.LocalSymInfo.StringsFileOffset = uint32(f.Headers[uuid].LocalSymbolsOffset) + f.LocalSymInfo.StringsOffset

		sr.Seek(int64(f.Headers[uuid].LocalSymbolsOffset+uint64(f.LocalSymInfo.EntriesOffset)), io.SeekStart)

		for i := 0; i < int(f.LocalSymInfo.EntriesCount); i++ {
			// if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheLocalSymbolsEntry); err != nil {
			// 	return nil, err
			// }
			var localSymEntry CacheLocalSymbolsEntry64
			if f.Headers[uuid].ImagesOffsetOld == 0 && f.Headers[uuid].ImagesCountOld == 0 { // NEW iOS15 dyld4 style caches
				if err := binary.Read(sr, f.ByteOrder, &localSymEntry); err != nil {
					return err
				}
			} else {
				var preDyld4LSEntry CacheLocalSymbolsEntry
				if err := binary.Read(sr, f.ByteOrder, &preDyld4LSEntry); err != nil {
					return err
				}
				localSymEntry.DylibOffset = uint64(preDyld4LSEntry.DylibOffset)
				localSymEntry.NlistStartIndex = preDyld4LSEntry.NlistStartIndex
				localSymEntry.NlistCount = preDyld4LSEntry.NlistCount
			}

			if len(f.Images) > i {
				f.Images[i].CacheLocalSymbolsEntry64 = localSymEntry
			} else {
				f.Images = append(f.Images, &CacheImage{
					Index: uint32(i),
					// Info:      iinfo,
					cache:                    f,
					CacheLocalSymbolsEntry64: localSymEntry,
				})
			}
			// f.Images[i].ReaderAt = io.NewSectionReader(r, int64(f.Images[i].DylibOffset), 1<<63-1)
		}
	}

	// Read dyld branch pool.
	if f.Headers[uuid].BranchPoolsOffset != 0 {
		sr.Seek(int64(f.Headers[uuid].BranchPoolsOffset), io.SeekStart)

		var bPools []uint64
		bpoolBytes := make([]byte, 8)
		for i := uint32(0); i != f.Headers[uuid].BranchPoolsCount; i++ {
			if err := binary.Read(sr, f.ByteOrder, &bpoolBytes); err != nil {
				return err
			}
			bPools = append(bPools, binary.LittleEndian.Uint64(bpoolBytes))
		}
		f.BranchPools = bPools
	}

	if f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr != 0 {
		if f.IsDyld4 { // iOS16 added dyld to the shared cache and resued these fields to point to the dyld image and _dyld_start
			f.dyldImageAddr = f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr
			f.dyldStartFnAddr = f.Headers[uuid].AccelerateInfoSizeUnusedOrDyldStartFuncAddr
		} else {
			// Read dyld optimization info.
			for _, mapping := range f.Mappings[uuid] {
				if mapping.Address <= f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr && f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr < mapping.Address+mapping.Size {
					accelInfoPtr := int64(f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr - mapping.Address + mapping.FileOffset)
					sr.Seek(accelInfoPtr, io.SeekStart)
					if err := binary.Read(sr, f.ByteOrder, &f.AcceleratorInfo); err != nil {
						return err
					}
					// Read dyld 16-bit array of sorted image indexes.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.BottomUpListOffset), io.SeekStart)
					bottomUpList := make([]uint16, f.AcceleratorInfo.ImageExtrasCount)
					if err := binary.Read(sr, f.ByteOrder, &bottomUpList); err != nil {
						return err
					}
					// Read dyld 16-bit array of dependencies.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DepListOffset), io.SeekStart)
					depList := make([]uint16, f.AcceleratorInfo.DepListCount)
					if err := binary.Read(sr, f.ByteOrder, &depList); err != nil {
						return err
					}
					// Read dyld 16-bit array of re-exports.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.ReExportListOffset), io.SeekStart)
					reExportList := make([]uint16, f.AcceleratorInfo.ReExportCount)
					if err := binary.Read(sr, f.ByteOrder, &reExportList); err != nil {
						return err
					}
					// Read dyld image info extras.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.ImagesExtrasOffset), io.SeekStart)
					for i := uint32(0); i != f.AcceleratorInfo.ImageExtrasCount; i++ {
						imgXtrInfo := CacheImageInfoExtra{}
						if err := binary.Read(sr, f.ByteOrder, &imgXtrInfo); err != nil {
							return err
						}
						f.Images[i].CacheImageInfoExtra = imgXtrInfo
					}
					// Read dyld initializers list.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.InitializersOffset), io.SeekStart)
					for i := uint32(0); i != f.AcceleratorInfo.InitializersCount; i++ {
						accelInit := CacheAcceleratorInitializer{}
						if err := binary.Read(sr, f.ByteOrder, &accelInit); err != nil {
							return err
						}
						// fmt.Printf("  image[%3d] 0x%X\n", accelInit.ImageIndex, f.Mappings[0].Address+uint64(accelInit.FunctionOffset))
						f.Images[accelInit.ImageIndex].Initializer = f.Mappings[uuid][0].Address + uint64(accelInit.FunctionOffset)
					}
					// Read dyld DOF sections list.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DofSectionsOffset), io.SeekStart)
					for i := uint32(0); i != f.AcceleratorInfo.DofSectionsCount; i++ {
						accelDOF := CacheAcceleratorDof{}
						if err := binary.Read(sr, f.ByteOrder, &accelDOF); err != nil {
							return err
						}
						// fmt.Printf("  image[%3d] 0x%X -> 0x%X\n", accelDOF.ImageIndex, accelDOF.SectionAddress, accelDOF.SectionAddress+uint64(accelDOF.SectionSize))
						f.Images[accelDOF.ImageIndex].DOFSectionAddr = accelDOF.SectionAddress
						f.Images[accelDOF.ImageIndex].DOFSectionSize = accelDOF.SectionSize
					}
					// Read dyld offset to start of ss.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.RangeTableOffset), io.SeekStart)
					for i := uint32(0); i != f.AcceleratorInfo.RangeTableCount; i++ {
						rEntry := CacheRangeEntry{}
						if err := binary.Read(sr, f.ByteOrder, &rEntry); err != nil {
							return err
						}
						// fmt.Printf("  0x%X -> 0x%X %s\n", rangeEntry.StartAddress, rangeEntry.StartAddress+uint64(rangeEntry.Size), f.Images[rangeEntry.ImageIndex].Name)
						offset, err := f.GetOffsetForUUID(uuid, rEntry.StartAddress)
						if err != nil {
							return fmt.Errorf("failed to get range entry's file offset: %v", err)
						}
						f.Images[rEntry.ImageIndex].RangeEntries = append(f.Images[rEntry.ImageIndex].RangeEntries, rangeEntry{
							StartAddr:  rEntry.StartAddress,
							FileOffset: offset,
							Size:       rEntry.Size,
						})
					}
					// Read dyld trie containing all dylib paths.
					sr.Seek(accelInfoPtr+int64(f.AcceleratorInfo.DylibTrieOffset), io.SeekStart)
					dylibTrie := make([]byte, f.AcceleratorInfo.DylibTrieSize)
					if err := binary.Read(sr, f.ByteOrder, &dylibTrie); err != nil {
						return err
					}
				}
			}
		}
	}

	// Read dyld text_info entries.
	sr.Seek(int64(f.Headers[uuid].ImagesTextOffset), io.SeekStart)
	for i := uint64(0); i != f.Headers[uuid].ImagesTextCount; i++ {
		if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheImageTextInfo); err != nil {
			return err
		}
	}

	if f.Headers[uuid].SubCacheArrayCount > 0 && f.Headers[uuid].SubCacheArrayOffset > 0 {
		sr.Seek(int64(f.Headers[uuid].SubCacheArrayOffset), io.SeekStart)
		f.SubCacheInfo = make([]SubcacheEntry, f.Headers[uuid].SubCacheArrayCount)
		// TODO: gross hack to read the subcache info for pre iOS 16.
		if f.Headers[f.UUID].MappingOffset >= 0x200 {
			subCacheInfo := make([]subcacheEntry, f.Headers[uuid].SubCacheArrayCount)
			if err := binary.Read(sr, f.ByteOrder, subCacheInfo); err != nil {
				return err
			}
			for idx, scinfo := range subCacheInfo {
				f.SubCacheInfo[idx].UUID = scinfo.UUID
				f.SubCacheInfo[idx].CacheVMOffset = scinfo.CacheVMOffset
				f.SubCacheInfo[idx].Extention = string(bytes.Trim(scinfo.FileSuffix[:], "\x00"))
			}
		} else {
			subCacheInfo := make([]subcacheEntryV1, f.Headers[uuid].SubCacheArrayCount)
			if err := binary.Read(sr, f.ByteOrder, subCacheInfo); err != nil {
				return err
			}
			for idx, scinfo := range subCacheInfo {
				f.SubCacheInfo[idx].UUID = scinfo.UUID
				f.SubCacheInfo[idx].CacheVMOffset = scinfo.CacheVMOffset
			}
		}
	}

	if f.Headers[uuid].MappingOffset >= 0x208 {
		// read TPRO mapping info
		sr.Seek(int64(f.Headers[uuid].TPROMappingOffset), io.SeekStart)
		f.TPROMappings = make([]TPROMapping, f.Headers[uuid].TPROMappingCount)
		if err := binary.Read(sr, f.ByteOrder, f.TPROMappings); err != nil {
			return fmt.Errorf("failed to read DSC TPRO mappings (new in iOS18.0beta1): %v", err)
		}
	}

	return nil
}

// Size returns the size of the cache file(s)
func (f *File) Size() int64 {
	return f.size
}

// GetSubCacheInfo returns the subcache info for the given UUID.
func (f *File) GetSubCacheInfo(uuid mtypes.UUID) *SubcacheEntry {
	for _, info := range f.SubCacheInfo {
		if info.UUID == uuid {
			return &info
		}
	}
	if f.UUID == uuid {
		return &SubcacheEntry{
			UUID:          uuid,
			CacheVMOffset: 0,
			Extention:     "primary",
		}
	}
	if f.symUUID == uuid {
		mapping, err := f.GetMappingForOffsetForUUID(f.SubCacheInfo[len(f.SubCacheInfo)-1].UUID, 0)
		if err != nil {
			return nil
		}
		return &SubcacheEntry{
			UUID:          uuid,
			CacheVMOffset: f.SubCacheInfo[len(f.SubCacheInfo)-1].CacheVMOffset + mapping.Size,
			Extention:     ".symbols",
		}
	}
	log.Errorf("UUID not found in subcache info %s", uuid)
	return nil
}

// GetNextSubCacheInfo returns the subcache info after the given UUID.
func (f *File) GetNextSubCacheInfo(uuid mtypes.UUID) *SubcacheEntry {
	for idx, info := range f.SubCacheInfo {
		if info.UUID == uuid {
			if idx+1 < len(f.SubCacheInfo) {
				return &f.SubCacheInfo[idx+1]
			}
		}
	}
	return nil
}

func (f *File) ParseImageArrays() error {
	// Read dyld image array info
	if f.Headers[f.UUID].DylibsImageArrayAddr > 0 || f.Headers[f.UUID].DylibsPblSetAddr > 0 {
		if err := f.GetDylibsImageArray(); err != nil {
			return fmt.Errorf("failed to parse dylibs image array: %v", err)
		}
	}

	// Read other image array info
	if f.Headers[f.UUID].OtherImageArrayAddr > 0 {
		if err := f.GetDlopenOtherImageArray(); err != nil {
			return fmt.Errorf("failed to parse other image array: %v", err)
		}
	}

	// Read program closure image array info
	if f.Headers[f.UUID].ProgClosuresTrieAddr > 0 || f.Headers[f.UUID].ProgramTrieAddr > 0 {
		if err := f.GetProgClosureImageArray(); err != nil {
			return fmt.Errorf("failed to parse program launch closures: %v", err)
		}
	}

	return nil
}

func (f *File) ParseStubIslands() error {
	for _, sc := range f.SubCacheInfo {
		if f.Headers[sc.UUID].ImagesCountOld == 0 && f.Headers[sc.UUID].ImagesCount == 0 {
			// found a stub island
			dat := make([]byte, f.Headers[sc.UUID].CodeSignatureOffset-0x4000)
			if _, err := f.r[sc.UUID].ReadAt(dat, 0x4000); err != nil {
				return fmt.Errorf("failed to read stub island data: %v", err)
			}
			stubs, err := disass.ParseStubsASM(dat, f.MappingsWithSlideInfo[sc.UUID][0].Address+0x4000, func(u uint64) (uint64, error) {
				return f.ReadPointerAtAddress(u)
			})
			if err != nil {
				return err
			}
			for k, v := range stubs {
				f.islandStubs[k] = v
			}
		}
	}
	return nil
}

// GetSlideInfo returns just the slideinfo header info
func (f *File) GetSlideInfo(uuid mtypes.UUID, mapping *CacheMappingWithSlideInfo) error {
	_, err := f.parseSlideInfo(uuid, mapping, false, false, 0, 0)
	return err
}

// DumpSlideInfo dumps dyld slide info for a given mapping
func (f *File) DumpSlideInfo(uuid mtypes.UUID, mapping *CacheMappingWithSlideInfo) error {
	_, err := f.parseSlideInfo(uuid, mapping, true, true, 0, 0)
	return err
}

// GetRebaseInfoForPages returns an offset to rebase address map for a given page index range
func (f *File) GetRebaseInfoForPages(uuid mtypes.UUID, mapping *CacheMappingWithSlideInfo, start, end uint64) ([]Rebase, error) {
	return f.parseSlideInfo(uuid, mapping, false, true, start, end)
}

func (f *File) parseSlideInfo(uuid mtypes.UUID, mapping *CacheMappingWithSlideInfo, dump bool, parsePages bool, startPage, endPage uint64) ([]Rebase, error) {
	var symName string
	var rebases []Rebase

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(mapping.SlideInfoOffset), io.SeekStart)

	// get version
	slideInfoVersionData := make([]byte, 4)
	sr.Read(slideInfoVersionData)
	slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

	sr.Seek(int64(mapping.SlideInfoOffset), io.SeekStart)

	switch slideInfoVersion {
	case 1:
		slideInfo := CacheSlideInfo{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return nil, err
		}

		if f.SlideInfo != nil {
			if f.SlideInfo.GetVersion() != slideInfo.GetVersion() {
				return nil, fmt.Errorf("found mixed slide info versions: %d and %d", f.SlideInfo.GetVersion(), slideInfo.GetVersion())
			}
		}

		f.SlideInfo = slideInfo

		if !parsePages {
			return nil, nil
		}

		output(dump, "slide info version = %d\n", slideInfo.Version)
		output(dump, "toc_count          = %d\n", slideInfo.TocCount)
		output(dump, "data page count    = %d\n", mapping.Size/4096)

		sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.EntriesOffset)), io.SeekStart)
		entries := make([]CacheSlideInfoEntry, int(slideInfo.EntriesCount))
		if err := binary.Read(sr, binary.LittleEndian, &entries); err != nil {
			return nil, err
		}

		sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.TocOffset)), io.SeekStart)
		tocs := make([]uint16, int(slideInfo.TocCount))
		if err := binary.Read(sr, binary.LittleEndian, &tocs); err != nil {
			return nil, err
		}
		// FIXME: what should I do for version 1 rebases ?
		for i, toc := range tocs {
			output(dump, "%#08x: [% 5d,% 5d] ", int(mapping.Address)+i*4096, i, tocs[i])
			for j := 0; i < int(slideInfo.EntriesSize); i++ {
				output(dump, "%02x", entries[toc].bits[j])
			}
			output(dump, "\n")
		}
	case 2:
		slideInfo := CacheSlideInfo2{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return nil, err
		}

		if f.SlideInfo != nil {
			if f.SlideInfo.GetVersion() != slideInfo.GetVersion() {
				return nil, fmt.Errorf("found mixed slide info versions: %d and %d", f.SlideInfo.GetVersion(), slideInfo.GetVersion())
			}
		}

		f.SlideInfo = slideInfo

		if !parsePages {
			return nil, nil
		}

		output(dump, "slide info version = %d\n", slideInfo.Version)
		output(dump, "page_size          = %d\n", slideInfo.PageSize)
		output(dump, "delta_mask         = %#016x\n", slideInfo.DeltaMask)
		output(dump, "value_add          = %#x\n", slideInfo.ValueAdd)
		output(dump, "page_starts_count  = %d\n", slideInfo.PageStartsCount)
		output(dump, "page_extras_count  = %d\n", slideInfo.PageExtrasCount)

		var targetValue uint64
		var pointer uint64

		sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.PageStartsOffset)), io.SeekStart)
		starts := make([]uint16, slideInfo.PageStartsCount)
		if err := binary.Read(sr, binary.LittleEndian, &starts); err != nil {
			return nil, err
		}

		if endPage == 0 || endPage > uint64(len(starts)-1) {
			endPage = uint64(len(starts) - 1) // set end page to MAX
		}

		sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.PageExtrasOffset)), io.SeekStart)
		extras := make([]uint16, int(slideInfo.PageExtrasCount))
		if err := binary.Read(sr, binary.LittleEndian, &extras); err != nil {
			return nil, err
		}

		for i, start := range starts[startPage:endPage] {
			i += int(startPage)
			pageAddress := mapping.Address + uint64(uint32(i)*slideInfo.PageSize)
			pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)
			rebaseChain := func(pageContent uint64, startOffset uint32) error {
				deltaShift := uint64(bits.TrailingZeros64(slideInfo.DeltaMask) - 2)
				delta := uint32(1)
				for delta != 0 {
					sr.Seek(int64(pageContent+uint64(startOffset)), io.SeekStart)
					if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
						return err
					}

					delta = uint32(pointer & slideInfo.DeltaMask >> deltaShift)
					targetValue = slideInfo.SlidePointer(pointer)

					if dump {
						sym, ok := f.AddressToSymbol[targetValue]
						if !ok {
							symName = "?"
						} else {
							symName = sym
						}
						fmt.Printf("    [% 5d + %#04x]: %#016x = %#016x, sym: %s\n", i, startOffset, pointer, targetValue, symName)
					} else {
						sym, ok := f.AddressToSymbol[targetValue]
						if !ok {
							symName = ""
						} else {
							symName = sym
						}
						rebases = append(rebases, Rebase{
							CacheFileOffset: uint64(startOffset) + pageOffset,
							CacheVMAddress:  uint64(startOffset) + pageAddress,
							Target:          targetValue,
							Pointer:         pointer,
							Symbol:          symName,
						})
					}
					startOffset += delta
				}
				return nil
			}

			if start == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE {
				output(dump, "page[% 5d]: no rebasing\n", i)
			} else if start&DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA != 0 {
				output(dump, "page[% 5d]: ", i)
				j := start & 0x3FFF
				done := false
				for !done {
					aStart := extras[j]
					output(dump, "start=%#04x ", aStart&0x3FFF)
					pageStartOffset := (aStart & 0x3FFF) * 4
					rebaseChain(pageOffset, uint32(pageStartOffset))
					done = (extras[j] & DYLD_CACHE_SLIDE_PAGE_ATTR_END) != 0
					j++
				}
				output(dump, "\n")
			} else {
				output(dump, "page[% 5d]: start=%#04X\n", i, starts[i])
				rebaseChain(pageOffset, uint32(start*4))
			}
		}
	case 3:
		slideInfo := CacheSlideInfo3{}
		if err := binary.Read(sr, binary.LittleEndian, &slideInfo); err != nil {
			return nil, err
		}

		if f.SlideInfo != nil {
			if f.SlideInfo.GetVersion() != slideInfo.GetVersion() {
				return nil, fmt.Errorf("found mixed slide info versions: %d and %d", f.SlideInfo.GetVersion(), slideInfo.GetVersion())
			}
		}

		f.SlideInfo = slideInfo

		if !parsePages {
			return nil, nil
		}

		output(dump, "slide info version = %d\n", slideInfo.Version)
		output(dump, "page_size          = %d\n", slideInfo.PageSize)
		output(dump, "page_starts_count  = %d\n", slideInfo.PageStartsCount)
		output(dump, "auth_value_add     = %#x\n", slideInfo.AuthValueAdd)

		var targetValue uint64
		var pointer CacheSlidePointer3

		starts := make([]uint16, slideInfo.PageStartsCount)
		if err := binary.Read(sr, binary.LittleEndian, &starts); err != nil {
			return nil, err
		}

		if endPage == 0 || endPage > uint64(len(starts)-1) {
			endPage = uint64(len(starts) - 1) // set end page to MAX
		}

		for i, start := range starts[startPage:endPage] {
			i += int(startPage)
			pageAddress := mapping.Address + uint64(uint32(i)*slideInfo.PageSize)
			pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)

			delta := uint64(start)

			if delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
				output(dump, "page[% 5d]: no rebasing\n", i)
				continue
			}

			output(dump, "page[% 5d]: start=0x%04X\n", i, delta)

			rebaseLocation := pageOffset
			rebaseAddr := pageAddress

			for {
				rebaseLocation += delta
				rebaseAddr += delta

				sr.Seek(int64(rebaseLocation), io.SeekStart)
				if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
					return nil, err
				}

				if pointer.Authenticated() {
					targetValue = slideInfo.AuthValueAdd + pointer.OffsetFromSharedCacheBase()
				} else {
					targetValue = pointer.SignExtend51()
				}

				if dump {
					sym, ok := f.AddressToSymbol[targetValue]
					if !ok {
						symName = "?"
					} else {
						symName = sym
					}
					fmt.Printf("    [% 5d + 0x%05X] (off: %#x @ vaddr: %#x; raw: %#x => target: %#x) %s, sym: %s\n", i, (uint64)(rebaseLocation-pageOffset), rebaseLocation, rebaseAddr, pointer.Raw(), targetValue, pointer, symName)
				} else {
					sym, ok := f.AddressToSymbol[targetValue]
					if !ok {
						symName = ""
					} else {
						symName = sym
					}
					rebases = append(rebases, Rebase{
						CacheFileOffset: rebaseLocation,
						CacheVMAddress:  rebaseAddr,
						Target:          targetValue,
						Pointer:         uint64(pointer),
						Symbol:          symName,
					})
				}

				if pointer.OffsetToNextPointer() == 0 {
					break
				}

				delta = pointer.OffsetToNextPointer() * 8
			}
		}
	case 4:
		slideInfo := CacheSlideInfo4{}
		if err := binary.Read(sr, f.ByteOrder, &slideInfo); err != nil {
			return nil, err
		}

		if f.SlideInfo != nil {
			if f.SlideInfo.GetVersion() != slideInfo.GetVersion() {
				return nil, fmt.Errorf("found mixed slide info versions: %d and %d", f.SlideInfo.GetVersion(), slideInfo.GetVersion())
			}
		}

		f.SlideInfo = slideInfo

		if !parsePages {
			return nil, nil
		}

		output(dump, "slide info version = %d\n", slideInfo.Version)
		output(dump, "page_size          = %d\n", slideInfo.PageSize)
		output(dump, "delta_mask         = %#016x\n", slideInfo.DeltaMask)
		output(dump, "value_add          = %#016x\n", slideInfo.ValueAdd)
		output(dump, "page_starts_count  = %d\n", slideInfo.PageStartsCount)
		output(dump, "page_extras_count  = %d\n", slideInfo.PageExtrasCount)

		var targetValue uint64
		var pointer uint32

		sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.PageStartsOffset)), io.SeekStart)
		starts := make([]uint16, slideInfo.PageStartsCount)
		if err := binary.Read(sr, binary.LittleEndian, &starts); err != nil {
			return nil, err
		}

		if endPage == 0 { // set end page to MAX
			endPage = uint64(len(starts) - 1)
		}

		sr.Seek(int64(mapping.SlideInfoOffset+uint64(slideInfo.PageExtrasOffset)), io.SeekStart)
		extras := make([]uint16, int(slideInfo.PageExtrasCount))
		if err := binary.Read(sr, binary.LittleEndian, &extras); err != nil {
			return nil, err
		}

		for i, start := range starts[startPage:endPage] {
			i += int(startPage)
			pageAddress := mapping.Address + uint64(uint32(i)*slideInfo.PageSize)
			pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)
			rebaseChainV4 := func(pageContent uint64, startOffset uint16) error {
				deltaShift := uint64(bits.TrailingZeros64(slideInfo.DeltaMask) - 2)
				pageOffset := uint32(startOffset)
				delta := uint32(1)
				for delta != 0 {
					sr.Seek(int64(pageContent+uint64(pageOffset)), io.SeekStart)
					if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
						return err
					}

					delta = uint32(uint64(pointer) & slideInfo.DeltaMask >> deltaShift)
					targetValue = slideInfo.SlidePointer(uint64(pointer))

					if dump {
						sym, ok := f.AddressToSymbol[targetValue]
						if !ok {
							symName = "?"
						} else {
							symName = sym
						}
						fmt.Printf("    [% 5d + %#04x]: %#08x = %#08x, sym: %s\n", i, pageOffset, pointer, targetValue, symName)
					} else {
						sym, ok := f.AddressToSymbol[targetValue]
						if !ok {
							symName = ""
						} else {
							symName = sym
						}
						rebases = append(rebases, Rebase{
							CacheFileOffset: pageContent + uint64(pageOffset),
							CacheVMAddress:  pageContent + uint64(pageAddress),
							Target:          targetValue,
							Pointer:         uint64(pointer),
							Symbol:          symName,
						})
					}
					pageOffset += delta
				}

				return nil
			}
			if start == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE {
				output(dump, "page[% 5d]: no rebasing\n", i)
			} else if start&DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA != 0 {
				output(dump, "page[% 5d]: ", i)
				j := (start & DYLD_CACHE_SLIDE4_PAGE_INDEX)
				done := false
				for !done {
					aStart := extras[j]
					output(dump, "start=0x%04X ", aStart&DYLD_CACHE_SLIDE4_PAGE_INDEX)
					pageStartOffset := (aStart & DYLD_CACHE_SLIDE4_PAGE_INDEX) * 4
					rebaseChainV4(pageOffset, pageStartOffset)
					done = (extras[j] & DYLD_CACHE_SLIDE4_PAGE_EXTRA_END) != 0
					j++
				}
				output(dump, "\n")
			} else {
				output(dump, "page[% 5d]: start=0x%04X\n", i, starts[i])
				rebaseChainV4(pageOffset, start*4)
			}
		}
	case 5:
		slideInfo := CacheSlideInfo5{}
		if err := binary.Read(sr, binary.LittleEndian, &slideInfo); err != nil {
			return nil, err
		}

		f.SlideInfo = slideInfo

		if !parsePages {
			return nil, nil
		}

		output(dump, "slide info version = %d\n", slideInfo.Version)
		output(dump, "page_size          = %#x\n", slideInfo.PageSize)
		output(dump, "page_starts_count  = %d\n", slideInfo.PageStartsCount)
		output(dump, "auth_value_add     = %#x\n", slideInfo.ValueAdd)

		var targetValue uint64
		var pointer CacheSlidePointer5

		starts := make([]uint16, slideInfo.PageStartsCount)
		if err := binary.Read(sr, binary.LittleEndian, &starts); err != nil {
			return nil, err
		}

		if endPage == 0 || endPage > uint64(len(starts)-1) {
			endPage = uint64(len(starts) - 1) // set end page to MAX
		}

		for i, start := range starts[startPage:endPage] {
			i += int(startPage)
			pageAddress := mapping.Address + uint64(uint32(i)*slideInfo.PageSize)
			pageOffset := mapping.FileOffset + uint64(uint32(i)*slideInfo.PageSize)

			delta := uint64(start)

			if delta == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE {
				output(dump, "page[% 5d]: no rebasing\n", i)
				continue
			}

			output(dump, "page[% 5d]: start=0x%04X\n", i, delta)

			rebaseLocation := pageOffset
			rebaseAddr := pageAddress

			for {
				rebaseLocation += delta
				rebaseAddr += delta

				sr.Seek(int64(rebaseLocation), io.SeekStart)
				if err := binary.Read(sr, binary.LittleEndian, &pointer); err != nil {
					return nil, err
				}

				if pointer.Authenticated() {
					targetValue = slideInfo.ValueAdd + pointer.Value()
				} else {
					targetValue = slideInfo.ValueAdd + pointer.SignExtend51()
				}

				if dump {
					sym, ok := f.AddressToSymbol[targetValue]
					if !ok {
						symName = "?"
					} else {
						symName = sym
					}
					fmt.Printf("    [% 5d + 0x%05X] (off: %#x @ vaddr: %#x; raw: %#x => target: %#x) %s, sym: %s\n", i, (uint64)(rebaseLocation-pageOffset), rebaseLocation, rebaseAddr, pointer.Raw(), targetValue, pointer, symName)
				} else {
					sym, ok := f.AddressToSymbol[targetValue]
					if !ok {
						symName = ""
					} else {
						symName = sym
					}
					rebases = append(rebases, Rebase{
						CacheFileOffset: rebaseLocation,
						CacheVMAddress:  rebaseAddr,
						Target:          targetValue,
						Pointer:         pointer.Raw(),
						Symbol:          symName,
					})
				}

				if pointer.OffsetToNextPointer() == 0 {
					break
				}

				delta = pointer.OffsetToNextPointer() * 8
			}
		}
	default:
		log.Errorf("got unexpected dyld slide info version: %d", slideInfoVersion)
	}

	return rebases, nil
}

func (f *File) patchInfoVersion() (uint32, error) {
	if f.IsDyld4 {
		uuid, patchInfoOffset, err := f.GetOffset(f.Headers[f.UUID].PatchInfoAddr)
		if err != nil {
			return 0, fmt.Errorf("failed to get patch info v2 offset: %v", err)
		}

		sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(patchInfoOffset), io.SeekStart)

		var pinfo CachePatchInfoV2
		if err := binary.Read(sr, f.ByteOrder, &pinfo); err != nil {
			return 0, fmt.Errorf("failed to read patch info v2: %v", err)
		}

		return pinfo.TableVersion, nil
	}

	return 1, nil
}

// ParsePatchInfo parses dyld patch info
func (f *File) ParsePatchInfo() error {
	var err error
	if f.Headers[f.UUID].PatchInfoAddr > 0 {
		f.PatchInfoVersion, err = f.patchInfoVersion()
		if err != nil {
			return fmt.Errorf("failed to get patch info version: %v", err)
		}
		switch f.PatchInfoVersion {
		case 1:
			if err := f.parsePatchInfoV1(); err != nil {
				return fmt.Errorf("failed to parse patch info v1: %v", err)
			}
		case 2, 3:
			if err := f.parsePatchInfoV2(); err != nil {
				return fmt.Errorf("failed to parse patch info v%d: %v", f.PatchInfoVersion, err)
			}
		case 4:
			if err := f.parsePatchInfoV4(); err != nil {
				return fmt.Errorf("failed to parse patch info v%d: %v", f.PatchInfoVersion, err)
			}
		default:
			return fmt.Errorf("unsupported patch info version: %d", f.PatchInfoVersion)
		}
		return nil
	}
	return fmt.Errorf("cache does NOT contain patch info")
}

func (f *File) parsePatchInfoV1() error {
	// Read dyld patch_info entries.
	uuid, patchInfoOffset, err := f.GetOffset(f.Headers[f.UUID].PatchInfoAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch info v1 offset: %v", err)
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(patchInfoOffset), io.SeekStart)

	var patchInfo CachePatchInfoV1
	if err := binary.Read(sr, f.ByteOrder, &patchInfo); err != nil {
		return fmt.Errorf("failed to read patch info v1: %v", err)
	}

	// Read all the other patch_info structs
	uuid, patchTableArrayOffset, err := f.GetOffset(patchInfo.PatchTableArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch table v1 array offset: %v", err)
	}

	sr.Seek(int64(patchTableArrayOffset), io.SeekStart)

	imagePatches := make([]CacheImagePatchesV1, patchInfo.PatchTableArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &imagePatches); err != nil {
		return fmt.Errorf("failed to read patch table v1 array: %v", err)
	}

	uuid, patchExportNamesOffset, err := f.GetOffset(patchInfo.PatchExportNamesAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch export v1 names offset: %v", err)
	}

	exportNames := io.NewSectionReader(f.r[uuid], int64(patchExportNamesOffset), int64(patchInfo.PatchExportNamesSize))

	uuid, patchExportArrayOffset, err := f.GetOffset(patchInfo.PatchExportArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch export v1 array offset: %v", err)
	}

	sr.Seek(int64(patchExportArrayOffset), io.SeekStart)

	patchExports := make([]CachePatchableExportV1, patchInfo.PatchExportArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &patchExports); err != nil {
		return fmt.Errorf("failed to read patch export v1 array: %v", err)
	}

	uuid, patchLocationArrayOffset, err := f.GetOffset(patchInfo.PatchLocationArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch location v1 array offset: %v", err)
	}

	sr.Seek(int64(patchLocationArrayOffset), io.SeekStart)
	patchableLocations := make([]CachePatchableLocationV1, patchInfo.PatchLocationArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &patchableLocations); err != nil {
		return fmt.Errorf("failed to read patch location v1 array: %v", err)
	}

	// Add patchabled export info to images
	for i, iPatch := range imagePatches {
		if iPatch.PatchExportsCount > 0 {
			for exportIndex := uint32(0); exportIndex != iPatch.PatchExportsCount; exportIndex++ {
				patchExport := patchExports[iPatch.PatchExportsStartIndex+exportIndex]
				var exportName string
				if uint64(patchExport.ExportNameOffset) < patchInfo.PatchExportNamesSize {
					exportNames.Seek(int64(patchExport.ExportNameOffset), io.SeekStart)
					s, err := bufio.NewReader(exportNames).ReadString('\x00')
					if err != nil {
						return fmt.Errorf("failed to read patch info v1 export string at %x: %v", uint32(patchExportNamesOffset)+patchExport.ExportNameOffset, err)
					}
					exportName = strings.Trim(s, "\x00")
				} else {
					exportName = ""
				}
				plocs := make([]CachePatchableLocationV1, patchExport.PatchLocationsCount)
				for locationIndex := uint32(0); locationIndex != patchExport.PatchLocationsCount; locationIndex++ {
					plocs[locationIndex] = patchableLocations[patchExport.PatchLocationsStartIndex+locationIndex]
				}
				f.Images[i].PatchableExports = append(f.Images[i].PatchableExports, PatchableExport{
					Name:           exportName,
					OffsetOfImpl:   patchExport.CacheOffsetOfImpl,
					PatchLocations: plocs,
				})
			}
		}
	}

	return nil
}

func (f *File) parsePatchInfoV2() error {

	uuid, patchInfoOffset, err := f.GetOffset(f.Headers[f.UUID].PatchInfoAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch info v2 offset: %v", err)
	}
	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchInfoOffset), io.SeekStart)
	var patchInfo CachePatchInfoV3
	if err := binary.Read(sr, f.ByteOrder, &patchInfo); err != nil {
		return fmt.Errorf("failed to read patch info v2: %v", err)
	}
	// patchArray
	uuid, patchTableArrayOffset, err := f.GetOffset(patchInfo.TableArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch table v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchTableArrayOffset), io.SeekStart)
	patchArray := make([]CacheImagePatchesV2, patchInfo.TableArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &patchArray); err != nil {
		return fmt.Errorf("failed to read patch table v2 array: %v", err)
	}
	// imageExports
	uuid, patchImageExportsOffset, err := f.GetOffset(patchInfo.ImageExportsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch image exports v2 offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchImageExportsOffset), io.SeekStart)
	imageExports := make([]CacheImageExportV2, patchInfo.ImageExportsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &imageExports); err != nil {
		return fmt.Errorf("failed to read patch image exports v2 array: %v", err)
	}
	// clientArray
	uuid, patchClientsArrayOffset, err := f.GetOffset(patchInfo.ClientsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch clients v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchClientsArrayOffset), io.SeekStart)
	clientArray := make([]CacheImageClientsV2, patchInfo.ClientsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &clientArray); err != nil {
		return fmt.Errorf("failed to read patch clients v2 array: %v", err)
	}
	// clientExports
	uuid, patchClientExportsArrayOffset, err := f.GetOffset(patchInfo.ClientExportsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch client exports v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchClientExportsArrayOffset), io.SeekStart)
	clientExports := make([]CachePatchableExportV2, patchInfo.ClientExportsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &clientExports); err != nil {
		return fmt.Errorf("failed to read patch client exports v2 array: %v", err)
	}
	// patchLocations
	uuid, patchLocationArrayOffset, err := f.GetOffset(patchInfo.LocationArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch location v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchLocationArrayOffset), io.SeekStart)
	patchLocations := make([]CachePatchableLocationV2, patchInfo.LocationArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &patchLocations); err != nil {
		return fmt.Errorf("failed to read patch location v2 array: %v", err)
	}
	// exportNames
	uuid, patchExportNamesOffset, err := f.GetOffset(patchInfo.ExportNamesAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch export v2 names offset: %v", err)
	}
	exportNames := io.NewSectionReader(f.r[uuid], int64(patchExportNamesOffset), int64(patchInfo.ExportNamesSize))

	// Add patchabled export info to images
	for i, patch := range patchArray {
		for clientIndex := uint32(0); clientIndex < patch.ClientsCount; clientIndex++ {
			client := clientArray[patch.ClientsStartIndex+clientIndex]
			for exportIndex := uint32(0); exportIndex != client.PatchExportsCount; exportIndex++ {
				clientExport := clientExports[client.PatchExportsStartIndex+exportIndex]
				imageExport := imageExports[clientExport.ImageExportIndex]
				var exportName string
				if uint64(imageExport.GetExportNameOffset()) < patchInfo.ExportNamesSize {
					exportNames.Seek(int64(imageExport.GetExportNameOffset()), io.SeekStart)
					s, err := bufio.NewReader(exportNames).ReadString('\x00')
					if err != nil {
						return fmt.Errorf("failed to read patch info v1 export string at %x: %v", uint32(patchExportNamesOffset)+imageExport.ExportNameOffset, err)
					}
					exportName = strings.Trim(s, "\x00")
				} else {
					exportName = ""
				}
				plocs := make([]CachePatchableLocationV2, clientExport.PatchLocationsCount)
				for locationIndex := uint32(0); locationIndex != clientExport.PatchLocationsCount; locationIndex++ {
					plocs[locationIndex] = patchLocations[clientExport.PatchLocationsStartIndex+locationIndex]
				}
				f.Images[i].PatchableExports = append(f.Images[i].PatchableExports, PatchableExport{
					Name:             exportName,
					Kind:             imageExport.GetPatchKind().String(),
					ClientIndex:      client.ClientDylibIndex,
					OffsetOfImpl:     imageExport.DylibOffsetOfImpl,
					PatchLocationsV2: plocs,
				})
			}
		}
	}

	if f.PatchInfoVersion == 3 {
		// GOT clients
		uuid, patchGOTClientsArrayOffset, err := f.GetOffset(patchInfo.GotClientsArrayAddr)
		if err != nil {
			return fmt.Errorf("failed to get patch GOT clients v3 array offset: %v", err)
		}
		sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(patchGOTClientsArrayOffset), io.SeekStart)
		gotClients := make([]CacheImageGotClientsV3, patchInfo.GotClientsArrayCount)
		if err := binary.Read(sr, f.ByteOrder, &gotClients); err != nil {
			return fmt.Errorf("failed to read patch GOT clients v3 array: %v", err)
		}
		// GOT client exports
		uuid, patchGOTClientExportsArrayOffset, err := f.GetOffset(patchInfo.GotClientExportsArrayAddr)
		if err != nil {
			return fmt.Errorf("failed to get patch GOT client exports v3 array offset: %v", err)
		}
		sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(patchGOTClientExportsArrayOffset), io.SeekStart)
		gotClientExports := make([]CachePatchableExportV3, patchInfo.GotClientExportsArrayCount)
		if err := binary.Read(sr, f.ByteOrder, &gotClientExports); err != nil {
			return fmt.Errorf("failed to read patch GOT client exports v3 array: %v", err)
		}
		// GOT patch locations
		uuid, patchGOTLocationArrayOffset, err := f.GetOffset(patchInfo.GotLocationArrayAddr)
		if err != nil {
			return fmt.Errorf("failed to get patch GOT location v3 array offset: %v", err)
		}
		sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(patchGOTLocationArrayOffset), io.SeekStart)
		gotPatchLocations := make([]CachePatchableLocationV3, patchInfo.GotLocationArrayCount)
		if err := binary.Read(sr, f.ByteOrder, &gotPatchLocations); err != nil {
			return fmt.Errorf("failed to read patch GOT location v3 array: %v", err)
		}

		for idx, gcli := range gotClients {
			for exportIndex := uint32(0); exportIndex < gcli.PatchExportsCount; exportIndex++ {
				gcliexp := gotClientExports[gcli.PatchExportsStartIndex+exportIndex]
				imageExport := imageExports[gcliexp.ImageExportIndex]
				var exportName string
				if uint64(imageExport.GetExportNameOffset()) < patchInfo.ExportNamesSize {
					exportNames.Seek(int64(imageExport.GetExportNameOffset()), io.SeekStart)
					s, err := bufio.NewReader(exportNames).ReadString('\x00')
					if err != nil {
						return fmt.Errorf("failed to read patch info v1 export string at %x: %v", uint32(patchExportNamesOffset)+imageExport.ExportNameOffset, err)
					}
					exportName = strings.Trim(s, "\x00")
				} else {
					exportName = ""
				}
				gots := make([]CachePatchableLocationV3, gcliexp.PatchLocationsCount)
				for locIndex := uint32(0); locIndex != gcliexp.PatchLocationsCount; locIndex++ {
					gots[locIndex] = gotPatchLocations[gcliexp.PatchLocationsStartIndex+locIndex]
				}
				f.Images[idx].PatchableGOTs = append(f.Images[idx].PatchableGOTs, PatchableGotExport{
					Name:           exportName,
					Kind:           imageExport.GetPatchKind().String(),
					OffsetOfImpl:   imageExport.DylibOffsetOfImpl,
					GotLocationsV3: gots,
				})
			}
		}
	}

	return nil
}

func (f *File) parsePatchInfoV4() error {

	uuid, patchInfoOffset, err := f.GetOffset(f.Headers[f.UUID].PatchInfoAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch info v4 offset: %v", err)
	}
	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchInfoOffset), io.SeekStart)
	var patchInfo CachePatchInfoV3
	if err := binary.Read(sr, f.ByteOrder, &patchInfo); err != nil {
		return fmt.Errorf("failed to read patch info v3: %v", err)
	}
	// patchArray
	uuid, patchTableArrayOffset, err := f.GetOffset(patchInfo.TableArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch table v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchTableArrayOffset), io.SeekStart)
	patchArray := make([]CacheImagePatchesV2, patchInfo.TableArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &patchArray); err != nil {
		return fmt.Errorf("failed to read patch table v2 array: %v", err)
	}
	// imageExports
	uuid, patchImageExportsOffset, err := f.GetOffset(patchInfo.ImageExportsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch image exports v2 offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchImageExportsOffset), io.SeekStart)
	imageExports := make([]CacheImageExportV2, patchInfo.ImageExportsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &imageExports); err != nil {
		return fmt.Errorf("failed to read patch image exports v2 array: %v", err)
	}
	// clientArray
	uuid, patchClientsArrayOffset, err := f.GetOffset(patchInfo.ClientsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch clients v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchClientsArrayOffset), io.SeekStart)
	clientArray := make([]CacheImageClientsV2, patchInfo.ClientsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &clientArray); err != nil {
		return fmt.Errorf("failed to read patch clients v2 array: %v", err)
	}
	// clientExports
	uuid, patchClientExportsArrayOffset, err := f.GetOffset(patchInfo.ClientExportsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch client exports v2 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchClientExportsArrayOffset), io.SeekStart)
	clientExports := make([]CachePatchableExportV2, patchInfo.ClientExportsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &clientExports); err != nil {
		return fmt.Errorf("failed to read patch client exports v2 array: %v", err)
	}
	// patchLocations
	uuid, patchLocationArrayOffset, err := f.GetOffset(patchInfo.LocationArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch location v4 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchLocationArrayOffset), io.SeekStart)
	patchLocations := make([]CachePatchableLocationV4, patchInfo.LocationArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &patchLocations); err != nil {
		return fmt.Errorf("failed to read patch location v4 array: %v", err)
	}
	// exportNames
	uuid, patchExportNamesOffset, err := f.GetOffset(patchInfo.ExportNamesAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch export names offset: %v", err)
	}
	exportNames := io.NewSectionReader(f.r[uuid], int64(patchExportNamesOffset), int64(patchInfo.ExportNamesSize))

	// Add patchabled export info to images
	for i, patch := range patchArray {
		for clientIndex := uint32(0); clientIndex < patch.ClientsCount; clientIndex++ {
			client := clientArray[patch.ClientsStartIndex+clientIndex]
			for exportIndex := uint32(0); exportIndex != client.PatchExportsCount; exportIndex++ {
				clientExport := clientExports[client.PatchExportsStartIndex+exportIndex]
				imageExport := imageExports[clientExport.ImageExportIndex]
				var exportName string
				if uint64(imageExport.GetExportNameOffset()) < patchInfo.ExportNamesSize {
					exportNames.Seek(int64(imageExport.GetExportNameOffset()), io.SeekStart)
					s, err := bufio.NewReader(exportNames).ReadString('\x00')
					if err != nil {
						return fmt.Errorf("failed to read patch info export string at %x: %v", uint32(patchExportNamesOffset)+imageExport.ExportNameOffset, err)
					}
					exportName = strings.Trim(s, "\x00")
				} else {
					exportName = ""
				}
				plocs := make([]CachePatchableLocationV4, clientExport.PatchLocationsCount)
				for locationIndex := uint32(0); locationIndex != clientExport.PatchLocationsCount; locationIndex++ {
					plocs[locationIndex] = patchLocations[clientExport.PatchLocationsStartIndex+locationIndex]
				}
				f.Images[i].PatchableExports = append(f.Images[i].PatchableExports, PatchableExport{
					Name:             exportName,
					Kind:             imageExport.GetPatchKind().String(),
					ClientIndex:      client.ClientDylibIndex,
					OffsetOfImpl:     imageExport.DylibOffsetOfImpl,
					PatchLocationsV4: plocs,
				})
			}
		}
	}

	// GOT clients
	uuid, patchGOTClientsArrayOffset, err := f.GetOffset(patchInfo.GotClientsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch GOT clients v3 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchGOTClientsArrayOffset), io.SeekStart)
	gotClients := make([]CacheImageGotClientsV3, patchInfo.GotClientsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &gotClients); err != nil {
		return fmt.Errorf("failed to read patch GOT clients v3 array: %v", err)
	}
	// GOT client exports
	uuid, patchGOTClientExportsArrayOffset, err := f.GetOffset(patchInfo.GotClientExportsArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch GOT client exports v3 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchGOTClientExportsArrayOffset), io.SeekStart)
	gotClientExports := make([]CachePatchableExportV3, patchInfo.GotClientExportsArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &gotClientExports); err != nil {
		return fmt.Errorf("failed to read patch GOT client exports v3 array: %v", err)
	}
	// GOT patch locations
	uuid, patchGOTLocationArrayOffset, err := f.GetOffset(patchInfo.GotLocationArrayAddr)
	if err != nil {
		return fmt.Errorf("failed to get patch GOT location v4 array offset: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	sr.Seek(int64(patchGOTLocationArrayOffset), io.SeekStart)
	gotPatchLocations := make([]CachePatchableLocationV4Got, patchInfo.GotLocationArrayCount)
	if err := binary.Read(sr, f.ByteOrder, &gotPatchLocations); err != nil {
		return fmt.Errorf("failed to read patch GOT location v4 array: %v", err)
	}

	for idx, gcli := range gotClients {
		for exportIndex := uint32(0); exportIndex < gcli.PatchExportsCount; exportIndex++ {
			gcliexp := gotClientExports[gcli.PatchExportsStartIndex+exportIndex]
			imageExport := imageExports[gcliexp.ImageExportIndex]
			var exportName string
			if uint64(imageExport.GetExportNameOffset()) < patchInfo.ExportNamesSize {
				exportNames.Seek(int64(imageExport.GetExportNameOffset()), io.SeekStart)
				s, err := bufio.NewReader(exportNames).ReadString('\x00')
				if err != nil {
					return fmt.Errorf("failed to read patch info GOT export string at %x: %v", uint32(patchExportNamesOffset)+imageExport.ExportNameOffset, err)
				}
				exportName = strings.Trim(s, "\x00")
			} else {
				exportName = ""
			}
			gots := make([]CachePatchableLocationV4Got, gcliexp.PatchLocationsCount)
			for locIndex := uint32(0); locIndex != gcliexp.PatchLocationsCount; locIndex++ {
				gots[locIndex] = gotPatchLocations[gcliexp.PatchLocationsStartIndex+locIndex]
			}
			f.Images[idx].PatchableGOTs = append(f.Images[idx].PatchableGOTs, PatchableGotExport{
				Name:           exportName,
				Kind:           imageExport.GetPatchKind().String(),
				ImageIndex:     gcliexp.ImageExportIndex,
				OffsetOfImpl:   imageExport.DylibOffsetOfImpl,
				GotLocationsV4: gots,
			})
		}
	}

	return nil
}

// Image returns the Image with the given name, or nil if no such image exists.
func (f *File) Image(name string) (*CacheImage, error) {
	// fast path
	if idx, err := f.GetDylibIndex(name); err == nil {
		return f.Images[idx], nil
	}
	// slow path
	var matches []*CacheImage
	for _, i := range f.Images {
		if strings.EqualFold(strings.ToLower(i.Name), strings.ToLower(name)) {
			matches = append(matches, i)
		} else if strings.EqualFold(strings.ToLower(filepath.Base(i.Name)), strings.ToLower(name)) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	} else if len(matches) > 1 {
		var names []string
		for _, m := range matches {
			names = append(names, m.Name)
		}
		return nil, fmt.Errorf("multiple images found for %s (please supply FULL path):\n\t- %s", name, strings.Join(names, "\n\t- "))
	}
	return nil, fmt.Errorf("image %s not found in cache", name)
}

func (f *File) Search(search []byte) (map[mtypes.UUID][]uint64, error) {
	chunkSize := uint64(4096)
	tailLen := uint64(len(search) - 1)
	chunk := make([]byte, chunkSize+tailLen)
	matches := make(map[mtypes.UUID][]uint64)
	for uuid, cache := range f.r {
		var offset uint64
		sr := io.NewSectionReader(cache, 0, 1<<63-1)
		n, err := sr.Read(chunk[tailLen:])
		idx := bytes.Index(chunk[tailLen:uint64(n)+tailLen], search)
		for {
			if idx >= 0 {
				// scan backwards to find the start of the line
				nullIdx := bytes.LastIndexByte(chunk[:uint64(idx)+tailLen], 0x00)
				if nullIdx >= 0 {
					if uint64(offset+uint64(nullIdx+1)) > 0 && uint64(offset+uint64(nullIdx+1)) >= uint64(len(search)-1) {
						matches[uuid] = append(matches[uuid], uint64(offset+uint64(nullIdx+1))-uint64(len(search)-1))
					} else {
						matches[uuid] = append(matches[uuid], uint64(offset+uint64(nullIdx+1)))
					}
				} else {
					matches[uuid] = append(matches[uuid], uint64(offset+uint64(idx)))
				}
			}
			if err == io.EOF {
				break
			} else if err != nil {
				return matches, err
			}
			copy(chunk, chunk[chunkSize:])
			offset += chunkSize
			n, err = sr.Read(chunk[tailLen:])
			idx = bytes.Index(chunk[:uint64(n)+tailLen], search)
		}
	}
	return matches, nil
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
func (f *File) GetImageContainingVMAddr(address uint64) (*CacheImage, error) {
	for _, img := range f.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			return nil, err
		}
		defer m.Close()
		if seg := m.FindSegmentForVMAddr(address); seg != nil {
			return img, nil
		}
	}
	return nil, fmt.Errorf("address %#x not in any dylib", address)
}

// HasImagePath returns the index of a given image path
func (f *File) HasImagePath(path string) (int, error) {
	var imageIndex uint64
	if f.Headers[f.UUID].MappingOffset >= 0x118 {
		uuid, off, err := f.GetOffset(f.Headers[f.UUID].DylibsTrieAddr)
		if err != nil {
			return -1, fmt.Errorf("failed to get dylibs trie offset: %v", err)
		}
		dylibTrie, err := f.ReadBytesForUUID(uuid, int64(off), f.Headers[f.UUID].DylibsTrieSize)
		if err != nil {
			return -1, fmt.Errorf("failed to read dylibs trie: %v", err)
		}
		imageNode, err := trie.WalkTrie(bytes.NewReader(dylibTrie), path)
		if err != nil {
			return -1, err
		}
		imageIndex, _, err = trie.ReadUleb128FromBuffer(bytes.NewBuffer(dylibTrie[imageNode:]))
		if err != nil {
			return -1, err
		}
	} else {
		img, err := f.Image(path)
		if err != nil {
			return -1, err
		}
		imageIndex = uint64(img.Index)
	}

	return int(imageIndex), nil
}
