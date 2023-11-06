package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/pkg/errors"
)

const (
	mask uint64 = (1 << 40) - 1 // 40bit mask
)

type optFlags uint32

const (
	IsProduction              optFlags = (1 << 0) // never set in development cache
	NoMissingWeakSuperclasses optFlags = (1 << 1) // set in development cache and customer
	LargeSharedCache          optFlags = (1 << 2) // Shared cache was built with the new Large format
)

// objcInfo is the dyld_shared_cache dylib objc object
type objcInfo struct {
	Methods   []objc.Method
	ClassRefs map[uint64]*objc.Class
	SuperRefs map[uint64]*objc.Class
	SelRefs   map[uint64]*objc.Selector
	ProtoRefs map[uint64]*objc.Protocol
	CatRefs   map[uint64]*objc.Category
	CFStrings []objc.CFString
	Stubs     map[uint64]*objc.Stub
}

type ObjcClassheaderT struct {
	ClsOffset int32
	HiOffset  int32
}

type ClassHeaderV16T uint64

func (h ClassHeaderV16T) IsDuplicate() bool {
	return types.ExtractBits(uint64(h), 0, 1) == 1
}

// ObjectCacheOffset returns offset from the shared cache base
func (h ClassHeaderV16T) ObjectCacheOffset() uint64 {
	return types.ExtractBits(uint64(h), 1, 47)
}
func (h ClassHeaderV16T) DylibObjCIndex() uint16 {
	return uint16(types.ExtractBits(uint64(h), 48, 16))
}

type Optimization interface {
	GetVersion() uint32
	GetFlags() optFlags
	// HeaderInfoRO() uint64
	// HeaderInfoRW() uint64
	SelectorHashTableOffset(uint64) uint64
	ClassHashTableOffset(uint64) uint64
	ProtocolHashTableOffset(uint64) uint64
	RelativeMethodListsBaseAddress(uint64) uint64
}

/*
 * objc_opt_t - op-level optimization structure. <dyld/include/objc-shared-cache.h>
 */

// ObjcOptT is a objc_opt_t structure
type ObjcOptT struct {
	Version                                      uint32
	Flags                                        optFlags
	SelectorOptOffset                            int32
	HeaderOptRoOffset                            int32
	UnusedClassOptOffset                         int32
	UnusedProtocolOptOffset                      int32
	HeaderoptRwOffset                            int32
	UnusedProtocolOpt2Offset                     int32
	LargeSharedCachesClassOffset                 int32
	LargeSharedCachesProtocolOffset              int32
	RelativeMethodSelectorBaseAddressCacheOffset int64
}

func (o *ObjcOptT) GetVersion() uint32 {
	return o.Version
}
func (o *ObjcOptT) GetFlags() optFlags {
	return o.Flags
}
func (o *ObjcOptT) SelectorHashTableOffset(base uint64) uint64 {
	return uint64(int64(base) + int64(o.SelectorOptOffset))
}
func (o *ObjcOptT) ClassHashTableOffset(base uint64) uint64 {
	switch o.Version {
	case 16:
		return uint64(int64(base) + int64(o.LargeSharedCachesClassOffset))
	default:
		return uint64(int64(base) + int64(o.UnusedClassOptOffset))
	}
}
func (o *ObjcOptT) ProtocolHashTableOffset(base uint64) uint64 {
	switch o.Version {
	case 16:
		return uint64(int64(base) + int64(o.LargeSharedCachesProtocolOffset))
	case 15:
		return uint64(int64(base) + int64(o.UnusedProtocolOpt2Offset))
	default:
		return uint64(int64(base) + int64(o.UnusedProtocolOptOffset))
	}
}
func (o *ObjcOptT) RelativeMethodListsBaseAddress(base uint64) uint64 {
	return uint64(int64(base) + int64(o.RelativeMethodSelectorBaseAddressCacheOffset))
}

func (o *ObjcOptT) isPointerAligned() bool {
	return (binary.Size(o) % 8) == 0
}

func (o ObjcOptT) GetClassOffset() int32 {
	if o.Version >= 16 {
		return o.LargeSharedCachesClassOffset
	} else {
		return o.UnusedClassOptOffset
	}
}

// ObjCOptimizationHeader is the NEW LargeSharedCache objc optimization header
type ObjCOptimizationHeader struct {
	Version                                 uint32
	Flags                                   optFlags
	HeaderInfoRoCacheOffset                 uint64
	HeaderInfoRwCacheOffset                 uint64
	SelectorHashTableCacheOffset            uint64
	ClassHashTableCacheOffset               uint64
	ProtocolHashTableCacheOffset            uint64
	RelativeMethodSelectorBaseAddressOffset uint64
}

func (o *ObjCOptimizationHeader) GetVersion() uint32 {
	if o.Version == 1 {
		return 16
	}
	return o.Version
}
func (o *ObjCOptimizationHeader) GetFlags() optFlags {
	return o.Flags
}
func (o *ObjCOptimizationHeader) GetHeaderInfoRoCacheOffset() uint64 {
	return o.HeaderInfoRoCacheOffset
}
func (o *ObjCOptimizationHeader) GetHeaderInfoRwCacheOffset() uint64 {
	return o.HeaderInfoRwCacheOffset
}
func (o *ObjCOptimizationHeader) SelectorHashTableOffset(base uint64) uint64 {
	return o.SelectorHashTableCacheOffset
}
func (o *ObjCOptimizationHeader) ClassHashTableOffset(base uint64) uint64 {
	return o.ClassHashTableCacheOffset
}
func (o *ObjCOptimizationHeader) ProtocolHashTableOffset(base uint64) uint64 {
	return o.ProtocolHashTableCacheOffset
}
func (o *ObjCOptimizationHeader) RelativeMethodListsBaseAddress(base uint64) uint64 {
	return o.RelativeMethodSelectorBaseAddressOffset
}

func (f *File) getLibObjC() (*macho.File, error) {
	image, err := f.Image("/usr/lib/libobjc.A.dylib")
	if err != nil {
		return nil, err
	}

	if image.pm == nil {
		image.pm, err = image.GetPartialMacho()
		if err != nil {
			return nil, err
		}
	}

	return image.pm, nil
}

func (f *File) getOptimizationsOld() (Optimization, error) {

	libObjC, err := f.getLibObjC()
	if err != nil {
		return nil, err
	}

	if s := libObjC.Section("__TEXT", "__objc_opt_ro"); s != nil {
		uuid, off, err := f.GetOffset(s.Addr)
		if err != nil {
			return nil, err
		}
		dat, err := f.ReadBytesForUUID(uuid, int64(off), s.Size)
		if err != nil {
			return nil, fmt.Errorf("failed to read __TEXT.__objc_opt_ro data")
		}
		opt := ObjcOptT{}
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &opt); err != nil {
			return nil, err
		}
		if opt.Version > 16 {
			return nil, fmt.Errorf("objc optimization version should be 16 or less, but found %d", opt.Version)
		}
		// log.Debugf("Objective-C Optimizations:\n%s", opt)
		return &opt, nil
	}

	return nil, fmt.Errorf("unable to find section __TEXT.__objc_opt_ro in /usr/lib/libobjc.A.dylib")
}

func (f *File) GetOptimizations() (Optimization, error) {
	if f.Headers[f.UUID].MappingOffset > uint32(unsafe.Offsetof(f.Headers[f.UUID].ObjcOptsSize)) { // check for NEW objc optimizations
		if f.Headers[f.UUID].ObjcOptsOffset > 0 && f.Headers[f.UUID].ObjcOptsSize > 0 {
			uuid, off, err := f.GetOffset(f.Headers[f.UUID].SharedRegionStart + f.Headers[f.UUID].ObjcOptsOffset)
			if err != nil {
				return nil, fmt.Errorf("failed to get offset for NEW objc optimization header at addr %#x: %v",
					f.Headers[f.UUID].SharedRegionStart+f.Headers[f.UUID].ObjcOptsOffset, err)
			}

			sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
			sr.Seek(int64(off), io.SeekStart)

			var o ObjCOptimizationHeader
			if err := binary.Read(sr, f.ByteOrder, &o); err != nil {
				return nil, fmt.Errorf("failed to read NEW objc optimization header: %v", err)
			}

			return &o, nil
		}
	}
	// check for OLD objc optimizations
	return f.getOptimizationsOld()
}

// GetAllHeaderRO dumps the header_ro from the optimized string hash
func (f *File) getHeaderInfoRO() (*objc_headeropt_ro_t, error) {

	var off uint64
	var u types.UUID
	var hdr objc_headeropt_ro_t

	opt, err := f.GetOptimizations()
	if err != nil {
		return nil, err
	}

	switch o := opt.(type) {
	case *ObjCOptimizationHeader:
		hdr.offset = o.GetHeaderInfoRoCacheOffset()
		u, off, err = f.GetCacheOffset(o.GetHeaderInfoRoCacheOffset())
		if err != nil {
			return nil, err
		}
		sr := io.NewSectionReader(f.r[u], 0, 1<<63-1)
		sr.Seek(int64(off), io.SeekStart)
		if err := binary.Read(sr, f.ByteOrder, &hdr.Count); err != nil {
			return nil, err
		}
		if err := binary.Read(sr, f.ByteOrder, &hdr.Entsize); err != nil {
			return nil, err
		}
		hdr.Headers = make([]header_info_ro, hdr.Count)
		if err := binary.Read(sr, f.ByteOrder, &hdr.Headers); err != nil {
			return nil, err
		}
	case *ObjcOptT:
		u, off, err = f.GetOffset(f.objcOptRoAddr + uint64(o.HeaderOptRoOffset))
		if err != nil {
			return nil, err
		}
		hdr.offset = off
		sr := io.NewSectionReader(f.r[u], 0, 1<<63-1)
		sr.Seek(int64(off), io.SeekStart)
		if err := binary.Read(sr, f.ByteOrder, &hdr.Count); err != nil {
			return nil, err
		}
		if err := binary.Read(sr, f.ByteOrder, &hdr.Entsize); err != nil {
			return nil, err
		}
		hdr.Headers = make([]header_info_ro, hdr.Count)
		if err := binary.Read(sr, f.ByteOrder, &hdr.Headers); err != nil {
			return nil, err
		}
	}

	return &hdr, nil
}

func (f *File) getSelectorStringHash() (*StringHash, *types.UUID, error) {

	var off uint64
	var u types.UUID
	var shash StringHash

	opt, err := f.GetOptimizations()
	if err != nil {
		return nil, nil, err
	}

	hdr, err := f.getHeaderInfoRO()
	if err != nil {
		return nil, nil, err
	}

	switch o := opt.(type) {
	case *ObjCOptimizationHeader:
		u, off, err = f.GetCacheOffset(o.SelectorHashTableOffset(0))
		if err != nil {
			return nil, nil, err
		}
		shash = StringHash{Type: selopt, FileOffset: int64(off), hdrRO: hdr, opt: opt}
		if err = shash.Read(io.NewSectionReader(f.r[u], 0, 1<<63-1)); err != nil {
			return nil, nil, err
		}
	case *ObjcOptT:
		u, off, err = f.GetOffset(f.objcOptRoAddr)
		if err != nil {
			return nil, nil, err
		}
		shash = StringHash{Type: selopt, FileOffset: int64(opt.SelectorHashTableOffset(off)), hdrRO: hdr, opt: opt}
		if err = shash.Read(io.NewSectionReader(f.r[u], 0, 1<<63-1)); err != nil {
			return nil, nil, err
		}
	}

	return &shash, &u, nil
}

func (f *File) getClassStringHash() (*StringHash, *types.UUID, error) {

	var off uint64
	var u types.UUID
	var shash StringHash

	opt, err := f.GetOptimizations()
	if err != nil {
		return nil, nil, err
	}

	hdr, err := f.getHeaderInfoRO()
	if err != nil {
		return nil, nil, err
	}

	switch o := opt.(type) {
	case *ObjCOptimizationHeader:
		u, off, err = f.GetCacheOffset(o.ClassHashTableOffset(0))
		if err != nil {
			return nil, nil, err
		}
		shash = StringHash{Type: clsopt, FileOffset: int64(off), hdrRO: hdr, opt: opt}
		if err = shash.Read(io.NewSectionReader(f.r[u], 0, 1<<63-1)); err != nil {
			return nil, nil, err
		}
	case *ObjcOptT:
		u, off, err = f.GetOffset(f.objcOptRoAddr)
		if err != nil {
			return nil, nil, err
		}
		shash = StringHash{Type: clsopt, FileOffset: int64(opt.ClassHashTableOffset(off)), hdrRO: hdr, opt: opt}
		if err = shash.Read(io.NewSectionReader(f.r[u], 0, 1<<63-1)); err != nil {
			return nil, nil, err
		}
	}

	return &shash, &u, nil
}

func (f *File) getProtocolStringHash() (*StringHash, *types.UUID, error) {

	var off uint64
	var u types.UUID
	var shash StringHash

	opt, err := f.GetOptimizations()
	if err != nil {
		return nil, nil, err
	}

	hdr, err := f.getHeaderInfoRO()
	if err != nil {
		return nil, nil, err
	}

	switch o := opt.(type) {
	case *ObjCOptimizationHeader:
		u, off, err = f.GetCacheOffset(o.ProtocolHashTableOffset(0))
		if err != nil {
			return nil, nil, err
		}
		shash = StringHash{Type: clsopt, FileOffset: int64(off), hdrRO: hdr, opt: opt}
		if err = shash.Read(io.NewSectionReader(f.r[u], 0, 1<<63-1)); err != nil {
			return nil, nil, err
		}
	case *ObjcOptT:
		u, off, err = f.GetOffset(f.objcOptRoAddr)
		if err != nil {
			return nil, nil, err
		}
		shash = StringHash{Type: clsopt, FileOffset: int64(opt.ProtocolHashTableOffset(off)), hdrRO: hdr, opt: opt}
		if err = shash.Read(io.NewSectionReader(f.r[u], 0, 1<<63-1)); err != nil {
			return nil, nil, err
		}
	}

	return &shash, &u, nil
}

func (f *File) getObjcDylibMap(shash *StringHash) {
	if shash.dylibMap == nil {
		shash.dylibMap = make(map[uint16]string)
		for _, image := range f.Images {
			if idx, err := shash.hdrRO.FindElement(image.LoadAddress); err == nil {
				shash.dylibMap[idx] = image.Name
			}
		}
	}
}

func (f *File) dumpOffsets(shash *StringHash, uuid types.UUID) {
	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
	for idx, ptr := range shash.Offsets {
		if ptr != 0 {
			sr.Seek(int64(int32(shash.FileOffset)+ptr), io.SeekStart)
			s, err := bufio.NewReader(sr).ReadString('\x00')
			if err != nil {
				log.Errorf("failed to read selector name at %#x: %v", int32(shash.FileOffset)+ptr, err)
			}
			if len(shash.ObjectOffsets) > 0 {
				log.Debug(shash.ObjectOffsets[idx].String())
				if !shash.ObjectOffsets[idx].IsDuplicate() {
					_, addr, err := f.GetCacheVMAddress(shash.ObjectOffsets[idx].ObjectCacheOffset())
					if err != nil {
						log.Errorf("failed to get cache vmaddr for object at cache vmoffset %#x: %v", shash.ObjectOffsets[idx].ObjectCacheOffset(), err)
					}
					if img, ok := shash.dylibMap[shash.ObjectOffsets[idx].DylibObjCIndex()]; ok {
						fmt.Printf("%s: %s\t%s\n", symAddrColor("%#09x", addr), strings.Trim(s, "\x00"), symImageColor(filepath.Base(img)))
					} else {
						fmt.Printf("%s: %s\n", symAddrColor("%#09x", addr), strings.Trim(s, "\x00"))
					}
				} else {
					for i := uint16(0); i < shash.ObjectOffsets[idx].DuplicateCount(); i++ {
						_, addr, err := f.GetCacheVMAddress(shash.DuplicateOffsets[shash.ObjectOffsets[idx].DuplicateIndex()+uint64(i)].ObjectCacheOffset())
						if err != nil {
							log.Errorf("failed to get cache vmaddr for object at cache vmoffset %#x: %v", shash.ObjectOffsets[idx].ObjectCacheOffset(), err)
						}
						if img, ok := shash.dylibMap[shash.DuplicateOffsets[shash.ObjectOffsets[idx].DuplicateIndex()+uint64(i)].DylibObjCIndex()]; ok {
							fmt.Printf("    %s: %s\t%s\n", symAddrColor("%#09x", addr), strings.Trim(s, "\x00"), symImageColor(filepath.Base(img)))
						} else {
							fmt.Printf("    %s: %s\n", symAddrColor("%#09x", addr), strings.Trim(s, "\x00"))
						}
					}
				}
			} else {
				addr, _ := f.GetVMAddressForUUID(uuid, uint64(int32(shash.FileOffset)+ptr))
				fmt.Printf("%s: %s\n", symAddrColor("%#09x", addr), strings.Trim(s, "\x00"))
			}
		}
	}
}

type objc_headeropt_ro_t struct {
	offset  uint64
	Count   uint32
	Entsize uint32
	Headers []header_info_ro
}
type header_info_ro struct {
	// Note, this is no longer a pointer, but instead an offset to a pointer
	// from this location.
	MhdrOffset int64

	// Note, this is no longer a pointer, but instead an offset to a pointer
	// from this location.
	InfoOffset int64

	// Note, this is no longer a pointer, but instead an offset to a pointer
	// from this location.
	// This may not be present in old shared caches
	DyldInfoOffset int64

	// // Offset from this location to the non-lazy class list
	// NlclslistOffset int64
	// NlclslistCount  uint64

	// // Offset from this location to the non-lazy category list
	// NlcatlistOffset int64
	// NlcatlistCount  uint64

	// // Offset from this location to the category list
	// CatlistOffset int64
	// CatlistCount  uint64

	// // Offset from this location to the category list 2
	// Catlist2Offset int64
	// Catlist2Count  uint64
}

func (h *objc_headeropt_ro_t) GetMachoHdrOffset(index int) (uint64, error) {
	if h == nil {
		return 0, fmt.Errorf("objc_headeropt_ro_t is nil")
	}
	if index > len(h.Headers) {
		return 0, fmt.Errorf("index out of range")
	}
	return uint64(int64(h.offset) + 8 + int64(index*binary.Size(header_info_ro{})) + h.Headers[index].MhdrOffset), nil
}
func (h *objc_headeropt_ro_t) FindElement(addr uint64) (uint16, error) {
	if h == nil {
		return 0, fmt.Errorf("objc_headeropt_ro_t is nil")
	}
	for idx, hdr := range h.Headers {
		calcAddr := uint64(int64(h.offset) + 8 + int64(idx*binary.Size(header_info_ro{})) + hdr.MhdrOffset)
		if (0x180000000 + calcAddr) == addr { // FIXME: this is for arm64 and shouldn't be hardcoded
			return uint16(idx), nil
		}
	}
	return 0, fmt.Errorf("failed to find element for address %#x", addr)
}
func (h *objc_headeropt_ro_t) GetObjcInfoOffset(index int) (uint64, error) {
	if h == nil {
		return 0, fmt.Errorf("objc_headeropt_ro_t is nil")
	}
	if index > len(h.Headers) {
		return 0, fmt.Errorf("index out of range")
	}
	return uint64(int64(h.offset) + 8 + int64(unsafe.Offsetof(h.Headers[index].InfoOffset)) + int64(index*binary.Size(header_info_ro{})) + h.Headers[index].InfoOffset), nil
}
func (h *objc_headeropt_ro_t) GetDyldInfoOffset(index int) (uint64, error) {
	if h == nil {
		return 0, fmt.Errorf("objc_headeropt_ro_t is nil")
	}
	if index > len(h.Headers) {
		return 0, fmt.Errorf("index out of range")
	}
	return uint64(int64(h.offset) + 8 + int64(unsafe.Offsetof(h.Headers[index].DyldInfoOffset)) + int64(index*binary.Size(header_info_ro{})) + h.Headers[index].DyldInfoOffset), nil
}

type objc_headeropt_rw_t struct {
	Count   uint32
	Entsize uint32
	Headers []header_info_rw
}
type header_info_rw uint64

func (rw header_info_rw) IsLoaded() bool {
	return types.ExtractBits(uint64(rw), 0, 1) == 1
}
func (rw header_info_rw) AllClassesRealized() bool {
	return types.ExtractBits(uint64(rw), 1, 1) == 1
}
func (rw header_info_rw) Next() uint64 {
	return types.ExtractBits(uint64(rw), 62, 2)
}

// func (f *File) dumpHeaderROOffsets(offsets []int32, fileOffset int64) {
// 	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
// 	sr := io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)
// 	for _, ptr := range offsets {
// 		if ptr != 0 {
// 			// sr.Seek(int64(int32(fileOffset)+ptr), io.SeekStart)
// 			sr.Seek(int64(int32(fileOffset)), io.SeekStart)
// 			var opt objc_headeropt_ro_t

// 			// off, err = f.GetOffset(f.SlideInfo.SlidePointer(classPtr.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64)
// 			// if err != nil {
// 			// 	return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
// 			// }

// 			// sr.Seek(int64(off), io.SeekStart)
// 			if err := binary.Read(sr, f.ByteOrder, &opt.Count); err != nil {
// 				log.Errorf("failed to read objc_headeropt_ro_t: %v", err)
// 			}
// 			if err := binary.Read(sr, f.ByteOrder, &opt.Entsize); err != nil {
// 				log.Errorf("failed to read objc_headeropt_ro_t: %v", err)
// 			}
// 			opt.Headers = make([]header_info, int(opt.Count))
// 			if err := binary.Read(sr, f.ByteOrder, &opt.Headers); err != nil {
// 				log.Errorf("failed to read objc_headeropt_ro_t: %v", err)
// 			}

// 			addr, _ := f.GetVMAddressForUUID(f.UUID,uint64(int32(fileOffset) + ptr))
// 			fmt.Printf("    0x%x: %#v\n", addr, opt)
// 		}

// 	}
// }

type objHashMap struct {
	Dylib string
	Name  string
}

func (f *File) offsetsToMap(shash *StringHash, uuid types.UUID) map[uint64]objHashMap {

	objcMap := make(map[uint64]objHashMap)
	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	for idx, ptr := range shash.Offsets {
		if ptr != 0 {
			sr.Seek(int64(int32(shash.FileOffset)+ptr), io.SeekStart)
			s, err := bufio.NewReader(sr).ReadString('\x00')
			if err != nil {
				log.Errorf("failed to read objc name at %#x: %v", int32(shash.FileOffset)+ptr, err)
			}
			addr, err := f.GetVMAddressForUUID(uuid, uint64(int32(shash.FileOffset)+ptr))
			if err != nil {
				log.Errorf("failed to get vmaddr for objc object at %#x: %v", int32(shash.FileOffset)+ptr, err)
			}
			s = strings.Trim(s, "\x00")
			f.AddressToSymbol[addr] = s
			if len(shash.ObjectOffsets) > 0 {
				if !shash.ObjectOffsets[idx].IsDuplicate() {
					_, addr, err := f.GetCacheVMAddress(shash.ObjectOffsets[idx].ObjectCacheOffset())
					if err != nil {
						log.Errorf("failed to get cache vmaddr for object at cache vmoffset %#x: %v", shash.ObjectOffsets[idx].ObjectCacheOffset(), err)
					} else {
						if len(shash.dylibMap) > 0 {
							objcMap[addr] = objHashMap{
								Dylib: filepath.Base(shash.dylibMap[shash.ObjectOffsets[idx].DylibObjCIndex()]),
								Name:  s,
							}
						} else {
							objcMap[addr] = objHashMap{Name: s}
						}
						f.AddressToSymbol[addr] = s
					}
				} else {
					for i := uint16(0); i < shash.ObjectOffsets[idx].DuplicateCount(); i++ {
						_, addr, err := f.GetCacheVMAddress(shash.DuplicateOffsets[shash.ObjectOffsets[idx].DuplicateIndex()+uint64(i)].ObjectCacheOffset())
						if err != nil {
							log.Errorf("failed to get cache vmaddr for object at cache vmoffset %#x: %v", shash.ObjectOffsets[idx].ObjectCacheOffset(), err)
						} else {
							if len(shash.dylibMap) > 0 {
								objcMap[addr] = objHashMap{
									Dylib: filepath.Base(shash.dylibMap[shash.DuplicateOffsets[shash.ObjectOffsets[idx].DuplicateIndex()+uint64(i)].DylibObjCIndex()]),
									Name:  s,
								}
							} else {
								objcMap[addr] = objHashMap{Name: s}
							}
							f.AddressToSymbol[addr] = s
						}
					}
				}
			} else {
				objcMap[addr] = objHashMap{Name: s}
			}
		}
	}

	return objcMap
}

// GetAllSelectors is a dumb brute force way to get all the ObjC selector/class etc address
// by just dumping all the strings in the __OBJC_RO segment
// returns: map[sym]addr
func (f *File) GetAllObjCSelectors(print bool) (map[uint64]objHashMap, error) {
	shash, uuid, err := f.getSelectorStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read selector objc_stringhash_t: %v", err)
	}

	f.getObjcDylibMap(shash)

	if print {
		f.dumpOffsets(shash, *uuid)
	}

	return f.offsetsToMap(shash, *uuid), nil
}

func (f *File) getStringHashAddresses(shash *StringHash, index uint32, uuid *types.UUID) ([]uint64, error) {
	if len(shash.ObjectOffsets) > 0 {
		if !shash.ObjectOffsets[index].IsDuplicate() {
			_, addr, err := f.GetCacheVMAddress(shash.ObjectOffsets[index].ObjectCacheOffset())
			if err != nil {
				return nil, fmt.Errorf("failed to get cache vmaddr for objc type at cache vmoffset %#x: %v", shash.ObjectOffsets[index].ObjectCacheOffset(), err)
			}
			return []uint64{addr}, nil
		} else {
			var addrs []uint64
			for i := uint16(0); i < shash.ObjectOffsets[index].DuplicateCount(); i++ {
				_, addr, err := f.GetCacheVMAddress(shash.DuplicateOffsets[shash.ObjectOffsets[index].DuplicateIndex()+uint64(i)].ObjectCacheOffset())
				if err != nil {
					log.Errorf("failed to get cache vmaddr for objc type at cache vmoffset %#x: %v", shash.ObjectOffsets[index].ObjectCacheOffset(), err)
				} else {
					addrs = append(addrs, addr)
				}
			}
			addrs = utils.Unique(addrs)
			return addrs, nil
		}
	}

	addr, err := f.GetVMAddressForUUID(*uuid, uint64(shash.FileOffset+int64(shash.Offsets[index])))
	if err != nil {
		return nil, fmt.Errorf("failed get address for objc type: %w", err)
	}

	return []uint64{addr}, nil
}

// GetSelectorAddress returns a selector addresses
func (f *File) GetSelectorAddresses(selector string) ([]uint64, error) {
	shash, uuid, err := f.getSelectorStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed get selector objc_stringhash_t for %s: %v", selector, err)
	}

	idx, err := shash.getIndex(selector)
	if err != nil {
		return nil, fmt.Errorf("failed get selector address for %s", selector)
	}

	return f.getStringHashAddresses(shash, idx, uuid)
}

// GetAllClasses dumps the classes from the optimized string hash
func (f *File) GetAllObjCClasses(print bool) (map[uint64]objHashMap, error) {
	shash, uuid, err := f.getClassStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read class objc_stringhash_t: %v", err)
	}

	f.getObjcDylibMap(shash)

	if print {
		f.dumpOffsets(shash, *uuid)
	}

	return f.offsetsToMap(shash, *uuid), nil
}

// GetClassAddress returns a class addresses
func (f *File) GetClassAddresses(class string) ([]uint64, error) {
	shash, uuid, err := f.getClassStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read class objc_stringhash_t: %v", err)
	}

	idx, err := shash.getIndex(class)
	if err != nil {
		return nil, fmt.Errorf("failed get class address for %s: %v", class, err)
	}

	return f.getStringHashAddresses(shash, idx, uuid)
}

// GetAllProtocols dumps the protols from the optimized string hash
func (f *File) GetAllObjCProtocols(print bool) (map[uint64]objHashMap, error) {
	shash, uuid, err := f.getProtocolStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read protocol objc_stringhash_t: %v", err)
	}

	f.getObjcDylibMap(shash)

	if print {
		f.dumpOffsets(shash, *uuid)
	}

	return f.offsetsToMap(shash, *uuid), nil
}

// GetProtocolAddress returns a protocol addresses
func (f *File) GetProtocolAddresses(protocol string) ([]uint64, error) {
	shash, uuid, err := f.getProtocolStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read protocol objc_stringhash_t: %v", err)
	}

	idx, err := shash.getIndex(protocol)
	if err != nil {
		return nil, fmt.Errorf("failed get protocol index for %s: %v", protocol, err)
	}

	return f.getStringHashAddresses(shash, idx, uuid)
}

// ClassesForImage returns all of the Objective-C classes for a given image
func (f *File) ClassesForImage(imageNames ...string) error {
	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}

		image.ObjC.ClassRefs, err = m.GetObjCClassReferences()
		if err != nil {
			return err
		}

		for ptr, class := range image.ObjC.ClassRefs {
			if len(class.Name) > 0 {
				f.AddressToSymbol[class.ClassPtr] = fmt.Sprintf("class_%s", class.Name)
				if sym, ok := f.AddressToSymbol[ptr]; ok {
					if len(sym) < len(class.Name) {
						f.AddressToSymbol[ptr] = class.Name
					}
				} else {
					f.AddressToSymbol[ptr] = class.Name
				}
			}
		}

		image.ObjC.SuperRefs, err = m.GetObjCSuperReferences()
		if err != nil {
			return err
		}

		for ptr, class := range image.ObjC.SuperRefs {
			if len(class.Name) > 0 {
				f.AddressToSymbol[class.ClassPtr] = fmt.Sprintf("class_%s", class.Name)
				if sym, ok := f.AddressToSymbol[ptr]; ok {
					if len(sym) < len(class.Name) {
						f.AddressToSymbol[ptr] = class.Name
					}
				} else {
					f.AddressToSymbol[ptr] = class.Name
				}
			}
		}
	}

	return nil
}

// CategoriesForImage returns all of the Objective-C categories for a given image
func (f *File) CategoriesForImage(imageNames ...string) error {
	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}

		cats, err := m.GetObjCCategories()
		if err != nil {
			return err
		}

		for _, cat := range cats {
			if len(cat.Name) > 0 {
				f.AddressToSymbol[cat.VMAddr] = fmt.Sprintf("cat_%s", cat.Name)
				if sym, ok := f.AddressToSymbol[cat.VMAddr]; ok {
					if len(sym) < len(cat.Name) {
						f.AddressToSymbol[cat.VMAddr] = cat.Name
					}
				} else {
					f.AddressToSymbol[cat.VMAddr] = cat.Name
				}
			}
		}
	}

	return nil
}

// ProtocolsForImage returns all of the Objective-C protocols for a given image
func (f *File) ProtocolsForImage(imageNames ...string) error {
	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetPartialMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO %v", image.Name, err)
		}
		image.ObjC.ProtoRefs, err = m.GetObjCProtoReferences()
		if err != nil {
			if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return fmt.Errorf("failed to get protocol references for image %s: %v", image.Name, err)
			}
		}
		for k, v := range image.ObjC.ProtoRefs {
			f.AddressToSymbol[v.Ptr] = v.Name
			f.AddressToSymbol[k] = fmt.Sprintf("proto_%s", v.Name)
		}
	}

	return nil
}

// SelectorsForImage returns all of the Objective-C selectors for a given image
func (f *File) SelectorsForImage(imageNames ...string) error {

	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}
		defer m.Close()

		image.ObjC.SelRefs, err = m.GetObjCSelectorReferences()
		if err != nil {
			return err
		}

		for ptr, sel := range image.ObjC.SelRefs {
			if len(sel.Name) > 0 {
				f.AddressToSymbol[ptr] = fmt.Sprintf("sel_%s", sel.Name)
				if sym, ok := f.AddressToSymbol[sel.VMAddr]; ok {
					if len(sym) < len(sel.Name) {
						f.AddressToSymbol[sel.VMAddr] = sel.Name
					}
				} else {
					f.AddressToSymbol[sel.VMAddr] = sel.Name
				}
			}
		}
	}

	return nil
}

// GetAllObjcMethods parses all the ObjC method lists in the cache dylibs
func (f *File) GetAllObjcMethods() error {
	return f.MethodsForImage()
}

// MethodsForImage returns all of the Objective-C methods for a given image
func (f *File) MethodsForImage(imageNames ...string) error {

	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}

		image.ObjC.Methods, err = m.GetObjCMethodLists()
		if err != nil {
			if errors.Is(err, macho.ErrObjcSectionNotFound) {
				return nil
			}
			return fmt.Errorf("failed to get objc methods for %s: %v", image.Name, err)
		}

		for _, meth := range image.ObjC.Methods {
			if len(meth.Name) > 0 {
				if sym, ok := f.AddressToSymbol[meth.ImpVMAddr]; ok {
					if len(sym) < len(meth.Name) {
						f.AddressToSymbol[meth.ImpVMAddr] = meth.Name
					}
				} else {
					f.AddressToSymbol[meth.ImpVMAddr] = meth.Name
				}
			}
		}
	}

	return nil
}

// ImpCachesForImage dumps all of the Objective-C imp caches for a given image
func (f *File) ImpCachesForImage(imageNames ...string) error {
	var selectorStringVMAddrStart uint64
	var selectorStringVMAddrEnd uint64

	image, err := f.Image("/usr/lib/libobjc.A.dylib")
	if err != nil {
		return err
	}

	libObjC, err := image.GetMacho()
	if err != nil {
		return err
	}

	symaddr, err := libObjC.FindSymbolAddress("_objc_opt_preopt_caches_version")
	if err != nil {
		return err
	}

	impCachesVersion, err := f.ReadPointerAtAddress(symaddr)
	if err != nil {
		return err
	}

	if sec := libObjC.Section("__DATA_CONST", "__objc_scoffs"); sec != nil {
		uuid, off, err := f.GetOffset(sec.Addr)
		if err != nil {
			return fmt.Errorf("failed to convert vmaddr: %v", err)
		}

		dat := make([]byte, sec.Size)
		if _, err := f.r[uuid].ReadAt(dat, int64(off)); err != nil {
			return fmt.Errorf("failed to read %s.%s data: %v", sec.Seg, sec.Name, err)
		}

		optOffsets := make([]uint64, sec.Size/uint64(binary.Size(uint64(0))))
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &optOffsets); err != nil {
			return err
		}

		selectorStringIndex := 0
		if impCachesVersion > 1 {
			selectorStringIndex = 1
		}

		selectorStringVMAddrStart = f.SlideInfo.SlidePointer(optOffsets[selectorStringIndex])
		selectorStringVMAddrEnd = f.SlideInfo.SlidePointer(optOffsets[selectorStringIndex+1])
		// inlinedSelectorsVMAddrStart = scoffs[2]
		// inlinedSelectorsVMAddrEnd = scoffs[3]
	} else {
		return fmt.Errorf("unable to find __DATA_CONST.__objc_scoffs")
	}

	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}

		image.ObjC.ClassRefs, err = m.GetObjCClassReferences()
		if err != nil {
			return err
		}

		for _, c := range image.ObjC.ClassRefs {

			if f.SlideInfo.SlidePointer(c.MethodCacheProperties) > 0 {
				uuid, off, err := f.GetOffset(c.MethodCacheProperties)
				if err != nil {
					return fmt.Errorf("failed to convert vmaddr: %v", err)
				}

				sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

				sr.Seek(int64(off), io.SeekStart)

				if impCachesVersion < 3 {
					var impCache objc.ImpCacheV1
					if err := binary.Read(sr, f.ByteOrder, &impCache.ImpCacheHeaderV1); err != nil {
						return fmt.Errorf("failed to read preopt_cache_t: %v", err)
					}

					impCache.Entries = make([]objc.ImpCacheEntryV1, impCache.Capacity())
					if err := binary.Read(sr, f.ByteOrder, &impCache.Entries); err != nil {
						return fmt.Errorf("failed to read []preopt_cache_entry_t: %v", err)
					}

					fmt.Printf("%s: (%s, buckets: %d)\n", c.Name, impCache.ImpCacheHeaderV1, impCache.Capacity())

					for _, bucket := range impCache.Entries {
						if bucket.SelOffset == 0xFFFFFFFF {
							fmt.Printf("  - %#09x:\n", 0)
						} else {
							if selectorStringVMAddrStart+uint64(bucket.SelOffset) < selectorStringVMAddrEnd {
								sel, err := f.GetCString(selectorStringVMAddrStart + uint64(bucket.SelOffset))
								if err != nil {
									return fmt.Errorf("failed to get cstring for selector in imp-cache bucket")
								}
								fmt.Printf("  - %#09x: %s\n", c.ClassPtr-uint64(bucket.ImpOffset), sel)
							} // TODO: handle the error case warn or crash?
						}
					}
				} else {
					var impCache objc.ImpCacheV2
					if err := binary.Read(sr, f.ByteOrder, &impCache.ImpCacheHeaderV2); err != nil {
						return fmt.Errorf("failed to read preopt_cache_t: %v", err)
					}

					impCache.Entries = make([]objc.ImpCacheEntryV2, impCache.Capacity())
					if err := binary.Read(sr, f.ByteOrder, &impCache.Entries); err != nil {
						return fmt.Errorf("failed to read []preopt_cache_entry_t: %v", err)
					}

					fmt.Printf("%s: (%s, buckets: %d)\n", c.Name, impCache.ImpCacheHeaderV2, impCache.Capacity())

					for _, bucket := range impCache.Entries {
						if bucket.GetSelOffset() == 0x3FFFFFF {
							fmt.Printf("  - %#09x:\n", 0)
						} else {
							if selectorStringVMAddrStart+uint64(bucket.GetSelOffset()) < selectorStringVMAddrEnd {
								sel, err := f.GetCString(selectorStringVMAddrStart + uint64(bucket.GetSelOffset()))
								if err != nil {
									return fmt.Errorf("failed to get cstring for selector in imp-cache bucket")
								}
								fmt.Printf("  - %#09x: %s\n", c.ClassPtr-uint64(bucket.GetImpOffset()<<2), sel)
							} // TODO: handle the error case warn or crash?
						}
					}
				}
			} else {
				fmt.Printf("%s: empty\n", c.Name)
			}
		}

		m.Close()
	}

	return nil
}

// CFStringsForImage returns all of the Objective-C cfstrings for a given image
func (f *File) CFStringsForImage(imageNames ...string) error {
	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}

		image.ObjC.CFStrings, err = m.GetCFStrings()
		if err != nil {
			return err
		}

		for _, cfstr := range image.ObjC.CFStrings {
			if len(cfstr.Name) > 0 {
				f.AddressToSymbol[cfstr.Address] = fmt.Sprintf("\"%s\"", cfstr.Name)
			}
		}
	}

	return nil
}

// GetObjCClass parses an ObjC class at a given virtual memory address
func (f *File) GetObjCClass(vmaddr uint64) (*objc.Class, error) {
	var classPtr objc.SwiftClassMetadata64

	uuid, off, err := f.GetOffset(vmaddr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}
	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(off), io.SeekStart)
	if err := binary.Read(sr, f.ByteOrder, &classPtr); err != nil {
		return nil, fmt.Errorf("failed to read swift_class_metadata_t: %v", err)
	}

	// info, err := f.GetObjCClassInfo(f.SlideInfo.SlidePointer(classPtr.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get class info at vmaddr: 0x%x; %v", classPtr.DataVMAddrAndFastFlags&objc.FAST_DATA_MASK64, err)
	// }

	var info objc.ClassRO64

	off, err = f.GetOffsetForUUID(uuid, f.SlideInfo.SlidePointer(classPtr.DataVMAddrAndFastFlags)&objc.FAST_DATA_MASK64)
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}

	sr.Seek(int64(off), io.SeekStart)
	if err := binary.Read(sr, f.ByteOrder, &info); err != nil {
		return nil, fmt.Errorf("failed to read class_ro_t: %v", err)
	}

	name, err := f.GetCString(f.SlideInfo.SlidePointer(info.NameVMAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to read cstring: %v", err)
	}

	// var methods []objc.Method
	// if info.BaseMethodsVMAddr > 0 {
	// 	methods, err = f.GetObjCMethods(f.SlideInfo.SlidePointer(info.BaseMethodsVMAddr))
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get methods at vmaddr: 0x%x; %v", info.BaseMethodsVMAddr, err)
	// 	}
	// }

	// var prots []objc.Protocol
	// if info.BaseProtocolsVMAddr > 0 {
	// 	prots, err = f.parseObjcProtocolList(info.BaseProtocolsVMAddr)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read protocols vmaddr: %v", err)
	// 	}
	// }

	// var ivars []objc.Ivar
	// if info.IvarsVMAddr > 0 {
	// 	ivars, err = f.GetObjCIvars(f.SlideInfo.SlidePointer(info.IvarsVMAddr))
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get ivars at vmaddr: 0x%x; %v", info.IvarsVMAddr, err)
	// 	}
	// }

	// var props []objc.Property
	// if info.BasePropertiesVMAddr > 0 {
	// 	props, err = f.GetObjCProperties(f.SlideInfo.SlidePointer(info.BasePropertiesVMAddr))
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to get props at vmaddr: 0x%x; %v", info.BasePropertiesVMAddr, err)
	// 	}
	// }

	// superClass := &objc.Class{Name: "<ROOT>"}
	// if classPtr.SuperclassVMAddr > 0 {
	// 	if !info.Flags.IsRoot() {
	// 		superClass, err = f.GetObjCClass(f.SlideInfo.SlidePointer(classPtr.SuperclassVMAddr))
	// 		if err != nil {
	// 			bindName, err := f.GetBindName(classPtr.SuperclassVMAddr)
	// 			if err == nil {
	// 				superClass = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
	// 			} else {
	// 				return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: 0x%x; %v", vmaddr, err)
	// 			}
	// 		}
	// 	}
	// }

	isaClass := &objc.Class{}
	var cMethods []objc.Method
	if classPtr.IsaVMAddr > 0 {
		if !info.Flags.IsMeta() {
			isaClass, err = f.GetObjCClass(f.SlideInfo.SlidePointer(classPtr.IsaVMAddr))
			if err != nil {
				// bindName, err := f.GetBindName(classPtr.IsaVMAddr)
				// if err == nil {
				// 	isaClass = &objc.Class{Name: strings.TrimPrefix(bindName, "_OBJC_CLASS_$_")}
				// } else {
				// 	return nil, fmt.Errorf("failed to read super class objc_class_t at vmaddr: 0x%x; %v", vmaddr, err)
				// }
			} else {
				if isaClass.ReadOnlyData.Flags.IsMeta() {
					cMethods = isaClass.InstanceMethods
				}
			}
		}
	}

	return &objc.Class{
		Name: name,
		// SuperClass:      superClass.Name,
		Isa: isaClass.Name,
		// InstanceMethods: methods,
		ClassMethods: cMethods,
		// Ivars:           ivars,
		// Props:           props,
		// Prots:           prots,
		ClassPtr:              vmaddr,
		IsaVMAddr:             f.SlideInfo.SlidePointer(classPtr.IsaVMAddr),
		SuperclassVMAddr:      f.SlideInfo.SlidePointer(classPtr.SuperclassVMAddr),
		MethodCacheBuckets:    classPtr.MethodCacheBuckets,
		MethodCacheProperties: classPtr.MethodCacheProperties,
		DataVMAddr:            f.SlideInfo.SlidePointer(classPtr.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64,
		IsSwiftLegacy:         (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_LEGACY == 1),
		IsSwiftStable:         (classPtr.DataVMAddrAndFastFlags&objc.FAST_IS_SWIFT_STABLE == 1),
		ReadOnlyData:          info,
	}, nil
}

func (f *File) GetObjCClassProtocolsAddrs(vmaddr uint64) ([]uint64, error) {
	var addrs []uint64

	if vmaddr == 0 {
		return nil, nil
	}

	uuid, off, err := f.GetOffset(vmaddr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}
	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(off), io.SeekStart)

	var classPtr objc.SwiftClassMetadata64
	if err := binary.Read(sr, f.ByteOrder, &classPtr); err != nil {
		return nil, fmt.Errorf("failed to read swift_class_metadata_t: %v", err)
	}

	uuid, off, err = f.GetOffset(f.SlideInfo.SlidePointer(classPtr.DataVMAddrAndFastFlags) & objc.FAST_DATA_MASK64)
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}
	sr = io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(off), io.SeekStart)

	var info objc.ClassRO64
	if err := binary.Read(sr, f.ByteOrder, &info); err != nil {
		return nil, fmt.Errorf("failed to read class_ro_t: %v", err)
	}

	if info.BaseProtocolsVMAddr == 0 {
		return nil, nil
	}

	off, err = f.GetOffsetForUUID(uuid, f.SlideInfo.SlidePointer(info.BaseProtocolsVMAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to convert vmaddr: %v", err)
	}

	sr.Seek(int64(off), io.SeekStart)

	var protList objc.ProtocolList
	if err := binary.Read(sr, f.ByteOrder, &protList.Count); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t count: %v", err)
	}

	protList.Protocols = make([]uint64, protList.Count)
	if err := binary.Read(sr, f.ByteOrder, &protList.Protocols); err != nil {
		return nil, fmt.Errorf("failed to read protocol_list_t prots: %v", err)
	}

	for _, prot := range protList.Protocols {
		addrs = append(addrs, f.SlideInfo.SlidePointer(prot))
	}

	return addrs, nil
}

func (f *File) GetAllObjCStubs() error {
	return f.GetObjCStubsForImage()
}

func (f *File) GetObjCStubsForImage(imageNames ...string) error {
	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			return fmt.Errorf("failed get image %s as MachO: %v", image.Name, err)
		}

		image.ObjC.Stubs, err = m.GetObjCStubs(func(addr uint64, data []byte) (map[uint64]*objc.Stub, error) {
			stubs := make(map[uint64]*objc.Stub)
			addr2sel, err := disass.ParseStubsASM(data, addr, func(u uint64) (uint64, error) {
				ptr, err := f.ReadPointerAtAddress(u)
				if err != nil {
					return 0, err
				}
				return f.SlideInfo.SlidePointer(ptr), nil
			})
			if err != nil {
				return nil, err
			}
			for addr, sel := range addr2sel {
				if f.AddressToSymbol[sel] != "_objc_msgSend" {
					stubs[addr] = &objc.Stub{
						Name:        f.AddressToSymbol[sel],
						SelectorRef: sel,
					}
				}
			}
			return stubs, nil
		})
		if err != nil {
			return err
		}

		for addr, stub := range image.ObjC.Stubs {
			if len(stub.Name) > 0 {
				f.AddressToSymbol[addr] = fmt.Sprintf("__objc_stub_%s", stub.Name)
			}
		}
	}

	return nil
}

// ParseAllObjc parses all the ObjC data in the cache and loads it into the symbol table
func (f *File) ParseAllObjc() error {
	if _, err := f.GetAllObjCClasses(false); err != nil {
		return fmt.Errorf("failed to parse objc classes: %v", err)
	}
	if err := f.GetAllObjcMethods(); err != nil { // TODO: should I put this back in? The same info is in the symbols
		return fmt.Errorf("failed to parse objc methods: %v", err)
	}
	if _, err := f.GetAllObjCSelectors(false); err != nil {
		return fmt.Errorf("failed to parse objc selectors: %v", err)
	}
	if _, err := f.GetAllObjCProtocols(false); err != nil {
		return fmt.Errorf("failed to parse objc protocols: %v", err)
	}
	if err := f.GetAllObjCStubs(); err != nil {
		return fmt.Errorf("failed to parse objc stubs: %v", err)
	}
	return nil
}

func (f *File) ParseObjcForImage(imageNames ...string) error {

	var images []*CacheImage

	if len(imageNames) > 0 && len(imageNames[0]) > 0 {
		for _, imageName := range imageNames {
			image, err := f.Image(imageName)
			if err != nil {
				return err
			}
			images = append(images, image)
		}
	} else {
		images = f.Images
	}

	for _, image := range images {
		if err := f.CFStringsForImage(image.Name); err != nil {
			return fmt.Errorf("failed to parse objc cfstrings for image %s: %v", filepath.Base(image.Name), err)
		}
		// TODO: add objc methods in the -[Class sel:] form
		if err := f.MethodsForImage(image.Name); err != nil {
			if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return fmt.Errorf("failed to parse objc methods for image %s: %v", filepath.Base(image.Name), err)
			}
		}
		if strings.Contains(image.Name, "libobjc.A.dylib") {
			if _, err := f.GetAllObjCSelectors(false); err != nil {
				return fmt.Errorf("failed to parse objc all selectors: %v", err)
			}
		} else {
			if err := f.SelectorsForImage(image.Name); err != nil {
				return fmt.Errorf("failed to parse objc selectors for image %s: %v", filepath.Base(image.Name), err)
			}
		}
		if err := f.ClassesForImage(image.Name); err != nil {
			return fmt.Errorf("failed to parse objc classes for image %s: %v", filepath.Base(image.Name), err)
		}
		if err := f.ProtocolsForImage(image.Name); err != nil {
			return fmt.Errorf("failed to parse objc protocols for image %s: %v", filepath.Base(image.Name), err)
		}
	}

	return nil
}
