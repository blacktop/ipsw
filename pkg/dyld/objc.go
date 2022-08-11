package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/pkg/errors"
)

type optFlags uint32

const (
	isProduction              optFlags = (1 << 0)      // never set in development cache
	noMissingWeakSuperclasses optFlags = (1 << 1)      // never set in development cache
	mask                      uint64   = (1 << 40) - 1 // 40bit mask
)

// objcInfo is the dyld_shared_cache dylib objc object
type objcInfo struct {
	Methods   []objc.Method
	ClassRefs map[uint64]*objc.Class
	SuperRefs map[uint64]*objc.Class
	SelRefs   map[uint64]*objc.Selector
	ProtoRefs map[uint64]*objc.Protocol
	CFStrings []objc.CFString
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

/*
 * objc_opt_t - dyld/include/objc-shared-cache.h
 *
 *  Top-level optimization structure.
 */

// Optimization structure
type Optimization struct {
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
	RelativeMethodSelectorBaseAddressCacheOffset uint64
}

func (o Optimization) isPointerAligned() bool {
	return (binary.Size(o) % 8) == 0
}

func (o Optimization) GetClassOffset() int32 {
	if o.Version >= 16 {
		return o.LargeSharedCachesClassOffset
	} else {
		return o.UnusedClassOptOffset
	}
}

func (o Optimization) GetProtocolOffset() int32 {
	if o.Version >= 16 {
		return o.LargeSharedCachesProtocolOffset
	} else if o.Version >= 15 {
		return o.UnusedProtocolOpt2Offset
	} else {
		return o.UnusedProtocolOptOffset
	}
}

func (o Optimization) String() string {
	return fmt.Sprintf(
		"Version                                      = %d\n"+
			"Flags                                        = %d\n"+
			"SelectorOptOffset                            = %#x\n"+
			"HeaderOptRoOffset                            = %#x\n"+
			"ClassOptOffset                               = %#x\n"+
			"ProtocolOptOffset                            = %#x\n"+
			"HeaderOptRwOffset                            = %#x\n"+
			"ProtocolOpt2Offset                           = %#x\n"+
			"LargeSharedCachesClassOffset                 = %#x\n"+
			"LargeSharedCachesProtocolOffset              = %#x\n"+
			"RelativeMethodSelectorBaseAddressCacheOffset = %#x\n"+
			"isPointerAligned                             = %t\n",
		o.Version,
		o.Flags,
		o.SelectorOptOffset,
		o.HeaderOptRoOffset,
		o.UnusedClassOptOffset,
		o.UnusedProtocolOptOffset,
		o.HeaderoptRwOffset,
		o.UnusedProtocolOpt2Offset,
		o.LargeSharedCachesClassOffset,
		o.LargeSharedCachesProtocolOffset,
		o.RelativeMethodSelectorBaseAddressCacheOffset,
		o.isPointerAligned())
}

func (f *File) getLibObjC() (*macho.File, error) {
	image, err := f.Image("/usr/lib/libobjc.A.dylib")
	if err != nil {
		return nil, err
	}

	m, err := image.GetPartialMacho()
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (f *File) getOptimizations() (*macho.Section, *Optimization, error) {

	libObjC, err := f.getLibObjC()
	if err != nil {
		return nil, nil, err
	}

	if s := libObjC.Section("__TEXT", "__objc_opt_ro"); s != nil {
		dat, err := s.Data()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read __TEXT.__objc_opt_ro data")
		}
		opt := Optimization{}
		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &opt); err != nil {
			return nil, nil, err
		}
		if opt.Version > 16 {
			return nil, nil, fmt.Errorf("objc optimization version should be 16 or less, but found %d", opt.Version)
		}
		// log.Debugf("Objective-C Optimizations:\n%s", opt)
		return s, &opt, nil
	}

	return nil, nil, fmt.Errorf("unable to find section __TEXT.__objc_opt_ro in /usr/lib/libobjc.A.dylib")
}

func (f *File) getSelectorStringHash() (*StringHash, error) {

	sec, opt, err := f.getOptimizations()
	if err != nil {
		return nil, err
	}

	if opt.SelectorOptOffset == 0 {
		return nil, fmt.Errorf("selopt_offset is 0")
	}

	shash := StringHash{FileOffset: int64(sec.Offset) + int64(opt.SelectorOptOffset), opt: opt}

	if err = shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
		return nil, err
	}

	return &shash, nil
}

// func (f *File) getHeaderRoStringHash() (*StringHash, error) {

// 	sec, opt, err := f.getOptimizations()
// 	if err != nil {
// 		return nil, err
// 	}

// 	if opt.HeaderOptRoOffset == 0 {
// 		return nil, fmt.Errorf("headeropt_ro_offset is 0")
// 	}

// 	shash := StringHash{FileOffset: int64(sec.Offset) + int64(opt.HeaderOptRoOffset)}

// 	if err = shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
// 		return nil, err
// 	}

// 	return &shash, nil
// }

func (f *File) getClassStringHash() (*StringHash, error) {

	sec, opt, err := f.getOptimizations()
	if err != nil {
		return nil, err
	}

	if opt.GetClassOffset() == 0 {
		return nil, fmt.Errorf("clsopt_offset is 0")
	}

	shash := StringHash{FileOffset: int64(sec.Offset) + int64(opt.GetClassOffset()), opt: opt}

	if err = shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
		return nil, err
	}

	return &shash, nil
}

func (f *File) getProtocolStringHash() (*StringHash, error) {

	sec, opt, err := f.getOptimizations()
	if err != nil {
		return nil, err
	}

	if opt.GetProtocolOffset() == 0 {
		return nil, fmt.Errorf("protocolopt_offset is 0")
	}

	shash := StringHash{FileOffset: int64(sec.Offset) + int64(opt.GetProtocolOffset()), opt: opt}

	if err = shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
		return nil, err
	}

	return &shash, nil
}

// func (f *File) getHeaderRwStringHash() (*StringHash, error) {

// 	sec, opt, err := f.getOptimizations()
// 	if err != nil {
// 		return nil, err
// 	}

// 	if opt.HeaderOptRwOffset == 0 {
// 		return nil, fmt.Errorf("headeropt_rw_offset is 0")
// 	}

// 	shash := StringHash{FileOffset: int64(sec.Offset) + int64(opt.HeaderOptRwOffset)}

// 	if err = shash.Read(io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)); err != nil {
// 		return nil, err
// 	}

// 	return &shash, nil
// }

func (f *File) dumpOffsets(offsets []int32, fileOffset int64) {
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	sr := io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)
	for _, ptr := range offsets {
		if ptr != 0 {
			sr.Seek(int64(int32(fileOffset)+ptr), io.SeekStart)
			s, err := bufio.NewReader(sr).ReadString('\x00')
			if err != nil {
				log.Errorf("failed to read selector name at %#x: %v", int32(fileOffset)+ptr, err)
			}
			addr, _ := f.GetVMAddressForUUID(f.UUID, uint64(int32(fileOffset)+ptr))
			fmt.Printf("    0x%x: %s\n", addr, strings.Trim(s, "\x00"))
		}

	}
}

type objc_headeropt_ro_t struct {
	Count   uint32
	Entsize uint32
	Headers []header_info
}
type header_info struct {
	// Note, this is no longer a pointer, but instead an offset to a pointer
	// from this location.
	MhdrOffset int64

	// Note, this is no longer a pointer, but instead an offset to a pointer
	// from this location.
	InfoOffset int64

	// Offset from this location to the non-lazy class list
	NlclslistOffset int64
	NlclslistCount  uint64

	// Offset from this location to the non-lazy category list
	NlcatlistOffset int64
	NlcatlistCount  uint64

	// Offset from this location to the category list
	CatlistOffset int64
	CatlistCount  uint64

	// Offset from this location to the category list 2
	Catlist2Offset int64
	Catlist2Count  uint64
}

type objc_headeropt_rw_t struct {
	Count   uint32
	Entsize uint32
	Headers []header_info_rw
}
type header_info_rw struct {
	Ptr uint64
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

func (f *File) offsetsToMap(offsets []int32, fileOffset int64) map[string]uint64 {
	objcMap := make(map[string]uint64)

	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	sr := io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)
	for _, ptr := range offsets {
		if ptr != 0 {
			sr.Seek(int64(int32(fileOffset)+ptr), io.SeekStart)
			s, err := bufio.NewReader(sr).ReadString('\x00')
			if err != nil {
				log.Errorf("failed to read selector name at %#x: %v", int32(fileOffset)+ptr, err)
			}
			addr, _ := f.GetVMAddressForUUID(f.UUID, uint64(int32(fileOffset)+ptr))
			objcMap[strings.Trim(s, "\x00")] = addr

			f.AddressToSymbol[addr] = strings.Trim(s, "\x00")
		}

	}
	return objcMap
}

// GetAllSelectors is a dumb brute force way to get all the ObjC selector/class etc address
// by just dumping all the strings in the __OBJC_RO segment
// returns: map[sym]addr
func (f *File) GetAllObjCSelectors(print bool) (map[string]uint64, error) {

	shash, err := f.getSelectorStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read selector objc_stringhash_t: %v", err)
	}

	if print {
		f.dumpOffsets(shash.Offsets, shash.FileOffset)
	}

	return f.offsetsToMap(shash.Offsets, shash.FileOffset), nil
}

// GetSelectorAddress returns a selector name's address
func (f *File) GetSelectorAddress(selector string) (uint64, error) {
	shash, err := f.getSelectorStringHash()
	if err != nil {
		return 0, fmt.Errorf("failed get selector objc_stringhash_t for %s: %v", selector, err)
	}

	selIndex, err := shash.getIndex(selector)
	if err != nil {
		return 0, fmt.Errorf("failed get selector address for %s", selector)
	}

	ptr, err := f.GetVMAddressForUUID(f.UUID, uint64(shash.FileOffset+int64(shash.Offsets[selIndex])))
	if err != nil {
		return 0, fmt.Errorf("failed get selector address for %s: %w", selector, err)
	}

	return ptr, nil
}

// GetAllClasses dumps the classes from the optimized string hash
func (f *File) GetAllObjCClasses(print bool) (map[string]uint64, error) {
	shash, err := f.getClassStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read class objc_stringhash_t")
	}

	if print {
		f.dumpOffsets(shash.Offsets, shash.FileOffset)
	}

	return f.offsetsToMap(shash.Offsets, shash.FileOffset), nil
}

// GetClassAddress returns a class address
func (f *File) GetClassAddress(class string) (uint64, error) {
	shash, err := f.getClassStringHash()
	if err != nil {
		return 0, fmt.Errorf("failed read selector objc_stringhash_t: %v", err)
	}

	selIndex, err := shash.getIndex(class)
	if err != nil {
		return 0, fmt.Errorf("failed get class address for %s: %v", class, err)
	}

	ptr, err := f.GetVMAddressForUUID(f.UUID, uint64(shash.FileOffset+int64(shash.Offsets[selIndex])))
	if err != nil {
		return 0, fmt.Errorf("failed get class address for %s: %w", class, err)
	}

	return ptr, nil
}

// GetAllProtocols dumps the protols from the optimized string hash
func (f *File) GetAllObjCProtocols(print bool) (map[string]uint64, error) {
	shash, err := f.getProtocolStringHash()
	if err != nil {
		return nil, fmt.Errorf("failed read selector objc_stringhash_t: %v", err)
	}

	if print {
		f.dumpOffsets(shash.Offsets, shash.FileOffset)
	}

	return f.offsetsToMap(shash.Offsets, shash.FileOffset), nil
}

// GetProtocolAddress returns a protocol address
func (f *File) GetProtocolAddress(protocol string) (uint64, error) {
	shash, err := f.getProtocolStringHash()
	if err != nil {
		return 0, fmt.Errorf("failed read selector objc_stringhash_t: %v", err)
	}

	selIndex, err := shash.getIndex(protocol)
	if err != nil {
		return 0, fmt.Errorf("failed get protocol address for %s: %v", protocol, err)
	}

	ptr, err := f.GetVMAddressForUUID(f.UUID, uint64(shash.FileOffset+int64(shash.Offsets[selIndex])))
	if err != nil {
		return 0, fmt.Errorf("failed get protocol address for %s: %w", protocol, err)
	}

	return ptr, nil
}

// // GetAllHeaderRO dumps the header_ro from the optimized string hash
// func (f *File) GetAllHeaderRO(print bool) (map[string]uint64, error) {

// 	shash, err := f.getHeaderRoStringHash()
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "failed read header_ro objc_stringhash_t")
// 	}

// 	if print {
// 		f.dumpHeaderROOffsets(shash.Offsets, shash.FileOffset)
// 	}

// 	return f.offsetsToMap(shash.Offsets, shash.FileOffset), nil
// }

// // GetAllHeaderRW dumps the header_ro from the optimized string hash
// func (f *File) GetAllHeaderRW(print bool) (map[string]uint64, error) {

// 	shash, err := f.getHeaderRwStringHash()
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "failed read header_rw objc_stringhash_t")
// 	}

// 	if print {
// 		f.dumpHeaderROOffsets(shash.Offsets, shash.FileOffset)
// 	}

// 	return f.offsetsToMap(shash.Offsets, shash.FileOffset), nil
// }

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

		image.ObjC.Methods, err = m.GetObjCMethodList()
		if err != nil {
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
	var optOffsets objc.OptOffsets
	// var optOffsets objc.OptOffsets2
	var selectorStringVMAddrStart uint64
	var selectorStringVMAddrEnd uint64

	_, opt, err := f.getOptimizations()
	if err != nil {
		return err
	}

	if f.IsDyld4 || opt.Version >= 16 {
		return fmt.Errorf("imp-cache dumping is NOT supported on macOS12/iOS15+ (yet)")
	}

	libObjC, err := f.getLibObjC()
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

		if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, &optOffsets); err != nil {
			return err
		}

		selectorStringVMAddrStart = f.SlideInfo.SlidePointer(optOffsets.MethodNameStart)
		selectorStringVMAddrEnd = f.SlideInfo.SlidePointer(optOffsets.MethodNameEnd)
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

				var impCache objc.ImpCache
				if err := binary.Read(sr, f.ByteOrder, &impCache.PreoptCacheT); err != nil {
					return fmt.Errorf("failed to read preopt_cache_t: %v", err)
				}

				impCache.Entries = make([]objc.PreoptCacheEntryT, impCache.Capacity())
				if err := binary.Read(sr, f.ByteOrder, &impCache.Entries); err != nil {
					return fmt.Errorf("failed to read []preopt_cache_entry_t: %v", err)
				}

				fmt.Printf("%s: (%s, buckets: %d)\n", c.Name, impCache.PreoptCacheT, impCache.Capacity())

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
				f.AddressToSymbol[cfstr.Address] = cfstr.Name
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

// ParseAllObjc parses all the ObjC data in the cache and loads it into the symbol table
func (f *File) ParseAllObjc() error {
	if _, err := f.GetAllObjCClasses(false); err != nil {
		return err
	}
	if err := f.GetAllObjcMethods(); err != nil {
		return err
	}
	if _, err := f.GetAllObjCSelectors(false); err != nil {
		return err
	}
	if _, err := f.GetAllObjCProtocols(false); err != nil {
		return err
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
			return fmt.Errorf("failed to parse objc cfstrings for image %s: %v", image.Name, err)
		}
		// TODO: add objc methods in the -[Class sel:] form
		if err := f.MethodsForImage(image.Name); err != nil {
			return fmt.Errorf("failed to parse objc methods for image %s: %v", image.Name, err)
		}
		if strings.Contains(image.Name, "libobjc.A.dylib") {
			if _, err := f.GetAllObjCSelectors(false); err != nil {
				return fmt.Errorf("failed to parse objc all selectors: %v", err)
			}
		} else {
			if err := f.SelectorsForImage(image.Name); err != nil {
				return fmt.Errorf("failed to parse objc selectors for image %s: %v", image.Name, err)
			}
		}
		if err := f.ClassesForImage(image.Name); err != nil {
			return fmt.Errorf("failed to parse objc classes for image %s: %v", image.Name, err)
		}
		if err := f.ProtocolsForImage(image.Name); err != nil {
			return fmt.Errorf("failed to parse objc protocols for image %s: %v", image.Name, err)
		}
	}

	return nil
}

/*
 * objc_stringhash_t - dyld/include/objc-shared-cache.h
 *
 * Precomputed perfect hash table of strings.
 * Base class for precomputed selector table and class table.
 */

type stringHash struct {
	Capacity uint32
	Occupied uint32
	Shift    uint32
	Mask     uint32
	_        uint32 // was zero
	_        uint32 // alignment pad
	Salt     uint64
	Scramble [256]uint32
}

type stringHashV16 struct {
	Version  uint32
	Capacity uint32
	Occupied uint32
	Shift    uint32
	Mask     uint32
	_        uint32 // was zero
	Salt     uint64
	Scramble [256]uint32
}

// StringHash struct
type StringHash struct {
	FileOffset       int64
	shash            interface{}
	Tab              []byte   /* tab[mask+1] (always power-of-2) */
	CheckBytes       []byte   /* check byte for each string */
	Offsets          []int32  /* offsets from &capacity to cstrings */
	ClassOffsets     []uint64 /* offsets from &capacity to cstrings */
	DuplicateCount   uint32
	DuplicateOffsets []uint64

	opt *Optimization
}

// Capacity returns the Capacity
func (s *StringHash) Capacity() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Capacity
	case stringHashV16:
		return h.Capacity
	}
	return 0
}

// Occupied returns the Occupied
func (s *StringHash) Occupied() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Occupied
	case stringHashV16:
		return h.Occupied
	}
	return 0
}

// Shift returns the Shift
func (s *StringHash) Shift() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Shift
	case stringHashV16:
		return h.Shift
	}
	return 0
}

// Mask returns the Mask
func (s *StringHash) Mask() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Mask
	case stringHashV16:
		return h.Mask
	}
	return 0
}

// Salt returns the Salt
func (s *StringHash) Salt() uint64 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Salt
	case stringHashV16:
		return h.Salt
	}
	return 0
}

// Scramble returns the Scramble
func (s *StringHash) Scramble() [256]uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Scramble
	case stringHashV16:
		return h.Scramble
	}
	return [256]uint32{0}
}

func (s *StringHash) Read(r *io.SectionReader) error {

	r.Seek(int64(s.FileOffset), io.SeekStart)

	if s.opt.Version >= 16 {
		var sh stringHashV16
		if err := binary.Read(r, binary.LittleEndian, &sh); err != nil {
			return fmt.Errorf("failed to read %T: %v", sh, err)
		}
		s.shash = sh
	} else {
		var sh stringHash
		if err := binary.Read(r, binary.LittleEndian, &sh); err != nil {
			return fmt.Errorf("failed to read %T: %v", sh, err)
		}
		s.shash = sh
	}

	// log.Debugf("Objective-C StringHash:\n%s", s)

	s.Tab = make([]byte, s.Mask()+1)
	if err := binary.Read(r, binary.LittleEndian, &s.Tab); err != nil {
		return err
	}

	s.CheckBytes = make([]byte, s.Capacity())
	if err := binary.Read(r, binary.LittleEndian, &s.CheckBytes); err != nil {
		return err
	}

	s.Offsets = make([]int32, s.Capacity())
	if err := binary.Read(r, binary.LittleEndian, &s.Offsets); err != nil {
		return err
	}

	// s.ClassOffsets = make([]uint64, s.Capacity())
	// if err := binary.Read(r, binary.LittleEndian, &s.Offsets); err != nil {
	// 	return err
	// }

	// if err := binary.Read(r, binary.LittleEndian, &s.DuplicateCount); err != nil {
	// 	return err
	// }

	// s.DuplicateOffsets = make([]uint64, s.DuplicateCount)
	// if err := binary.Read(r, binary.LittleEndian, &s.DuplicateOffsets); err != nil {
	// 	return err
	// }

	return nil
}

func (s StringHash) String() string {
	return fmt.Sprintf(
		"FileOffset = %X\n"+
			"Capacity   = %X\n"+
			"Occupied   = %X\n"+
			"Shift      = %X\n"+
			"Mask       = %X\n"+
			"Salt       = %016X\n",
		s.FileOffset,
		s.Capacity(),
		s.Occupied(),
		s.Shift(),
		s.Mask(),
		s.Salt())
}

/*
--------------------------------------------------------------------
mix -- mix 3 64-bit values reversibly.
mix() takes 48 machine instructions, but only 24 cycles on a superscalar

	machine (like Intel's new MMX architecture).  It requires 4 64-bit
	registers for 4::2 parallelism.

All 1-bit deltas, all 2-bit deltas, all deltas composed of top bits of

	(a,b,c), and all deltas of bottom bits were tested.  All deltas were
	tested both on random keys and on keys that were nearly all zero.
	These deltas all cause every bit of c to change between 1/3 and 2/3
	of the time (well, only 113/400 to 287/400 of the time for some
	2-bit delta).  These deltas all cause at least 80 bits to change
	among (a,b,c) when the mix is run either forward or backward (yes it
	is reversible).

This implies that a hash using mix64 has no funnels.  There may be

	characteristics with 3-bit deltas or bigger, I didn't test for
	those.

--------------------------------------------------------------------
*/
func mix64(a, b, c *uint64) {
	*a = (*a - *b - *c) ^ (*c >> 43)
	*b = (*b - *c - *a) ^ (*a << 9)
	*c = (*c - *a - *b) ^ (*b >> 8)
	*a = (*a - *b - *c) ^ (*c >> 38)
	*b = (*b - *c - *a) ^ (*a << 23)
	*c = (*c - *a - *b) ^ (*b >> 5)
	*a = (*a - *b - *c) ^ (*c >> 35)
	*b = (*b - *c - *a) ^ (*a << 49)
	*c = (*c - *a - *b) ^ (*b >> 11)
	*a = (*a - *b - *c) ^ (*c >> 12)
	*b = (*b - *c - *a) ^ (*a << 18)
	*c = (*c - *a - *b) ^ (*b >> 22)
}

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 64-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 8-byte value
Returns a 64-bit value.  Every bit of the key affects every bit of
the return value.  No funnels.  Every 1-bit and 2-bit delta achieves
avalanche.  About 41+5len instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 64 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, Jan 4 1997.  bob_jenkins@burtleburtle.net.  You may
use this code any way you wish, private, educational, or commercial,
but I would appreciate if you give me credit.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^64
is acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

func lookup8(k []byte, level uint64) uint64 {
	// uint8_t *k;        /* the key */
	// uint64_t  length;   /* the length of the key */
	// uint64_t  level;    /* the previous hash, or an arbitrary value */
	var a, b, c uint64
	var length int

	/* Set up the internal state */
	length = len(k)
	a = level
	b = level              /* the previous hash value */
	c = 0x9e3779b97f4a7c13 /* the golden ratio; an arbitrary value */
	p := 0
	/*---------------------------------------- handle most of the key */
	for length >= 24 {
		a += uint64(k[p+0]) + (uint64(k[p+1]) << 8) + (uint64(k[p+2]) << 16) + (uint64(k[p+3]) << 24) + (uint64(k[p+4]) << 32) + (uint64(k[p+5]) << 40) + (uint64(k[p+6]) << 48) + (uint64(k[p+7]) << 56)
		b += uint64(k[p+8]) + (uint64(k[p+9]) << 8) + (uint64(k[p+10]) << 16) + (uint64(k[p+11]) << 24) + (uint64(k[p+12]) << 32) + (uint64(k[p+13]) << 40) + (uint64(k[p+14]) << 48) + (uint64(k[p+15]) << 56)
		c += uint64(k[p+16]) + (uint64(k[p+17]) << 8) + (uint64(k[p+18]) << 16) + (uint64(k[p+19]) << 24) + (uint64(k[p+20]) << 32) + (uint64(k[p+21]) << 40) + (uint64(k[p+22]) << 48) + (uint64(k[p+23]) << 56)
		mix64(&a, &b, &c)
		p += 24
		length -= 24
	}

	/*------------------------------------- handle the last 23 bytes */
	c += uint64(len(k))
	switch length { /* all the case statements fall through */
	case 23:
		c += (uint64(k[p+22]) << 56)
		fallthrough
	case 22:
		c += (uint64(k[p+21]) << 48)
		fallthrough
	case 21:
		c += (uint64(k[p+20]) << 40)
		fallthrough
	case 20:
		c += (uint64(k[p+19]) << 32)
		fallthrough
	case 19:
		c += (uint64(k[p+18]) << 24)
		fallthrough
	case 18:
		c += (uint64(k[p+17]) << 16)
		fallthrough
	case 17:
		c += (uint64(k[p+16]) << 8)
		fallthrough
	/* the first byte of c is reserved for the length */
	case 16:
		b += (uint64(k[p+15]) << 56)
		fallthrough
	case 15:
		b += (uint64(k[p+14]) << 48)
		fallthrough
	case 14:
		b += (uint64(k[p+13]) << 40)
		fallthrough
	case 13:
		b += (uint64(k[p+12]) << 32)
		fallthrough
	case 12:
		b += (uint64(k[p+11]) << 24)
		fallthrough
	case 11:
		b += (uint64(k[p+10]) << 16)
		fallthrough
	case 10:
		b += (uint64(k[p+9]) << 8)
		fallthrough
	case 9:
		b += (uint64(k[p+8]))
		fallthrough
	case 8:
		a += (uint64(k[p+7]) << 56)
		fallthrough
	case 7:
		a += (uint64(k[p+6]) << 48)
		fallthrough
	case 6:
		a += (uint64(k[p+5]) << 40)
		fallthrough
	case 5:
		a += (uint64(k[p+4]) << 32)
		fallthrough
	case 4:
		a += (uint64(k[p+3]) << 24)
		fallthrough
	case 3:
		a += (uint64(k[p+2]) << 16)
		fallthrough
	case 2:
		a += (uint64(k[p+1]) << 8)
		fallthrough
	case 1:
		a += uint64(k[p+0])
		/* case 0: nothing left to add */
	}
	mix64(&a, &b, &c)
	/*-------------------------------------------- report the result */
	return c
}

func (s StringHash) hash(key []byte) uint32 {
	val := lookup8(key, s.Salt())
	index := (val >> uint64(s.Shift())) ^ uint64(s.Scramble()[s.Tab[(val&uint64(s.Mask()))]])
	return uint32(index)
}

// The check bytes are used to reject strings that aren't in the table
// without paging in the table's cstring data. This checkbyte calculation
// catches 4785/4815 rejects when launching Safari; a perfect checkbyte
// would catch 4796/4815.
func checkbyte(key []byte) uint8 {
	return ((key[0] & 0x7) << 5) | (uint8(len(key)) & 0x1f)
}

func (s StringHash) getIndex(keyStr string) (uint32, error) {
	key := []byte(keyStr)

	h := s.hash(key)

	// Use check byte to reject without paging in the table's cstrings
	hCheck := s.CheckBytes[h]
	keyCheck := checkbyte(key)
	if hCheck != keyCheck {
		return 0, fmt.Errorf("INDEX_NOT_FOUND")
	}

	offset := s.Offsets[h]
	if offset == 0 {
		return 0, fmt.Errorf("INDEX_NOT_FOUND")
	}
	// result = (const char *)this + offset
	// TODO: fix me
	// result := "FIX ME"
	// if result != string(key) {
	// 	return 0, fmt.Errorf("INDEX_NOT_FOUND")
	// }

	return h, nil
}
