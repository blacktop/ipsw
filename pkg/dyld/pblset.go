package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

const (
	LoaderMagic            = 0x6c347964 // "l4yd"
	PrebuiltLoaderSetMagic = 0x73703464 // "sp4d"
	NoUnzipperedTwin       = 0xFFFF
)

type LoaderRef uint16

// index       : 15,   // index into PrebuiltLoaderSet
// app         :  1;   // app vs dyld cache PrebuiltLoaderSet

// Index index into PrebuiltLoaderSet
func (l LoaderRef) Index() uint16 {
	return uint16(types.ExtractBits(uint64(l), 0, 15))
}

// IsApp app vs dyld cache PrebuiltLoaderSet
func (l LoaderRef) IsApp() bool {
	return types.ExtractBits(uint64(l), 15, 1) != 0
}
func (l LoaderRef) IsMissingWeakImage() bool {
	return (l.Index() == 0x7fff) && !l.IsApp()
}

type Loader struct {
	Magic uint32 // "l4yd"
	Info  uint16
	// isPrebuilt         :  1,  // PrebuiltLoader vs JustInTimeLoader
	// dylibInDyldCache   :  1,
	// hasObjC            :  1,
	// mayHavePlusLoad    :  1,
	// hasReadOnlyData    :  1,  // __DATA_CONST.  Don't use directly.  Use hasConstantSegmentsToProtect()
	// neverUnload        :  1,  // part of launch or has non-unloadable data (e.g. objc, tlv)
	// leaveMapped        :  1,  // RTLD_NODELETE
	// hasReadOnlyObjC    :  1,  // Has __DATA_CONST,__objc_selrefs section
	// pre2022Binary      :  1,
	// padding            :  6;
	Ref LoaderRef
}

func (l Loader) IsPrebuilt() bool {
	return types.ExtractBits(uint64(l.Info), 0, 1) != 0
}
func (l Loader) DylibInDyldCache() bool {
	return types.ExtractBits(uint64(l.Info), 1, 1) != 0
}
func (l Loader) HasObjC() bool {
	return types.ExtractBits(uint64(l.Info), 2, 1) != 0
}
func (l Loader) MayHavePlusLoad() bool {
	return types.ExtractBits(uint64(l.Info), 3, 1) != 0
}
func (l Loader) HasReadOnlyData() bool {
	return types.ExtractBits(uint64(l.Info), 4, 1) != 0
}
func (l Loader) NeverUnload() bool {
	return types.ExtractBits(uint64(l.Info), 5, 1) != 0
}
func (l Loader) LeaveMapped() bool {
	return types.ExtractBits(uint64(l.Info), 6, 1) != 0
}
func (l Loader) HasReadOnlyObjC() bool {
	return types.ExtractBits(uint64(l.Info), 7, 1) != 0
}
func (l Loader) Pre2022Binary() bool {
	return types.ExtractBits(uint64(l.Info), 8, 1) != 0
}

func (l Loader) String() string {
	return fmt.Sprintf("isPrebuilt: %t, dylibInDyldCache: %t, hasObjC: %t, mayHavePlusLoad: %t, hasReadOnlyData: %t, neverUnload: %t, leaveMapped: %t, hasReadOnlyObjC: %t, pre2022Binary: %t, index: %d, isApp: %t",
		l.IsPrebuilt(),
		l.DylibInDyldCache(),
		l.HasObjC(),
		l.MayHavePlusLoad(),
		l.HasReadOnlyData(),
		l.NeverUnload(),
		l.LeaveMapped(),
		l.HasReadOnlyObjC(),
		l.Pre2022Binary(),
		l.Ref.Index(),
		l.Ref.IsApp())
}

type DependentKind uint8

const (
	KindNormal   DependentKind = 0
	KindWeakLink DependentKind = 1
	KindReexport DependentKind = 2
	KindUpward   DependentKind = 3
)

func (k DependentKind) String() string {
	switch k {
	case KindNormal:
		return ""
	case KindWeakLink:
		return "weak link"
	case KindReexport:
		return "reexport"
	case KindUpward:
		return "upward"
	default:
		return "unknown"
	}
}

// Region stored in PrebuiltLoaders and generated on the fly by JustInTimeLoaders, passed to mapSegments()
type Region struct {
	Info uint64
	// vmOffset     : 59,
	// perms        :  3,
	// isZeroFill   :  1,
	// readOnlyData :  1;
	FileOffset uint32
	FileSize   uint32 // mach-o files are limited to 4GB, but zero fill data can be very large
}

func (r Region) VMOffset() uint64 {
	return types.ExtractBits(r.Info, 0, 59)
}

func (r Region) Perms() types.VmProtection {
	return types.VmProtection(types.ExtractBits(r.Info, 59, 3))
}

func (r Region) IsZeroFill() bool {
	return types.ExtractBits(r.Info, 62, 1) != 0
}

func (r Region) ReadOnlyData() bool {
	return types.ExtractBits(r.Info, 63, 1) != 0
}

func (r Region) String() string {
	return fmt.Sprintf("file_off: %#x, file_siz: %#x, vm_off: %#x, perms: %s, is_zerofill: %t, ro_data: %t",
		r.FileOffset,
		r.FileSize,
		r.VMOffset(),
		r.Perms(),
		r.IsZeroFill(),
		r.ReadOnlyData())
}

type RSKind uint32

const (
	RSKindRebase RSKind = iota
	RSKindBindToImage
	RSKindBindAbsolute
)

func (k RSKind) String() string {
	switch k {
	case RSKindRebase:
		return "rebase"
	case RSKindBindToImage:
		return "bind to image"
	case RSKindBindAbsolute:
		return "bind absolute"
	default:
		return "unknown"
	}
}

type ResolvedSymbol struct {
	TargetLoader        *Loader
	TargetSymbolName    string
	TargetRuntimeOffset uint64
	Kind                RSKind
	IsCode              bool
	IsWeakDef           bool
	IsMissingFlatLazy   bool
}

type BindTarget struct {
	Loader        *Loader
	RuntimeOffset uint64
}

// FileValidation stored in PrebuiltLoader when it references a file on disk
type FileValidation struct {
	SliceOffset     uint64
	Inode           uint64
	Mtime           uint64
	CDHash          [20]byte // to validate file has not changed since PrebuiltLoader was built
	UUID            types.UUID
	CheckInodeMtime bool
	CheckCDHash     bool
}

type CodeSignatureInFile struct {
	FileOffset uint32
	Size       uint32
}

func deserializeAbsoluteValue(value uint64) uint64 {
	// sign extend
	if (value & 0x4000000000000000) != 0 {
		value |= 0x8000000000000000
	}
	return value
}

type BindTargetRef uint64

func (b BindTargetRef) LoaderRef() LoaderRef {
	return LoaderRef(types.ExtractBits(uint64(b), 0, 16))
}
func (b BindTargetRef) high8() uint64 {
	return types.ExtractBits(uint64(b), 16, 8)
}
func (b BindTargetRef) low39() uint64 {
	return types.ExtractBits(uint64(b), 24, 39) // signed
}
func (b BindTargetRef) AbsoluteValue() uint64 {
	return deserializeAbsoluteValue(uint64(types.ExtractBits(uint64(b), 0, 63)))
}
func (b BindTargetRef) Kind() uint8 {
	return uint8(types.ExtractBits(uint64(b), 63, 1))
}
func (b BindTargetRef) IsAbsolute() bool {
	return b.Kind() == 1
}
func (b BindTargetRef) Offset() uint64 {
	if b.IsAbsolute() {
		return b.AbsoluteValue()
	}
	signedOffset := b.low39()
	if (signedOffset & 0x0000004000000000) != 0 {
		signedOffset |= 0x00FFFF8000000000
	}
	return (b.high8() << 56) | signedOffset
}

type PrebuiltLoader struct {
	Loader
	PathOffset                     uint16
	DependentLoaderRefsArrayOffset uint16 // offset to array of LoaderRef
	DependentKindArrayOffset       uint16 // zero if all deps normal
	FixupsLoadCommandOffset        uint16

	AltPathOffset        uint16 // if install_name does not match real path
	FileValidationOffset uint16 // zero or offset to FileValidationInfo

	Info uint16
	// hasInitializers      :  1,
	// isOverridable        :  1,      // if in dyld cache, can roots override it
	// supportsCatalyst     :  1,      // if false, this cannot be used in catalyst process
	// isCatalystOverride   :  1,      // catalyst side of unzippered twin
	// regionsCount         : 12
	RegionsOffset uint16 // offset to Region array

	DepCount             uint16
	BindTargetRefsOffset uint16
	BindTargetRefsCount  uint32 // bind targets can be large, so it is last
	// After this point, all offsets in to the PrebuiltLoader need to be 32-bits as the bind targets can be large

	ObjcBinaryInfoOffset uint32 // zero or offset to ObjCBinaryInfo
	IndexOfTwin          uint16 // if in dyld cache and part of unzippered twin, then index of the other twin
	_                    uint16

	ExportsTrieLoaderOffset uint64
	ExportsTrieLoaderSize   uint32
	VmSize                  uint32

	CodeSignature CodeSignatureInFile

	PatchTableOffset uint32

	OverrideBindTargetRefsOffset uint32
	OverrideBindTargetRefsCount  uint32

	// followed by:
	//  path chars
	//  dep kind array
	//  file validation info
	//  segments
	//  bind targets
}

func (pl PrebuiltLoader) HasInitializers() bool {
	return types.ExtractBits(uint64(pl.Info), 0, 1) != 0
}
func (pl PrebuiltLoader) IsOverridable() bool {
	return types.ExtractBits(uint64(pl.Info), 1, 1) != 0
}
func (pl PrebuiltLoader) SupportsCatalyst() bool {
	return types.ExtractBits(uint64(pl.Info), 2, 1) != 0
}
func (pl PrebuiltLoader) IsCatalystOverride() bool {
	return types.ExtractBits(uint64(pl.Info), 3, 1) != 0
}
func (pl PrebuiltLoader) RegionsCount() uint16 {
	return uint16(types.ExtractBits(uint64(pl.Info), 4, 12))
}
func (pl PrebuiltLoader) GetInfo() string {
	return fmt.Sprintf("has_initializers: %t, overridable: %t, supports_catalyst: %t, catalyst_override: %t, regions_count: %d",
		pl.HasInitializers(),
		pl.IsOverridable(),
		pl.SupportsCatalyst(),
		pl.IsCatalystOverride(),
		pl.RegionsCount())
}

// PrebuiltLoaderSet is an mmap()ed read-only data structure which holds a set of PrebuiltLoader objects;
// The contained PrebuiltLoader objects can be found be index O(1) or path O(n).
type PrebuiltLoaderSet struct {
	Magic                    uint32
	VersionHash              uint32 // PREBUILTLOADER_VERSION
	Length                   uint32
	LoadersArrayCount        uint32
	LoadersArrayOffset       uint32
	CachePatchCount          uint32
	CachePatchOffset         uint32
	DyldCacheUuidOffset      uint32
	MustBeMissingPathsCount  uint32
	MustBeMissingPathsOffset uint32
	// ObjC prebuilt data
	ObjcSelectorHashTableOffset  uint32
	ObjcClassHashTableOffset     uint32
	ObjcProtocolHashTableOffset  uint32
	Reserved                     uint32
	ObjcProtocolClassCacheOffset uint64
	// Swift prebuilt data
	SwiftTypeConformanceTableOffset        uint32
	SwiftMetadataConformanceTableOffset    uint32
	SwiftForeignTypeConformanceTableOffset uint32
}

// ObjCBinaryInfo stores information about the layout of the objc sections in a binary,
// as well as other properties relating to the objc information in there.
type ObjCBinaryInfo struct {
	// Offset to the __objc_imageinfo section
	ImageInfoRuntimeOffset uint64

	// Offsets to sections containing objc pointers
	SelRefsRuntimeOffset      uint64
	ClassListRuntimeOffset    uint64
	CategoryListRuntimeOffset uint64
	ProtocolListRuntimeOffset uint64

	// Counts of the above sections.
	SelRefsCount      uint32
	ClassListCount    uint32
	CategoryCount     uint32
	ProtocolListCount uint32

	// Do we have stable Swift fixups to apply to at least one class?
	HasClassStableSwiftFixups bool

	// Do we have any pointer-based method lists to set as uniqued?
	HasClassMethodListsToSetUniqued    bool
	HasCategoryMethodListsToSetUniqued bool
	HasProtocolMethodListsToSetUniqued bool

	// Do we have any method lists in which to set selector references.
	// Note we only support visiting selector refernces in pointer based method lists
	// Relative method lists should have been verified to always point to __objc_selrefs
	HasClassMethodListsToUnique    bool
	HasCategoryMethodListsToUnique bool
	HasProtocolMethodListsToUnique bool

	// Whwn serialized to the PrebuildLoader, these fields will encode other information about
	// the binary.

	// Offset to an array of 's.  One for each protocol.
	// Note this can be 0 (ie, have no fixups), even if we have protocols.  That would be the case
	// if this binary contains no canonical protocol definitions, ie, all canonical defs are in other binaries
	// or the shared cache.
	ProtocolFixupsOffset uint32
	// Offset to an array of BindTargetRef's.  One for each selector reference to fix up
	// Note we only fix up selector refs in the __objc_selrefs section, and in pointer-based method lists
	SelectorReferencesFixupsOffset uint32
	SelectorReferencesFixupsCount  uint32
}

func (f *File) ForEachLaunchLoaderSet(handler func(execPath string, pset *PrebuiltLoaderSet, pbls []PrebuiltLoader)) error {
	uuid, off, err := f.GetOffset(f.Headers[f.UUID].ProgramTrieAddr)
	if err != nil {
		return err
	}

	dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(f.Headers[f.UUID].ProgramTrieSize))
	if err != nil {
		return err
	}

	r := bytes.NewReader(dat)

	nodes, err := trie.ParseTrie(r)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		r.Seek(int64(node.Offset), io.SeekStart)

		pblsOff, err := trie.ReadUleb128(r)
		if err != nil {
			return err
		}

		uuid, off, err := f.GetOffset(f.Headers[f.UUID].ProgramsPblSetPoolAddr + uint64(pblsOff))
		if err != nil {
			return err
		}

		sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)
		sr.Seek(int64(off), io.SeekStart)

		var pset PrebuiltLoaderSet
		if err := binary.Read(sr, binary.LittleEndian, &pset); err != nil {
			return err
		}

		sr.Seek(int64(off)+int64(pset.LoadersArrayOffset), io.SeekStart)

		loaderOffsets := make([]uint32, pset.LoadersArrayCount)
		if err := binary.Read(sr, binary.LittleEndian, &loaderOffsets); err != nil {
			return err
		}

		var pbls []PrebuiltLoader
		for _, loaderOffset := range loaderOffsets {
			sr.Seek(int64(off)+int64(loaderOffset), io.SeekStart)
			var pbl PrebuiltLoader
			if err := binary.Read(sr, binary.LittleEndian, &pbl); err != nil {
				return err
			}
			pbls = append(pbls, pbl)
			if string(node.Data) == "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd" {
				fmt.Println("WAIT!")
			}
			if pbl.ObjcBinaryInfoOffset > 0 {
				sr.Seek(int64(off)+int64(loaderOffset)+int64(pbl.ObjcBinaryInfoOffset), io.SeekStart)
				var obi ObjCBinaryInfo
				if err := binary.Read(sr, binary.LittleEndian, &obi); err != nil {
					return err
				}
				_ = obi
			}
		}

		handler(string(node.Data), &pset, pbls)
	}

	return nil
}

func (f *File) GetLaunchLoaderSet(executablePath string) (*PrebuiltLoaderSet, error) {
	uuid, off, err := f.GetOffset(f.Headers[f.UUID].ProgramTrieAddr)
	if err != nil {
		return nil, err
	}

	dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(f.Headers[f.UUID].ProgramTrieSize))
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(dat)

	if _, err = trie.WalkTrie(r, executablePath); err != nil {
		return nil, fmt.Errorf("could not find executable %s in the ProgramTrie: %w", executablePath, err)
	}

	poolOffset, err := trie.ReadUleb128(r)
	if err != nil {
		return nil, err
	}
	r.Seek(int64(poolOffset), io.SeekStart)

	uuid, off, err = f.GetOffset(f.Headers[f.UUID].ProgramsPblSetPoolAddr + uint64(poolOffset))
	if err != nil {
		return nil, err
	}

	sr := io.NewSectionReader(f.r[uuid], int64(off), 1<<63-1)

	var pset PrebuiltLoaderSet
	if err := binary.Read(sr, binary.LittleEndian, &pset); err != nil {
		return nil, err
	}

	if pset.Magic != PrebuiltLoaderSetMagic {
		return nil, fmt.Errorf("invalid magic for PrebuiltLoader at %#x: expected %x got %x", off, PrebuiltLoaderSetMagic, pset.Magic)
	}

	sr.Seek(int64(pset.LoadersArrayOffset), io.SeekStart)

	loaderOffsets := make([]uint32, pset.LoadersArrayCount)
	if err := binary.Read(sr, binary.LittleEndian, &loaderOffsets); err != nil {
		return nil, err
	}

	var pbls []PrebuiltLoader
	for _, loaderOffset := range loaderOffsets {
		sr.Seek(int64(loaderOffset), io.SeekStart)
		var pbl PrebuiltLoader
		if err := binary.Read(sr, binary.LittleEndian, &pbl); err != nil {
			return nil, err
		}

		if pbl.Magic != LoaderMagic {
			return nil, fmt.Errorf("invalid magic for PrebuiltLoader at %#x: expected %x got %x", loaderOffset, LoaderMagic, pbl.Magic)
		}

		pbls = append(pbls, pbl)

		if pbl.RegionsCount() > 0 {
			sr.Seek(int64(loaderOffset)+int64(pbl.RegionsOffset), io.SeekStart)
			regions := make([]Region, pbl.RegionsCount())
			if err := binary.Read(sr, binary.LittleEndian, &regions); err != nil {
				return nil, err
			}
			for _, region := range regions {
				fmt.Println(region)
			}
		}
		if pbl.FileValidationOffset > 0 {
			sr.Seek(int64(loaderOffset)+int64(pbl.FileValidationOffset), io.SeekStart)
			var fv FileValidation
			if err := binary.Read(sr, binary.LittleEndian, &fv); err != nil {
				return nil, err
			}
			_ = fv
		}
		if pbl.DependentLoaderRefsArrayOffset > 0 {
			sr.Seek(int64(loaderOffset)+int64(pbl.DependentLoaderRefsArrayOffset), io.SeekStart)
			depsArray := make([]LoaderRef, pbl.DepCount)
			if err := binary.Read(sr, binary.LittleEndian, &depsArray); err != nil {
				return nil, err
			}
			sr.Seek(int64(loaderOffset)+int64(pbl.DependentKindArrayOffset), io.SeekStart)
			kindsArray := make([]DependentKind, pbl.DepCount)
			if err := binary.Read(sr, binary.LittleEndian, &kindsArray); err != nil {
				return nil, err
			}
		}
		if pbl.ObjcBinaryInfoOffset > 0 {
			sr.Seek(int64(loaderOffset)+int64(pbl.ObjcBinaryInfoOffset), io.SeekStart)
			var obi ObjCBinaryInfo
			if err := binary.Read(sr, binary.LittleEndian, &obi); err != nil {
				return nil, err
			}
			_ = obi
		}
	}

	return &pset, nil
}

func (f *File) GetDylibLaunchLoader(executablePath string) (*PrebuiltLoader, error) {
	uuid, off, err := f.GetOffset(f.Headers[f.UUID].DylibsPblSetAddr)
	if err != nil {
		return nil, err
	}

	sr := io.NewSectionReader(f.r[uuid], int64(off), 1<<63-1)

	var pset PrebuiltLoaderSet
	if err := binary.Read(sr, binary.LittleEndian, &pset); err != nil {
		return nil, err
	}

	sr.Seek(int64(pset.LoadersArrayOffset), io.SeekStart)

	loaderOffsets := make([]uint32, pset.LoadersArrayCount)
	if err := binary.Read(sr, binary.LittleEndian, &loaderOffsets); err != nil {
		return nil, err
	}

	imgIdx, err := f.HasImagePath(executablePath)
	if err != nil {
		return nil, err
	} else if imgIdx < 0 {
		return nil, fmt.Errorf("image not found")
	}

	sr.Seek(int64(loaderOffsets[imgIdx]), io.SeekStart)

	var pbl PrebuiltLoader
	if err := binary.Read(sr, binary.LittleEndian, &pbl); err != nil {
		return nil, err
	}

	return &pbl, nil
}
