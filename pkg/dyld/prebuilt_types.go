package dyld

//go:generate go tool stringer -type=dyld_section_location_kind -trimprefix=dyld_section_location_ -output prebuilt_string.go

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/table"
)

const (
	LoaderMagic            = 0x6c347964 // "l4yd"
	PrebuiltLoaderSetMagic = 0x73703464 // "sp4d"
	NoUnzipperedTwin       = 0xFFFF
)

var ErrPrebuiltLoaderSetNotSupported = fmt.Errorf("dyld_shared_cache has no launch prebuilt loader set info")
var ErrProgramTrieNotSupported = fmt.Errorf("dyld_shared_cache has no program trie info")

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
func (l LoaderRef) String() string {
	var typ string
	if l.IsApp() {
		typ = ", type: app"
	}
	missing_weak_image := ""
	if l.IsMissingWeakImage() {
		missing_weak_image = " (missing weak image)"
	}
	return fmt.Sprintf("index: %d%s%s", l.Index(), typ, missing_weak_image)
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
	// isPremapped        :  1,  // mapped by exclave core
	// hasUUIDLoadCommand :  1,
	// hasWeakDefs        :  1,
	// hasTLVs            :  1,
	// belowLibSystem     :  1,
	// padding            :  2;
	Ref LoaderRef
	// Unk [12]uint16
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
func (l Loader) IsPremapped() bool {
	return types.ExtractBits(uint64(l.Info), 9, 1) != 0
}
func (l Loader) HasUUIDLoadCommand() bool {
	return types.ExtractBits(uint64(l.Info), 10, 1) != 0
}
func (l Loader) HasWeakDefs() bool {
	return types.ExtractBits(uint64(l.Info), 11, 1) != 0
}
func (l Loader) HasTLVs() bool {
	return types.ExtractBits(uint64(l.Info), 12, 1) != 0
}
func (l Loader) BelowLibSystem() bool {
	return types.ExtractBits(uint64(l.Info), 13, 1) != 0
}
func (l Loader) Padding() uint8 {
	return uint8(types.ExtractBits(uint64(l.Info), 14, 2))
}

func (l Loader) String() string {
	var out []string
	if l.IsPrebuilt() {
		out = append(out, "prebuilt")
	} else {
		out = append(out, "jit")
	}
	if l.DylibInDyldCache() {
		out = append(out, "in-cache-dylib")
	}
	if l.HasObjC() {
		out = append(out, "objc")
	}
	if l.MayHavePlusLoad() {
		out = append(out, "+load")
	}
	if l.HasReadOnlyData() {
		out = append(out, "ro-data")
	}
	if l.NeverUnload() {
		out = append(out, "never-unload")
	}
	if l.LeaveMapped() {
		out = append(out, "leave-mapped")
	}
	if l.HasReadOnlyObjC() {
		out = append(out, "ro-objc")
	}
	if l.Pre2022Binary() {
		out = append(out, "pre-2022")
	}
	if l.IsPremapped() {
		out = append(out, "premapped")
	}
	if l.HasUUIDLoadCommand() {
		out = append(out, "uuid-load-cmd")
	}
	if l.HasWeakDefs() {
		out = append(out, "weak-defs")
	}
	if l.HasTLVs() {
		out = append(out, "tlvs")
	}
	if l.BelowLibSystem() {
		out = append(out, "below-libsystem")
	}
	return fmt.Sprintf("%s, ref: %s", strings.Join(out, "|"), l.Ref)
}

type DependentKind uint8

const (
	KindNormal   DependentKind = 0
	KindWeakLink DependentKind = 1
	KindReexport DependentKind = 2
	KindUpward   DependentKind = 4
	KindDelayed  DependentKind = 8
)

func (k DependentKind) String() string {
	switch k {
	case KindNormal:
		return "regular"
	case KindWeakLink:
		return "weak-link"
	case KindReexport:
		return "re-export"
	case KindUpward:
		return "upward"
	case KindDelayed:
		return "delay-init"
	default:
		return fmt.Sprintf("unknown %d", k)
	}
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
func (b BindTargetRef) String(f *File) string {
	if b.IsAbsolute() {
		return fmt.Sprintf("%#08x: (absolue)", b.Offset())
	}
	if b.LoaderRef().IsApp() || int(b.LoaderRef().Index()) >= len(f.Images) {
		return fmt.Sprintf("%#08x: (%s)", b.Offset(), b.LoaderRef())
	}
	return fmt.Sprintf("%#08x: %s", b.Offset(), f.Images[b.LoaderRef().Index()].Name)
}

type CachePatch struct {
	DylibIndex    uint32
	DylibVMOffset uint32
	PatchTo       BindTargetRef
}
type dpkind int64

const (
	endOfPatchTable   dpkind = -1
	missingWeakImport dpkind = 0
	objcClass         dpkind = 1
	singleton         dpkind = 2
)

type DylibPatch struct {
	OverrideOffsetOfImpl int64
	Kind                 dpkind
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
	TargetLoader          *Loader
	TargetSymbolName      string
	TargetRuntimeOffset   uint64
	TargetAddressForDlsym uint64
	Kind                  RSKind
	IsCode                bool
	IsWeakDef             bool
	IsMissingFlatLazy     bool
	IsMaterializing       bool
}

type BindTarget struct {
	Loader        *Loader
	RuntimeOffset uint64
}

// fileValidation stored in PrebuiltLoader when it references a file on disk
type fileValidation struct {
	SliceOffset     uint64
	DeviceID        uint64
	Inode           uint64
	Mtime           uint64
	CDHash          [20]byte // to validate file has not changed since PrebuiltLoader was built
	CheckInodeMtime bool
	CheckCDHash     bool
}

type CodeSignatureInFile struct {
	FileOffset uint32
	Size       uint32
}

type ExportsTrieLoaderInFile struct {
	Offset uint64
	Size   uint32
}

func deserializeAbsoluteValue(value uint64) uint64 {
	// sign extend
	if (value & 0x4000000000000000) != 0 {
		value |= 0x8000000000000000
	}
	return value
}

type dependent struct {
	Name string
	Kind DependentKind
}

type dyld_section_location_kind uint32

const (
	// TEXT:
	dyld_section_location_text_swift5_protos dyld_section_location_kind = iota
	dyld_section_location_text_swift5_proto
	dyld_section_location_text_swift5_types
	dyld_section_location_text_swift5_replace
	dyld_section_location_text_swift5_replace2
	dyld_section_location_text_swift5_ac_funcs

	// DATA*:
	dyld_section_location_objc_image_info
	dyld_section_location_data_sel_refs
	dyld_section_location_data_msg_refs
	dyld_section_location_data_class_refs
	dyld_section_location_data_super_refs
	dyld_section_location_data_protocol_refs
	dyld_section_location_data_class_list
	dyld_section_location_data_non_lazy_class_list
	dyld_section_location_data_stub_list
	dyld_section_location_data_category_list
	dyld_section_location_data_category_list2
	dyld_section_location_data_non_lazy_category_list
	dyld_section_location_data_protocol_list
	dyld_section_location_data_objc_fork_ok
	dyld_section_location_data_raw_isa

	// Note, always add new entries before this
	dyld_section_location_count
)

type SectionLocations struct {
	Version uint32 // = 1;
	Flags   uint32 // = 0;

	Offsets [dyld_section_location_count]uint64
	Sizes   [dyld_section_location_count]uint64
}

type prebuiltLoaderHeader struct {
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

	ExportsTrieLoader ExportsTrieLoaderInFile

	VmSize uint32

	CodeSignature CodeSignatureInFile

	PatchTableOffset uint32

	OverrideBindTargetRefsOffset uint32
	OverrideBindTargetRefsCount  uint32

	_ uint32 // padding

	Sections SectionLocations

	// followed by:
	//  path chars
	//  dep kind array
	//  file validation info
	//  segments
	//  bind targets
}

func (hdr prebuiltLoaderHeader) HasInitializers() bool {
	return types.ExtractBits(uint64(hdr.Info), 0, 1) != 0
}
func (hdr prebuiltLoaderHeader) IsOverridable() bool {
	return types.ExtractBits(uint64(hdr.Info), 1, 1) != 0
}
func (hdr prebuiltLoaderHeader) SupportsCatalyst() bool {
	return types.ExtractBits(uint64(hdr.Info), 2, 1) != 0
}
func (hdr prebuiltLoaderHeader) IsCatalystOverride() bool {
	return types.ExtractBits(uint64(hdr.Info), 3, 1) != 0
}
func (hdr prebuiltLoaderHeader) RegionsCount() uint16 {
	return uint16(types.ExtractBits(uint64(hdr.Info), 4, 12))
}
func (hdr prebuiltLoaderHeader) GetInfo() string {
	var out []string
	if hdr.HasInitializers() {
		out = append(out, "initializers")
	}
	if hdr.IsOverridable() {
		out = append(out, "overridable")
	}
	if hdr.SupportsCatalyst() {
		out = append(out, "catalyst")
	}
	if hdr.IsCatalystOverride() {
		out = append(out, "catalyst_override")
	}
	if hdr.RegionsCount() > 0 {
		out = append(out, fmt.Sprintf("regions=%d", hdr.RegionsCount()))
	}
	return strings.Join(out, "|")
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
	_                              bool //padding

	// When serialized to the PrebuildLoader, these fields will encode other information about
	// the binary.

	// Offset to an array of uint8_t's.  One for each protocol.
	// Note this can be 0 (ie, have no fixups), even if we have protocols.  That would be the case
	// if this binary contains no canonical protocol definitions, ie, all canonical defs are in other binaries
	// or the shared cache.
	ProtocolFixupsOffset uint32
	// Offset to an array of BindTargetRef's.  One for each selector reference to fix up
	// Note we only fix up selector refs in the __objc_selrefs section, and in pointer-based method lists
	SelectorReferencesFixupsOffset uint32
	SelectorReferencesFixupsCount  uint32
}

func (o ObjCBinaryInfo) String() string {
	var out string
	out += fmt.Sprintf("  __objc_imageinfo: %#08x\n", o.ImageInfoRuntimeOffset)
	out += fmt.Sprintf("  __objc_selrefs:   %#08x (count=%d)\n", o.SelRefsRuntimeOffset, o.SelRefsCount)
	out += fmt.Sprintf("  __objc_classlist: %#08x (count=%d)\n", o.ClassListRuntimeOffset, o.ClassListCount)
	out += fmt.Sprintf("  __objc_catlist:   %#08x (count=%d)\n", o.CategoryListRuntimeOffset, o.CategoryCount)
	out += fmt.Sprintf("  __objc_protolist: %#08x (count=%d)\n", o.ProtocolListRuntimeOffset, o.ProtocolListCount)
	var flags []string
	if o.HasClassStableSwiftFixups {
		flags = append(flags, "class-stable-swift-fixups")
	}
	if o.HasClassMethodListsToSetUniqued {
		flags = append(flags, "class-method-lists-to-set-uniqued")
	}
	if o.HasCategoryMethodListsToSetUniqued {
		flags = append(flags, "category-method-lists-to-set-uniqued")
	}
	if o.HasProtocolMethodListsToSetUniqued {
		flags = append(flags, "protocol-method-lists-to-set-uniqued")
	}
	if o.HasClassMethodListsToUnique {
		flags = append(flags, "class-method-lists-to-unique")
	}
	if o.HasCategoryMethodListsToUnique {
		flags = append(flags, "category-method-lists-to-unique")
	}
	if o.HasProtocolMethodListsToUnique {
		flags = append(flags, "protocol-method-lists-to-unique")
	}
	if len(flags) > 0 {
		out += "\n  flags:\n"
		for _, f := range flags {
			out += fmt.Sprintf("    - %s\n", f)
		}
	}
	return out
}

type PrebuiltLoader struct {
	Loader
	UUID                        types.UUID
	CpuSubtype                  uint32
	Unused                      uint32
	Header                      prebuiltLoaderHeader
	Path                        string
	AltPath                     string
	Twin                        string
	Dependents                  []dependent
	FileValidation              *fileValidation
	Regions                     []Region
	BindTargets                 []BindTargetRef
	DylibPatches                []DylibPatch
	OverrideBindTargets         []BindTargetRef
	ObjcFixupInfo               *ObjCBinaryInfo
	ObjcCanonicalProtocolFixups []bool
	ObjcSelectorFixups          []BindTargetRef
}

func (pl PrebuiltLoader) GetFileOffset(vmoffset uint64) uint64 {
	for _, region := range pl.Regions {
		if vmoffset >= region.VMOffset() && vmoffset < region.VMOffset()+uint64(region.FileSize) {
			return uint64(region.FileOffset) + (vmoffset - region.VMOffset())
		}
	}
	return 0
}
func (pl PrebuiltLoader) String(f *File) string {
	var out string
	if pl.Path != "" {
		out += fmt.Sprintf("Path:    %s\n", pl.Path)
	}
	if pl.AltPath != "" {
		out += fmt.Sprintf("AltPath: %s\n", pl.AltPath)
	}
	if pl.Twin != "" {
		out += fmt.Sprintf("Twin:    %s\n", pl.Twin)
	}
	out += fmt.Sprintf("VM Size:       %#x\n", pl.Header.VmSize)
	if pl.Header.CodeSignature.Size > 0 {
		out += fmt.Sprintf("CodeSignature: off=%#08x, sz=%#x\n", pl.Header.CodeSignature.FileOffset, pl.Header.CodeSignature.Size)
	}
	if pl.FileValidation != nil {
		if pl.FileValidation.CheckCDHash {
			h := sha1.New()
			h.Write(pl.FileValidation.CDHash[:])
			out += fmt.Sprintf("CDHash:        %x\n", h.Sum(nil))
		}
		if pl.FileValidation.CheckInodeMtime {
			out += fmt.Sprintf("slice-offset:  %#x\n", pl.FileValidation.SliceOffset)
			out += fmt.Sprintf("device-id:  %#x\n", pl.FileValidation.DeviceID)
			out += fmt.Sprintf("inode          %#x\n", pl.FileValidation.Inode)
			out += fmt.Sprintf("mod-time       %#x\n", pl.FileValidation.Mtime)
		}
		// if !pl.FileValidation.UUID.IsNull() {
		// 	out += fmt.Sprintf("UUID:          %s\n", pl.FileValidation.UUID)
		// }
	}
	out += fmt.Sprintf("Loader:        %s\n", pl.Loader)
	if len(pl.Header.GetInfo()) > 0 {
		out += fmt.Sprintf("Info:          %s\n", pl.Header.GetInfo())
	}
	if pl.Header.ExportsTrieLoader.Size > 0 {
		out += fmt.Sprintf("ExportsTrie:   off=%#08x, sz=%#x\n", pl.GetFileOffset(pl.Header.ExportsTrieLoader.Offset), pl.Header.ExportsTrieLoader.Size)
	}
	if pl.Header.FixupsLoadCommandOffset > 0 {
		out += fmt.Sprintf("FixupsLoadCmd: off=%#08x\n", pl.Header.FixupsLoadCommandOffset)
	}
	if len(pl.Regions) > 0 {
		out += "\nRegions:\n\n"
		tableString := &strings.Builder{}
		rdata := [][]string{}
		for _, rg := range pl.Regions {
			rdata = append(rdata, []string{
				fmt.Sprintf("%#08x", rg.FileOffset),
				fmt.Sprintf("%#08x", rg.FileSize),
				fmt.Sprintf("%#08x", rg.VMOffset()),
				rg.Perms().String(),
				fmt.Sprintf("%t", rg.IsZeroFill()),
				fmt.Sprintf("%t", rg.ReadOnlyData()),
			})
		}
		tbl := table.NewStringBuilderTableWriter(tableString)
		tbl.SetHeader([]string{"File Off", "File Sz", "VM Off", "Perms", "Zero Fill", "RO Data"})
		tbl.SetBorders(nil)
		tbl.SetCenterSeparator("|")
		tbl.AppendBulk(rdata)
		tbl.SetAlignment(1)
		tbl.Render()
		out += tableString.String()
	}
	out += "\nSections:\n"
	buf := &strings.Builder{}
	w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
	for idx, off := range pl.Header.Sections.Offsets {
		if off == 0 {
			continue
		}
		fmt.Fprintf(w, "    %s:\toff=%#x\tsz=%d\n", dyld_section_location_kind(idx), off, pl.Header.Sections.Sizes[idx])
	}
	w.Flush()
	out += buf.String()
	if len(pl.Dependents) > 0 {
		out += "\nDependents:\n"
		for _, dp := range pl.Dependents {
			out += fmt.Sprintf("    %-10s) %s\n", dp.Kind, dp.Name)
		}
	}
	if len(pl.BindTargets) > 0 {
		out += "\nBindTargets:\n"
		for _, bt := range pl.BindTargets {
			out += fmt.Sprintf("    %s\n", bt.String(f))
		}
	}
	if len(pl.OverrideBindTargets) > 0 {
		out += "\nOverride BindTargets:\n"
		for _, bt := range pl.OverrideBindTargets {
			out += fmt.Sprintf("    %s\n", bt.String(f))
		}
	}
	if pl.ObjcFixupInfo != nil {
		out += "\nObjC Fixup Info:\n"
		out += fmt.Sprintln(pl.ObjcFixupInfo.String())
	}
	if len(pl.ObjcCanonicalProtocolFixups) > 0 {
		out += "ObjC Canonical ProtocolFixups:\n"
		for _, fixup := range pl.ObjcCanonicalProtocolFixups {
			out += fmt.Sprintf("    %t\n", fixup)
		}
	}
	if len(pl.ObjcSelectorFixups) > 0 {
		out += "\nObjC SelectorFixups:\n"
		for _, bt := range pl.ObjcSelectorFixups {
			out += fmt.Sprintf("    %s\n", bt.String(f))
		}
	}

	return out
}

type objCFlags uint32

const (
	NoObjCFlags         objCFlags = 0
	HasDuplicateClasses objCFlags = 1 << 0
)

// PrebuiltLoaderSet is an mmap()ed read-only data structure which holds a set of PrebuiltLoader objects;
// The contained PrebuiltLoader objects can be found be index O(1) or path O(n).
type prebuiltLoaderSetHeader struct {
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
	ObjcFlags                    objCFlags
	ObjcProtocolClassCacheOffset uint64
	// Swift prebuilt data
	SwiftTypeConformanceTableOffset        uint32
	SwiftMetadataConformanceTableOffset    uint32
	SwiftForeignTypeConformanceTableOffset uint32
}

type PrebuiltLoaderSet struct {
	prebuiltLoaderSetHeader
	Loaders                       []PrebuiltLoader
	Patches                       []CachePatch
	DyldCacheUUID                 types.UUID
	MustBeMissingPaths            []string
	SelectorTable                 *ObjCSelectorOpt
	ClassTable                    *ObjCClassOpt
	ProtocolTable                 *ObjCClassOpt
	SwiftTypeProtocolTable        SwiftTypeConformanceEntries
	SwiftMetadataProtocolTable    SwiftMetadataConformanceEntries
	SwiftForeignTypeProtocolTable SwiftForeignTypeConformanceEntries
}

func (pls PrebuiltLoaderSet) HasOptimizedObjC() bool {
	return (pls.ObjcSelectorHashTableOffset != 0) || (pls.ObjcClassHashTableOffset != 0) || (pls.ObjcProtocolHashTableOffset != 0)
}
func (pls PrebuiltLoaderSet) HasOptimizedSwift() bool {
	return (pls.SwiftForeignTypeConformanceTableOffset != 0) || (pls.SwiftMetadataConformanceTableOffset != 0) || (pls.SwiftTypeConformanceTableOffset != 0)
}
func (pls PrebuiltLoaderSet) String(f *File) string {
	var out string
	out += "PrebuiltLoaderSet:\n"
	out += fmt.Sprintf("  Version: %x\n", pls.VersionHash)
	if !pls.DyldCacheUUID.IsNull() {
		out += fmt.Sprintf("  DyldCacheUUID: %s\n", pls.DyldCacheUUID)
	}
	if len(pls.Loaders) > 0 {
		out += "\nLoaders:\n"
		for _, pl := range pls.Loaders {
			if len(pls.Loaders) > 1 {
				out += "---\n"
			}
			out += pl.String(f)
		}
	}
	if pls.SelectorTable != nil {
		out += "\nObjC Selector Table:\n"
		for _, bt := range pls.SelectorTable.Offsets {
			if bt.IsAbsolute() {
				continue
			}
			out += fmt.Sprintf("  %s\n", bt.String(f))
		}
	}
	if pls.ClassTable != nil {
		out += "\nObjC Class Table:\n"
		for idx, bt := range pls.ClassTable.Offsets {
			if bt.IsAbsolute() {
				continue
			}
			out += fmt.Sprintf("  %s name\n", bt.String(f))
			out += fmt.Sprintf("    %s impl\n", pls.ClassTable.Classes[idx].String(f))
		}
	}
	if pls.ProtocolTable != nil {
		out += "\nObjC Protocol Table:\n"
		for idx, bt := range pls.ProtocolTable.Offsets {
			if bt.IsAbsolute() {
				continue
			}
			out += fmt.Sprintf("  %s name\n", bt.String(f))
			out += fmt.Sprintf("    %s impl\n", pls.ProtocolTable.Classes[idx].String(f))
		}
	}
	if pls.HasOptimizedObjC() && pls.ObjcProtocolClassCacheOffset != 0 {
		out += fmt.Sprintf("\nObjC Protocol Class Cache Address: %#x\n", f.Headers[f.UUID].SharedRegionStart+pls.ObjcProtocolClassCacheOffset)
	}
	if len(pls.SwiftTypeProtocolTable) > 0 {
		out += "\nSwift Type Protocol Table\n"
		out += "-------------------------\n"
		pls.SwiftTypeProtocolTable.ForEachEntry(func(key SwiftTypeProtocolConformanceDiskLocationKey, values []SwiftTypeProtocolConformanceDiskLocation) {
			out += fmt.Sprintf("  %s type descriptor\n", key.TypeDescriptor.String(f))
			out += fmt.Sprintf("    %s protocol\n", key.Protocol.String(f))
			for _, v := range values {
				out += fmt.Sprintf("      %s conformance\n", v.ProtocolConformance.String(f))
			}
		})
	}
	if len(pls.SwiftMetadataProtocolTable) > 0 {
		out += "\nSwift Metadata Protocol Table\n"
		out += "-----------------------------\n"
		pls.SwiftMetadataProtocolTable.ForEachEntry(func(key SwiftMetadataProtocolConformanceDiskLocationKey, values []SwiftMetadataProtocolConformanceDiskLocation) {
			out += fmt.Sprintf("  %s metadata descriptor\n", key.MetadataDescriptor.String(f))
			out += fmt.Sprintf("    %s protocol\n", key.Protocol.String(f))
			for _, v := range values {
				out += fmt.Sprintf("      %s conformance\n", v.ProtocolConformance.String(f))
			}
		})
	}
	if len(pls.SwiftForeignTypeProtocolTable) > 0 {
		out += "\nSwift Foreign Protocol Table\n"
		out += "----------------------------\n"
		pls.SwiftForeignTypeProtocolTable.ForEachEntry(func(key SwiftForeignTypeProtocolConformanceDiskLocationKey, values []SwiftForeignTypeProtocolConformanceDiskLocation) {
			out += fmt.Sprintf("  %s foreign descriptor\n", key.ForeignDescriptor.String(f))
			out += fmt.Sprintf("    %s protocol\n", key.Protocol.String(f))
			for _, v := range values {
				out += fmt.Sprintf("      %s conformance\n", v.ProtocolConformance.String(f))
			}
		})
	}
	if len(pls.MustBeMissingPaths) > 0 {
		out += "\nMustBeMissing:\n"
		for _, path := range pls.MustBeMissingPaths {
			out += fmt.Sprintf("    %s\n", path)
		}
	}
	if len(pls.Patches) > 0 {
		out += "\nCache Overrides:\n"
		for _, patch := range pls.Patches {
			if len(pls.Patches) > 1 {
				out += "---\n"
			}
			img := fmt.Sprintf("(index=%d)", patch.DylibIndex)
			if patch.DylibIndex < uint32(len(f.Images)) {
				img = f.Images[patch.DylibIndex].Name
			}
			out += fmt.Sprintf("  cache-dylib:    %s\n", img)
			out += fmt.Sprintf("  dylib-offset:   %#08x\n", patch.DylibVMOffset)
			if patch.PatchTo.LoaderRef().Index() < uint16(len(f.Images)) {
				img = f.Images[patch.PatchTo.LoaderRef().Index()].Name
			} else {
				img = patch.PatchTo.LoaderRef().String()
			}
			out += fmt.Sprintf("  replace-loader: %s\n", img)
			out += fmt.Sprintf("  replace-offset: %#08x\n", patch.PatchTo.Offset())
		}
	}

	return out
}

type objCStringTable struct {
	Capacity              uint32
	Occupied              uint32
	Shift                 uint32
	Mask                  uint32
	RoundedTabSize        uint32
	RoundedCheckBytesSize uint32
	Salt                  uint64

	Scramble [256]uint32
	// uint8_t tab[0];                     /* tab[mask+1] (always power-of-2). Rounded up to roundedTabSize */
	// uint8_t checkbytes[capacity];    /* check byte for each string. Rounded up to roundedCheckBytesSize */
	// BindTargetRef offsets[capacity]; /* offsets from &capacity to cstrings */
}

type ObjCSelectorOpt struct {
	objCStringTable
	Tab        []byte          /* tab[mask+1] (always power-of-2). Rounded up to roundedTabSize */
	Checkbytes []byte          /* check byte for each string. Rounded up to roundedCheckBytesSize */
	Offsets    []BindTargetRef /* offsets from &capacity to cstrings */
}

type ObjCClassOpt struct {
	objCStringTable
	Tab        []byte          /* tab[mask+1] (always power-of-2). Rounded up to roundedTabSize */
	Checkbytes []byte          /* check byte for each string. Rounded up to roundedCheckBytesSize */
	Offsets    []BindTargetRef /* offsets from &capacity to cstrings */
	Classes    []BindTargetRef /* offsets from &capacity to cstrings */
	Duplicates []BindTargetRef /* offsets from &capacity to cstrings */
}

const MapSentinelHash = ^uint64(0)

type SwiftConformanceMultiMap struct {
	NextHashBufferGrowth uint64
	HashBufferUseCount   uint64
	// hashBufferCount 	uint64
	// hashBuffer [hashBufferCount]uint64
	// nodeBufferCount 	uint64
	// hashBuffer [nodeBufferCount]NodeEntryT
}

type SwiftTypeConformanceEntries []SwiftTypeProtocolNodeEntryT

func (ents SwiftTypeConformanceEntries) ForEachEntry(handler func(SwiftTypeProtocolConformanceDiskLocationKey, []SwiftTypeProtocolConformanceDiskLocation)) {
	var vals []SwiftTypeProtocolConformanceDiskLocation
	for _, head := range ents {
		nextNode := head.Next
		if !nextNode.HasAnyDuplicates() {
			handler(head.Key, []SwiftTypeProtocolConformanceDiskLocation{head.Value})
		}
		if !nextNode.IsDuplicateHead() {
			continue
		}
		vals = append(vals, head.Value) // add head node
		for ents[nextNode.NextIndex()].Next.HasMoreDuplicates() {
			vals = append(vals, ents[nextNode.NextIndex()].Value)
			nextNode = ents[nextNode.NextIndex()].Next
		}
		vals = append(vals, ents[nextNode.NextIndex()].Value) // add last node
		handler(head.Key, vals)
	}
}

type SwiftTypeProtocolNodeEntryT struct {
	Key   SwiftTypeProtocolConformanceDiskLocationKey
	Value SwiftTypeProtocolConformanceDiskLocation
	Next  NextNode
	_     uint32
}

type SwiftTypeProtocolConformanceDiskLocationKey struct {
	TypeDescriptor BindTargetRef
	Protocol       BindTargetRef
}

type SwiftTypeProtocolConformanceDiskLocation struct {
	ProtocolConformance BindTargetRef
}

type SwiftMetadataConformanceEntries []SwiftMetadataConformanceNodeEntryT

func (ents SwiftMetadataConformanceEntries) ForEachEntry(handler func(SwiftMetadataProtocolConformanceDiskLocationKey, []SwiftMetadataProtocolConformanceDiskLocation)) {
	var vals []SwiftMetadataProtocolConformanceDiskLocation
	for _, head := range ents {
		nextNode := head.Next
		if !nextNode.HasAnyDuplicates() {
			handler(head.Key, []SwiftMetadataProtocolConformanceDiskLocation{head.Value})
		}
		if !nextNode.IsDuplicateHead() {
			continue
		}
		vals = append(vals, head.Value) // add head node
		for ents[nextNode.NextIndex()].Next.HasMoreDuplicates() {
			vals = append(vals, ents[nextNode.NextIndex()].Value)
			nextNode = ents[nextNode.NextIndex()].Next
		}
		vals = append(vals, ents[nextNode.NextIndex()].Value) // add last node
		handler(head.Key, vals)
	}
}

type SwiftMetadataConformanceNodeEntryT struct {
	Key   SwiftMetadataProtocolConformanceDiskLocationKey
	Value SwiftMetadataProtocolConformanceDiskLocation
	Next  NextNode
	_     uint32
}

type SwiftMetadataProtocolConformanceDiskLocationKey struct {
	MetadataDescriptor BindTargetRef
	Protocol           BindTargetRef
}

type SwiftMetadataProtocolConformanceDiskLocation struct {
	ProtocolConformance BindTargetRef
}

type SwiftForeignTypeConformanceEntries []SwiftForeignTypeConformanceNodeEntryT

func (ents SwiftForeignTypeConformanceEntries) ForEachEntry(handler func(SwiftForeignTypeProtocolConformanceDiskLocationKey, []SwiftForeignTypeProtocolConformanceDiskLocation)) {
	var vals []SwiftForeignTypeProtocolConformanceDiskLocation
	for _, head := range ents {
		nextNode := head.Next
		if !nextNode.HasAnyDuplicates() {
			handler(head.Key, []SwiftForeignTypeProtocolConformanceDiskLocation{head.Value})
		}
		if !nextNode.IsDuplicateHead() {
			continue
		}
		vals = append(vals, head.Value) // add head node
		for ents[nextNode.NextIndex()].Next.HasMoreDuplicates() {
			vals = append(vals, ents[nextNode.NextIndex()].Value)
			nextNode = ents[nextNode.NextIndex()].Next
		}
		vals = append(vals, ents[nextNode.NextIndex()].Value) // add last node
		handler(head.Key, vals)
	}
}

type SwiftForeignTypeConformanceNodeEntryT struct {
	Key   SwiftForeignTypeProtocolConformanceDiskLocationKey
	Value SwiftForeignTypeProtocolConformanceDiskLocation
	Next  NextNode
	_     uint32
}

type SwiftForeignTypeProtocolConformanceDiskLocationKey struct {
	OriginalPointer             uint64
	ForeignDescriptor           BindTargetRef
	ForeignDescriptorNameLength uint64
	Protocol                    BindTargetRef
}

type SwiftForeignTypeProtocolConformanceDiskLocation struct {
	ProtocolConformance BindTargetRef
}

type NextNode uint32

func (nn NextNode) IsDuplicateHead() bool {
	return types.ExtractBits(uint64(nn), 0, 1) != 0
}
func (nn NextNode) IsDuplicateEntry() bool {
	return types.ExtractBits(uint64(nn), 1, 1) != 0
}
func (nn NextNode) IsDuplicateTail() bool {
	return types.ExtractBits(uint64(nn), 2, 1) != 0
}
func (nn NextNode) NextIndex() uint32 {
	return uint32(types.ExtractBits(uint64(nn), 3, 29))
}
func (nn NextNode) HasAnyDuplicates() bool {
	return nn.IsDuplicateHead() || nn.IsDuplicateEntry() || nn.IsDuplicateTail()
}
func (nn NextNode) HasMoreDuplicates() bool {
	return nn.IsDuplicateHead() || nn.IsDuplicateEntry()
}

// type NodeEntryT struct {
// 	Key   BindTargetRef
// 	Value BindTargetRef
// 	Next  NextNode
// }
