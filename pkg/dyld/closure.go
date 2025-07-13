package dyld

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/table"
)

//go:generate go tool stringer -type=closureType,linkKind -output closure_string.go

type closureType uint32

const (
	// containers which have an overall length and TypedBytes inside ther content
	launchClosure closureType = 1 // contains TypedBytes of closure attributes including imageArray
	imageArray    closureType = 2 // sizeof(ImageArray) + sizeof(uint32_t)*count + size of all images
	image         closureType = 3 // contains TypedBytes of image attributes
	dlopenClosure closureType = 4 // contains TypedBytes of closure attributes including imageArray
	// attributes for Images
	imageFlags           closureType = 7  // sizeof(Image::Flags)
	pathWithHash         closureType = 8  // len = uint32_t + length path + 1 use multiple entries for aliases
	fileInodeAndTime     closureType = 9  // sizeof(FileInfo)
	cdHash               closureType = 10 // 20 use multiple entries on watchOS for all hashes
	uuid                 closureType = 11 // 16
	mappingInfo          closureType = 12 // sizeof(MappingInfo)
	diskSegment          closureType = 13 // sizeof(DiskSegment) * count
	cacheSegment         closureType = 14 // sizeof(DyldCacheSegment) * count
	dependents           closureType = 15 // sizeof(LinkedImage) * count
	initOffsets          closureType = 16 // sizeof(uint32_t) * count
	dofOffsets           closureType = 17 // sizeof(uint32_t) * count
	codeSignLoc          closureType = 18 // sizeof(CodeSignatureLocation)
	farPlayLoc           closureType = 19 // sizeof(FarPlayRange)
	rebaseFixups         closureType = 20 // sizeof(RebasePattern) * count
	bindFixups           closureType = 21 // sizeof(BindPattern) * count
	cachePatchInfo       closureType = 22 // deprecated
	textFixups           closureType = 23 // sizeof(TextFixupPattern) * count
	imageOverride        closureType = 24 // sizeof(ImageNum)
	initBefores          closureType = 25 // sizeof(ImageNum) * count
	initsSection         closureType = 26 // sizeof(InitializerSectionRange)
	chainedFixupsTargets closureType = 27 // sizeof(ResolvedSymbolTarget) * count
	termOffsets          closureType = 28 // sizeof(uint32_t) * count
	chainedStartsOffset  closureType = 29 // sizeof(uint64_t)
	objcFixups           closureType = 30 // sizeof(ResolvedSymbolTarget) + (sizeof(uint32_t) * 2) + (sizeof(ProtocolISAFixup) * count) + (sizeof(SelectorReferenceFixup) * count)
	// attributes for Closures (launch or dlopen)
	closureFlags          closureType = 32 // sizeof(Closure::Flags)
	dyldCacheUUID         closureType = 33 // 16
	missingFiles          closureType = 34
	envVar                closureType = 35 // "DYLD_BLAH=stuff"
	topImage              closureType = 36 // sizeof(ImageNum)
	libDyldEntry          closureType = 37 // sizeof(ResolvedSymbolTarget)
	libSystemNum          closureType = 38 // sizeof(ImageNum)
	mainEntry             closureType = 40 // sizeof(ResolvedSymbolTarget)
	startEntry            closureType = 41 // sizeof(ResolvedSymbolTarget)     // used by programs built with crt1.o
	cacheOverrides        closureType = 42 // sizeof(PatchEntry) * count       // used if process uses interposing or roots (cached dylib overrides)
	interposeTuples       closureType = 43 // sizeof(InterposingTuple) * count
	existingFiles         closureType = 44 // uint64_t + (SkippedFiles * count)
	selectorTable         closureType = 45 // uint32_t + (sizeof(ObjCSelectorImage) * count) + hashTable size
	classTable            closureType = 46 // (3 * uint32_t) + (sizeof(ObjCClassImage) * count) + classHashTable size + protocolHashTable size
	warning               closureType = 47 // len = uint32_t + length path + 1 use one entry per warning
	duplicateClassesTable closureType = 48 // duplicateClassesHashTable
	progVars              closureType = 49 // sizeof(uint32_t)
)

const (
	FirstDyldCacheImageNum     = 0x00000001
	LastDyldCacheImageNum      = 0x00000FFF
	FirstOtherOSImageNum       = 0x00001001
	LastOtherOSImageNum        = 0x00001FFF
	FirstLaunchClosureImageNum = 0x00002000
	MissingWeakLinkedImage     = 0x0FFFFFFF
)

type CImage struct {
	ID                    uint32
	Name                  string
	Hash                  uint32
	UUID                  types.UUID
	Flags                 cFlags
	Dependents            []linkedImage
	CacheSegments         []cacheSegmentType
	DiskSegments          []diskSegmentType
	InitOrder             []uint32
	DofOffsets            []uint32
	InitializerOffsets    []uint32
	TerminatorOffsets     []uint32
	InitializerSections   []initializerSectionRangeType
	MappingInfo           mappingInfoType
	CodeSignatureLocation codeSignatureLocationType
	CDHash                cdhash
	Rebases               []rebasePatternType
	Binds                 []BindPattern
	TextFixups            []TextFixupPattern
	ChainedFixupsTargets  []resolvedSymbolTarget
	ChainedStartsOffset   uint64
	ObjcFixups            ObjcFixups
	FarPlayLocation       farPlayLocType
	FileInfo              fileInfoType
	ImageOverride         uint32
}

type LaunchClosure struct {
	Flags           lcFlags
	Images          []*CImage
	DyldUUID        types.UUID
	LibSystemNum    uint32
	LibDyldEntry    resolvedSymbolTarget
	TopImage        uint32
	MainEntry       resolvedSymbolTarget
	StartEntry      resolvedSymbolTarget
	ProgVars        uint32
	Warnings        []warningType
	DyldCacheFixups []PatchEntry
	MissingFiles    []string
	EnvVars         []string
}

func (i CImage) GetID() uint32 {
	return uint32(i.Flags.ImageNum())
}
func (i CImage) PageSize() uint32 {
	if i.Flags.Has16KbPages() {
		return 0x4000
	}
	return 0x1000
}

func (i CImage) String(d *File, verbose bool) string {
	var mappings string
	if i.MappingInfo.TotalVmPages > 0 {
		var slice string
		if i.MappingInfo.SliceOffsetIn4K > 0 {
			slice = fmt.Sprintf("Slice Offset:      %#x\n", i.MappingInfo.SliceOffsetIn4K*0x1000)
		}
		mappings = fmt.Sprintf(
			"Total VM Size:     %#x\n"+
				"%s",
			i.MappingInfo.TotalVmPages*i.PageSize(),
			slice,
		)
	}
	var cacheSegs string
	if len(i.CacheSegments) > 0 {
		cacheSegs = "Cache Segments:\n"
		for _, cs := range i.CacheSegments {
			cacheSegs += fmt.Sprintf("\t%s\n", cs)
		}
	}
	var diskSegs string
	if len(i.DiskSegments) > 0 {
		diskSegs = "\nMappings:\n"
		tableString := &strings.Builder{}

		mdata := [][]string{}
		prevFOff := uint32(0)
		for _, ds := range i.DiskSegments {
			mdata = append(mdata, []string{
				fmt.Sprintf("%#08x", prevFOff),
				fmt.Sprintf("%#08x", ds.FilePageCount()*i.PageSize()),
				fmt.Sprintf("%#08x", ds.VMPageCount()*i.PageSize()),
				ds.PermString(),
			})
			prevFOff += ds.FilePageCount() * i.PageSize()
		}
		tbl := table.NewStringBuilderTableWriter(tableString)
		tbl.SetHeader([]string{"File Offset", "File Size", "VM Size", "Prot"})
		tbl.SetBorders(nil)
		tbl.SetCenterSeparator("|")
		tbl.AppendBulk(mdata)
		tbl.SetAlignment(1)
		tbl.Render()

		diskSegs += tableString.String()
	}
	var initOrder string
	if len(i.InitOrder) > 0 {
		initOrder = "\nInit Order:\n"
		for _, io := range i.InitOrder {
			if val, ok := d.ImageArray[io]; ok {
				initOrder += fmt.Sprintf("\t%s\n", val.Name)
			} else {
				if io == FirstLaunchClosureImageNum {
					initOrder += fmt.Sprintf("\t%s\n", i.Name)
				} else {
					log.Errorf("no image found for ID %d", i)
				}
			}
		}
	}
	var deps string
	if len(i.Dependents) > 0 {
		deps = "\nDependents:\n"
		for _, dp := range i.Dependents {
			if val, ok := d.ImageArray[dp.ImgNum()]; ok {
				deps += fmt.Sprintf("\t%-8s) %s\n", dp.Link(), val.Name)
			} else {
				if dp.ImgNum() == FirstLaunchClosureImageNum {
					deps += fmt.Sprintf("\t%-8s) %s\n", dp.Link(), i.Name)
				} else if dp.ImgNum() == MissingWeakLinkedImage && dp.Link() == weak {
					continue
				} else {
					log.Errorf("no image found for ID %d", dp.ImgNum())
				}
			}
		}
	}
	var inits string
	var terms string
	var dofoff string
	if verbose {
		if len(i.InitializerOffsets) > 0 {
			inits = "\nInitializers:\n"
			for _, i := range i.InitializerOffsets {
				inits += fmt.Sprintf("\t%#x\n", i)
			}
		}
		if len(i.TerminatorOffsets) > 0 {
			terms = "\nTerminators:\n"
			for _, t := range i.TerminatorOffsets {
				terms += fmt.Sprintf("\t%#x\n", t)
			}
		}
		if len(i.DofOffsets) > 0 {
			dofoff = "\nDOF Offsets:\n"
			for _, do := range i.DofOffsets {
				dofoff += fmt.Sprintf("\t%#x\n", do)
			}
		}
	}
	var cslocation string
	if i.CodeSignatureLocation.FileSize > 0 {
		cslocation = fmt.Sprintf(
			"Code Signature:    offset: 0x%08x-0x%08x, size: %5d\n",
			i.CodeSignatureLocation.FileOffset,
			i.CodeSignatureLocation.FileOffset+i.CodeSignatureLocation.FileSize,
			i.CodeSignatureLocation.FileSize,
		)
	}
	var cdhash string
	if len(i.CDHash) > 0 {
		cdhash = fmt.Sprintf("CDHash:            %s\n", i.CDHash)
	}
	var id string
	if i.ID != FirstLaunchClosureImageNum {
		id = fmt.Sprintf("ID:                %d\n", i.ID)
	}
	return fmt.Sprintf(
		"%s"+
			"Name:              %s\n"+
			"Flags:             %s\n"+
			"UUID:              %s\n"+
			"%s%s%s%s%s%s%s%s%s%s",
		id,
		i.Name,
		i.Flags,
		i.UUID,
		cdhash,
		cslocation,
		mappings,
		cacheSegs,
		diskSegs,
		deps,
		initOrder,
		inits,
		terms,
		dofoff,
	)
}

type cdhash []byte

func (cd cdhash) String() string {
	h := sha1.New()
	h.Write(cd)
	return fmt.Sprintf("%x", h.Sum(nil))
}

type cacheSegmentType uint64

func (d cacheSegmentType) CacheOffset() uint32 {
	return uint32(types.ExtractBits(uint64(d), 0, 32))
}
func (d cacheSegmentType) Size() uint32 {
	return uint32(types.ExtractBits(uint64(d), 32, 28))
}
func (d cacheSegmentType) Permissions() uint32 {
	return uint32(types.ExtractBits(uint64(d), 60, 4))
}
func (d cacheSegmentType) String() string {
	return fmt.Sprintf("offset: %#08x, size: %#08x, perms: %s", d.CacheOffset(), d.Size(), types.VmProtection(d.Permissions()))
}

const ReadOnlyDataPermissions = 2

type diskSegmentType uint64

func (d diskSegmentType) FilePageCount() uint32 {
	return uint32(types.ExtractBits(uint64(d), 0, 30))
}
func (d diskSegmentType) VMPageCount() uint32 {
	return uint32(types.ExtractBits(uint64(d), 30, 30))
}
func (d diskSegmentType) Permissions() uint32 {
	return uint32(types.ExtractBits(uint64(d), 60, 3))
}
func (d diskSegmentType) PermString() string {
	perms := types.VmProtection(d.Permissions()).String()
	if d.Permissions() == ReadOnlyDataPermissions {
		perms = "-w-"
	}
	return perms
}
func (d diskSegmentType) PaddingNotSeg() bool {
	return uint32(types.ExtractBits(uint64(d), 63, 1)) != 0
}
func (d diskSegmentType) String() string {

	return fmt.Sprintf("file_pages: %d, vm_pages: %d, perms: %s, noncontig_segs : %t",
		d.FilePageCount(),
		d.VMPageCount(),
		d.PermString(),
		d.PaddingNotSeg())
}

type rebasePatternType uint32

func (r rebasePatternType) RepeatCount() uint32 {
	return uint32(types.ExtractBits(uint64(r), 0, 20))
}
func (r rebasePatternType) ContigCount() uint32 {
	return uint32(types.ExtractBits(uint64(r), 20, 8))
}
func (r rebasePatternType) SkipCount() uint32 {
	return uint32(types.ExtractBits(uint64(r), 28, 4))
}

func (r rebasePatternType) String() string {
	return fmt.Sprintf("repeat_count: %d, contig_count: %d, skip_count : %d",
		r.RepeatCount(),
		r.ContigCount(),
		r.SkipCount())
}

type targetKind uint8

const (
	KindRebase targetKind = iota
	KindSharedCache
	KindImage
	KindAbsolute
)

type resolvedSymbolTarget uint64

func (r resolvedSymbolTarget) Kind() targetKind {
	return targetKind(types.ExtractBits(uint64(r), 0, 2))
}
func (r resolvedSymbolTarget) SharedCacheOffset() uint64 {
	return types.ExtractBits(uint64(r), 2, 22)
}
func (r resolvedSymbolTarget) ImageNum() uint64 {
	return types.ExtractBits(uint64(r), 2, 22)
}
func (r resolvedSymbolTarget) ImageOffset() uint64 {
	return types.ExtractBits(uint64(r), 24, 40)
}
func (r resolvedSymbolTarget) AbsoluteValue() int64 { // sign extended
	return int64(types.ExtractBits(uint64(r), 2, 62))
}
func (r resolvedSymbolTarget) Raw() uint64 {
	return uint64(r)
}
func (r resolvedSymbolTarget) String() string {
	switch r.Kind() {
	case KindRebase:
		return fmt.Sprintf("kind: rebase, raw: %#x", r.Raw())
	case KindSharedCache:
		return fmt.Sprintf("kind: shared_cache, offset: %#x", r.SharedCacheOffset())
	case KindImage:
		return fmt.Sprintf("kind: image, index: %d, offset: %#x", r.ImageNum(), r.ImageOffset())
	case KindAbsolute:
		return fmt.Sprintf("kind: absolute, value: %#x", r.AbsoluteValue())
	}
	return fmt.Sprintf("error: unknown kind %d", r.Kind())
}

type BindPattern struct {
	Target resolvedSymbolTarget
	Detail bindPatternType
}

func (b BindPattern) String() string {
	return fmt.Sprintf("%s, %s", b.Target, b.Detail)
}

type bindPatternType uint64

func (b bindPatternType) StartVMOffset() uint64 { // max 1TB offset
	return types.ExtractBits(uint64(b), 0, 40)
}
func (b bindPatternType) SkipCount() uint64 {
	return types.ExtractBits(uint64(b), 40, 8)
}
func (b bindPatternType) RepeatCount() uint64 {
	return types.ExtractBits(uint64(b), 48, 16)
}

func (b bindPatternType) String() string {
	return fmt.Sprintf("start_vmoffset: %#x, skip_count: %d, repeat_count : %d",
		b.StartVMOffset(),
		b.SkipCount(),
		b.RepeatCount())
}

type TextFixupPattern struct {
	Target        resolvedSymbolTarget
	StartVmOffset uint32
	RepeatCount   uint16
	SkipCount     uint16
}

func (t TextFixupPattern) String() string {
	return fmt.Sprintf("%s, start_vmoffset: %#x, skip_count: %d, repeat_count : %d",
		t.Target, t.StartVmOffset, t.SkipCount, t.RepeatCount)
}

type ObjcFixups struct {
	objcFixupsType
	ProtocolISAFixups      []protocolISAFixup
	SelRefFixups           []SelectorReferenceFixup
	StableSwiftFixupCount  uint32
	MethodListFixupCount   uint32
	ClassStableSwiftFixups []classStableSwiftFixup
	MethodListFixups       []methodListFixup
}
type objcFixupsType struct {
	ProtocolClassTarget resolvedSymbolTarget
	ImageInfoVMOffset   uint64
	ProtocolFixupCount  uint32
	SelRefFixupCount    uint32
}

type protocolISAFixup uint64

func (p protocolISAFixup) StartVMOffset() uint64 {
	return types.ExtractBits(uint64(p), 0, 40)
}
func (p protocolISAFixup) SkipCount() uint64 {
	return types.ExtractBits(uint64(p), 40, 8)
}
func (p protocolISAFixup) RepeatCount() uint64 {
	return types.ExtractBits(uint64(p), 48, 16)
}
func (p protocolISAFixup) String() string {
	return fmt.Sprintf("start_vmoffset: %#x, skip_count: %d, repeat_count : %d",
		p.StartVMOffset(),
		p.SkipCount(),
		p.RepeatCount())
}

type SelectorReferenceFixup uint32

func (s SelectorReferenceFixup) String() string {
	return fmt.Sprintf("offset: %#x, %s", uint32(s), chainEntry(s))
}

type chainEntry uint32

func (c chainEntry) Index() uint32 {
	return uint32(types.ExtractBits(uint64(c), 0, 24))
}
func (c chainEntry) Next() uint32 {
	return uint32(types.ExtractBits(uint64(c), 24, 7))
}
func (c chainEntry) InSharedCache() bool {
	return types.ExtractBits(uint64(c), 31, 1) != 0
}
func (c chainEntry) String() string {
	return fmt.Sprintf("index: %d, next: %d, in_cache : %t",
		c.Index(), c.Next(), c.InSharedCache())
}

type classStableSwiftFixup uint64

func (c classStableSwiftFixup) StartVMOffset() uint64 {
	return types.ExtractBits(uint64(c), 0, 40)
}
func (c classStableSwiftFixup) SkipCount() uint64 {
	return types.ExtractBits(uint64(c), 40, 8)
}
func (c classStableSwiftFixup) RepeatCount() uint64 {
	return types.ExtractBits(uint64(c), 48, 16)
}
func (c classStableSwiftFixup) String() string {
	return fmt.Sprintf("start_vmoffset: %#x, skip_count: %d, repeat_count : %d",
		c.StartVMOffset(),
		c.SkipCount(),
		c.RepeatCount())
}

type methodListFixup uint64

func (m methodListFixup) StartVMOffset() uint64 {
	return types.ExtractBits(uint64(m), 0, 40)
}
func (m methodListFixup) SkipCount() uint64 {
	return types.ExtractBits(uint64(m), 40, 8)
}
func (m methodListFixup) RepeatCount() uint64 {
	return types.ExtractBits(uint64(m), 48, 16)
}
func (m methodListFixup) String() string {
	return fmt.Sprintf("start_vmoffset: %#x, skip_count: %d, repeat_count : %d",
		m.StartVMOffset(),
		m.SkipCount(),
		m.RepeatCount())
}

type linkKind uint32

const (
	regular  linkKind = 0
	weak     linkKind = 1
	upward   linkKind = 2
	reExport linkKind = 3
)

type linkedImage uint32

func (l linkedImage) ImgNum() uint32 {
	return uint32(types.ExtractBits(uint64(l), 0, 30))
}
func (l linkedImage) Link() linkKind {
	return linkKind(types.ExtractBits(uint64(l), 30, 2))
}
func (l linkedImage) String() string {
	return fmt.Sprintf("img_no: %d, link: %s", l.ImgNum(), l.Link())
}

type ImageArray struct {
	imageArrayType
	Offsets []uint32
}

func (i ImageArray) String() string {
	return fmt.Sprintf("%s, frst_img: %d, %s", i.T, i.FrstImageNum, i.CR)
}

type imageArrayType struct {
	T            typedBytes
	FrstImageNum uint32
	CR           countAndHasRoots
}

type typedBytes uint32

func (t typedBytes) Type() closureType {
	return closureType(types.ExtractBits(uint64(t), 0, 8))
}
func (t typedBytes) PayloadLength() uint32 {
	return uint32(types.ExtractBits(uint64(t), 8, 24))
}
func (t typedBytes) String() string {
	return fmt.Sprintf("type: %s, length: %#x, raw: %#x", t.Type(), t.PayloadLength(), uint32(t))
}

var sizeOfTypeBytes = uint32(binary.Size(typedBytes(0)))

type countAndHasRoots uint32

func (cr countAndHasRoots) Count() uint32 {
	return uint32(types.ExtractBits(uint64(cr), 0, 31))
}
func (cr countAndHasRoots) HasRoots() bool {
	return types.ExtractBits(uint64(cr), 31, 1) != 0
}
func (cr countAndHasRoots) String() string {
	return fmt.Sprintf("count: %d, has_roots: %t", cr.Count(), cr.HasRoots())
}

type lcFlags uint32

func (f lcFlags) UsedAtPaths() bool {
	return types.ExtractBits(uint64(f), 0, 16) != 0
}
func (f lcFlags) UsedFallbackPaths() bool {
	return types.ExtractBits(uint64(f), 0, 16) != 0
}
func (f lcFlags) InitImageCount() uint32 {
	return uint32(types.ExtractBits(uint64(f), 0, 16))
}
func (f lcFlags) HasInsertedLibraries() bool {
	return types.ExtractBits(uint64(f), 0, 16) != 0
}
func (f lcFlags) HasProgVars() bool {
	return types.ExtractBits(uint64(f), 0, 16) != 0
}
func (f lcFlags) UsedInterposing() bool {
	return types.ExtractBits(uint64(f), 0, 16) != 0
}
func (f lcFlags) Padding() uint32 {
	return uint32(types.ExtractBits(uint64(f), 0, 16))
}
func (f lcFlags) String() string {
	var flags []string
	if f.UsedAtPaths() {
		flags = append(flags, "@paths")
	}
	if !f.UsedFallbackPaths() {
		flags = append(flags, "fallback_paths")
	}
	if f.HasInsertedLibraries() {
		flags = append(flags, "inserted_libs")
	}
	if f.HasProgVars() {
		flags = append(flags, "prog_vars")
	}
	if f.UsedInterposing() {
		flags = append(flags, "interposing")
	}
	return fmt.Sprintf("initial_image_count: %d, flags: [%s]",
		f.InitImageCount(),
		strings.Join(flags, "|"),
	)
}

type cFlags uint64

func (f cFlags) ImageNum() uint16 {
	return uint16(types.ExtractBits(uint64(f), 0, 16))
}
func (f cFlags) MaxLoadCount() uint16 {
	return uint16(types.ExtractBits(uint64(f), 16, 12))
}
func (f cFlags) IsInvalid() bool { // IsInvalid an error occurred creating the info for this image
	return types.ExtractBits(uint64(f), 28, 1) != 0
}
func (f cFlags) Has16KbPages() bool {
	return types.ExtractBits(uint64(f), 29, 1) != 0
}
func (f cFlags) Is64() bool {
	return types.ExtractBits(uint64(f), 30, 1) != 0
}
func (f cFlags) HasObjC() bool {
	return types.ExtractBits(uint64(f), 31, 1) != 0
}
func (f cFlags) MayHavePlusLoads() bool {
	return types.ExtractBits(uint64(f), 32, 1) != 0
}
func (f cFlags) IsEncrypted() bool { // IsEncrypted image is DSMOS or FarPlay encrypted
	return types.ExtractBits(uint64(f), 33, 1) != 0
}
func (f cFlags) HasWeakDefs() bool {
	return types.ExtractBits(uint64(f), 34, 1) != 0
}
func (f cFlags) NeverUnload() bool {
	return types.ExtractBits(uint64(f), 35, 1) != 0
}
func (f cFlags) CwdSameAsThis() bool { // CwdSameAsThis dylibs use file system relative paths, cwd must be main's dr
	return types.ExtractBits(uint64(f), 36, 1) != 0
}
func (f cFlags) IsPlatformBinary() bool { // IsPlatformBinary part of OS - can be loaded into LV process
	return types.ExtractBits(uint64(f), 37, 1) != 0
}
func (f cFlags) IsBundle() bool {
	return types.ExtractBits(uint64(f), 38, 1) != 0
}
func (f cFlags) IsDylib() bool {
	return types.ExtractBits(uint64(f), 39, 1) != 0
}
func (f cFlags) IsExecutable() bool {
	return types.ExtractBits(uint64(f), 40, 1) != 0
}
func (f cFlags) OverridableDylib() bool { // OverridableDylib only applicable to cached dylibs
	return types.ExtractBits(uint64(f), 41, 1) != 0
}
func (f cFlags) InDyldCache() bool {
	return types.ExtractBits(uint64(f), 42, 1) != 0
}
func (f cFlags) HasTerminators() bool {
	return types.ExtractBits(uint64(f), 43, 1) != 0
}
func (f cFlags) HasReadOnlyData() bool {
	return types.ExtractBits(uint64(f), 44, 1) != 0
}
func (f cFlags) HasChainedFixups() bool {
	return types.ExtractBits(uint64(f), 45, 1) != 0
}
func (f cFlags) HasPrecomputedObjC() bool {
	return types.ExtractBits(uint64(f), 46, 1) != 0
}
func (f cFlags) FixupsNotEncoded() bool {
	return types.ExtractBits(uint64(f), 47, 1) != 0
}
func (f cFlags) RebasesNotEncoded() bool {
	return types.ExtractBits(uint64(f), 48, 1) != 0
}
func (f cFlags) HasOverrideImageNum() bool {
	return types.ExtractBits(uint64(f), 49, 1) != 0
}
func (f cFlags) String() string {
	var flags []string
	if f.IsInvalid() {
		flags = append(flags, "invalid")
	}
	if !f.Has16KbPages() {
		flags = append(flags, "4kb_pages")
	}
	if !f.Is64() {
		flags = append(flags, "32bit")
	}
	if f.HasObjC() {
		flags = append(flags, "objc")
	}
	if f.MayHavePlusLoads() {
		flags = append(flags, "plus_loads")
	}
	if f.IsEncrypted() {
		flags = append(flags, "encrypted")
	}
	if f.HasWeakDefs() {
		flags = append(flags, "weak_defs")
	}
	if !f.NeverUnload() {
		flags = append(flags, "can_unload")
	}
	if f.CwdSameAsThis() {
		flags = append(flags, "cwd_same_as_this")
	}
	if f.IsPlatformBinary() {
		flags = append(flags, "platform_bin")
	}
	if f.IsBundle() {
		flags = append(flags, "bundle")
	}
	if f.IsDylib() {
		flags = append(flags, "dylib")
	}
	if f.IsExecutable() {
		flags = append(flags, "exe")
	}
	if f.OverridableDylib() {
		flags = append(flags, "overridable")
	}
	if f.InDyldCache() {
		flags = append(flags, "in_cache")
	}
	if f.HasTerminators() {
		flags = append(flags, "terms")
	}
	if f.HasReadOnlyData() {
		flags = append(flags, "readonly_data")
	}
	if f.HasChainedFixups() {
		flags = append(flags, "fixups")
	}
	if f.HasPrecomputedObjC() {
		flags = append(flags, "precomp_objc")
	}
	if f.FixupsNotEncoded() {
		flags = append(flags, "fixups_not_enc")
	}
	if f.RebasesNotEncoded() {
		flags = append(flags, "rebase_not_enc")
	}
	if f.HasOverrideImageNum() {
		flags = append(flags, "override_img_no")
	}
	var max string
	if f.MaxLoadCount() > 0 {
		max = fmt.Sprintf("max_load: %d, ", f.MaxLoadCount())
	}
	return fmt.Sprintf("%s%s",
		max,
		strings.Join(flags, "|"),
	)
}

type mappingInfoType struct {
	TotalVmPages    uint32
	SliceOffsetIn4K uint32
}
type initializerSectionRangeType struct {
	SectionOffset uint32
	SectionSize   uint32
}
type codeSignatureLocationType struct {
	FileOffset uint32
	FileSize   uint32
}
type farPlayLocType struct {
	RangeStart  uint32
	RangeLength uint32
}
type fileInfoType struct {
	INode   uint64
	ModTime uint64
}

type warningType struct {
	Type    uint32
	Message []byte
}

type PatchEntry struct {
	OverriddenDylibInCache uint32
	ExportCacheOffset      uint32
	Replacement            resolvedSymbolTarget
}

type duplicateClassesHashTable struct {
	//     uint32_t capacity;
	// uint32_t occupied;
	// uint32_t shift;
	// uint32_t mask;
	// StringTarget sentinelTarget;
	// uint32_t roundedTabSize;
	// uint64_t salt;
}

// GetProgClosuresOffsets returns the closure trie data
// NOTE: this doesn't auto add the ProgClosuresAddr (and probably should)
func (f *File) GetProgClosuresOffsets() ([]trie.Node, error) {
	var addr uint64
	var size uint64

	if f.Headers[f.UUID].ProgClosuresTrieAddr == 0 {
		if f.Headers[f.UUID].ProgramTrieAddr == 0 {
			return nil, fmt.Errorf("cache does not contain prog closures trie info")
		} else {
			addr = f.Headers[f.UUID].ProgramTrieAddr
			size = uint64(f.Headers[f.UUID].ProgramTrieSize)
		}
	} else {
		addr = f.Headers[f.UUID].ProgClosuresTrieAddr
		size = f.Headers[f.UUID].ProgClosuresTrieSize
	}

	uuid, offset, err := f.GetOffset(addr)
	if err != nil {
		return nil, err
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(offset), io.SeekStart)

	progClosuresTrie := make([]byte, size)
	if err := binary.Read(sr, f.ByteOrder, &progClosuresTrie); err != nil {
		return nil, err
	}

	r := bytes.NewReader(progClosuresTrie)

	nodes, err := trie.ParseTrie(r)
	if err != nil {
		return nil, err
	}

	for idx, node := range nodes {
		r.Seek(int64(node.Offset), io.SeekStart)
		off, err := trie.ReadUleb128(r)
		if err != nil {
			return nil, err
		}
		nodes[idx].Offset = off
	}

	return nodes, nil
}

// GetProgClosureAddress returns the closure pointer for a given path
func (f *File) GetProgClosureAddress(executablePath string) (uint64, error) {

	var addr uint64
	var size uint64

	if f.Headers[f.UUID].ProgClosuresTrieAddr == 0 {
		if f.Headers[f.UUID].ProgramTrieAddr == 0 {
			return 0, fmt.Errorf("cache does not contain prog closures trie info")
		} else {
			addr = f.Headers[f.UUID].ProgramTrieAddr
			size = uint64(f.Headers[f.UUID].ProgramTrieSize)
		}
	} else {
		addr = f.Headers[f.UUID].ProgClosuresTrieAddr
		size = f.Headers[f.UUID].ProgClosuresTrieSize
	}

	uuid, offset, err := f.GetOffset(addr)
	if err != nil {
		return 0, err
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(offset), io.SeekStart)

	progClosuresTrie := make([]byte, size)
	if err := binary.Read(sr, f.ByteOrder, &progClosuresTrie); err != nil {
		return 0, err
	}

	r := bytes.NewReader(progClosuresTrie)

	if _, err = trie.WalkTrie(r, executablePath); err != nil {
		return 0, err
	}

	closureOffset, err := trie.ReadUleb128(r)
	if err != nil {
		return 0, err
	}

	return f.Headers[f.UUID].ProgClosuresAddr + closureOffset, nil
}

// GetDylibsImageArray returns the dylibs image array
func (f *File) GetProgClosureImageArray() error {
	var addr uint64
	var size uint64

	if f.IsDyld4 {
		return fmt.Errorf("dyld4 no longer uses prog closures")
	}

	if f.Headers[f.UUID].ProgClosuresAddr == 0 {
		return fmt.Errorf("cache does not contain prog launch closure info")
	} else {
		addr = f.Headers[f.UUID].ProgClosuresAddr
		size = f.Headers[f.UUID].ProgClosuresSize
	}

	u, offset, err := f.GetOffset(addr)
	if err != nil {
		return err
	}

	sr := io.NewSectionReader(f.r[u], 0, 1<<63-1)

	sr.Seek(int64(offset), io.SeekStart)

	imageArrayData := make([]byte, size)
	if err := binary.Read(sr, f.ByteOrder, &imageArrayData); err != nil {
		return err
	}

	return f.parseClosureContainers(bytes.NewReader(imageArrayData))
}

// GetDylibsImageArray returns the dylibs image array
func (f *File) GetDylibsImageArray() error {
	var addr uint64
	var size uint64

	if f.Headers[f.UUID].DylibsImageArrayAddr == 0 {
		return fmt.Errorf("cache does not contain dylibs image array info")
	} else {
		addr = f.Headers[f.UUID].DylibsImageArrayAddr
		size = f.Headers[f.UUID].DylibsImageArraySize
	}

	u, offset, err := f.GetOffset(addr)
	if err != nil {
		return err
	}

	sr := io.NewSectionReader(f.r[u], 0, 1<<63-1)

	sr.Seek(int64(offset), io.SeekStart)

	imageArrayData := make([]byte, size)
	if err := binary.Read(sr, f.ByteOrder, &imageArrayData); err != nil {
		return err
	}

	return f.parseClosureContainers(bytes.NewReader(imageArrayData))
}

func (f *File) GetDylibsImageArrayIDs() ([]trie.Node, error) {

	if f.Headers[f.UUID].DylibsTrieAddr == 0 {
		return nil, fmt.Errorf("cache does not contain dylibs trie info")
	}

	uuid, off, err := f.GetOffset(f.Headers[f.UUID].DylibsTrieAddr)
	if err != nil {
		return nil, err
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(off), io.SeekStart)

	dylibTrie := make([]byte, f.Headers[f.UUID].DylibsTrieSize)
	if err := binary.Read(sr, f.ByteOrder, &dylibTrie); err != nil {
		return nil, err
	}

	return trie.ParseTrie(bytes.NewReader(dylibTrie))
}

// GetDylibIndex returns the index of a given dylib
func (f *File) GetDylibIndex(path string) (uint64, error) {

	if f.Headers[f.UUID].DylibsTrieAddr == 0 {
		return 0, fmt.Errorf("cache does not contain dylibs trie info")
	}

	uuid, off, err := f.GetOffset(f.Headers[f.UUID].DylibsTrieAddr)
	if err != nil {
		return 0, err
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(off), io.SeekStart)

	dylibTrie := make([]byte, f.Headers[f.UUID].DylibsTrieSize)
	if err := binary.Read(sr, f.ByteOrder, &dylibTrie); err != nil {
		return 0, err
	}

	imageNode, err := trie.WalkTrie(bytes.NewReader(dylibTrie), path)
	if err != nil {
		return 0, fmt.Errorf("dylib not found in dylibs trie")
	}

	imageIndex, _, err := trie.ReadUleb128FromBuffer(bytes.NewBuffer(dylibTrie[imageNode:]))
	if err != nil {
		return 0, fmt.Errorf("failed to read ULEB at image node in dyblibs trie")
	}

	return imageIndex, nil
}

// GetDlopenOtherImageArray returns the other images array
func (f *File) GetDlopenOtherImageArray() error {
	var addr uint64
	var size uint64

	if f.Headers[f.UUID].OtherImageArrayAddr == 0 {
		return fmt.Errorf("cache does not contain other image array info")
	} else {
		addr = f.Headers[f.UUID].OtherImageArrayAddr
		size = f.Headers[f.UUID].OtherImageArraySize
	}

	u, offset, err := f.GetOffset(addr)
	if err != nil {
		return err
	}

	sr := io.NewSectionReader(f.r[u], 0, 1<<63-1)

	sr.Seek(int64(offset), io.SeekStart)

	imageArrayData := make([]byte, size)
	if err := binary.Read(sr, f.ByteOrder, &imageArrayData); err != nil {
		return err
	}

	return f.parseClosureContainers(bytes.NewReader(imageArrayData))
}

// GetDlopenOtherImages returns the dlopen other images trie data
func (f *File) GetDlopenOtherImages() ([]trie.Node, error) {

	if f.Headers[f.UUID].OtherTrieAddr == 0 {
		return nil, fmt.Errorf("cache does not contain dlopen other image trie info")
	}

	uuid, offset, err := f.GetOffset(f.Headers[f.UUID].OtherTrieAddr)
	if err != nil {
		return nil, err
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(offset), io.SeekStart)

	otherTrie := make([]byte, f.Headers[uuid].OtherTrieSize)
	if err := binary.Read(sr, f.ByteOrder, &otherTrie); err != nil {
		return nil, err
	}

	r := bytes.NewReader(otherTrie)

	nodes, err := trie.ParseTrie(r)
	if err != nil {
		return nil, err
	}

	for idx, node := range nodes {
		r.Seek(int64(node.Offset), io.SeekStart)
		index, err := trie.ReadUleb128(r)
		if err != nil {
			return nil, err
		}
		nodes[idx].Offset = index
	}

	return nodes, err
}

// GetDlopenOtherImageIndex returns the dlopen other image index for a given path
func (f *File) GetDlopenOtherImageIndex(path string) (uint64, error) {
	sr := io.NewSectionReader(f.r[f.UUID], 0, 1<<63-1)

	if f.Headers[f.UUID].OtherTrieAddr == 0 {
		return 0, fmt.Errorf("cache does not contain dlopen other image trie info")
	}

	offset, err := f.GetOffsetForUUID(f.UUID, f.Headers[f.UUID].OtherTrieAddr)
	if err != nil {
		return 0, err
	}

	sr.Seek(int64(offset), io.SeekStart)

	otherTrie := make([]byte, f.Headers[f.UUID].OtherTrieSize)
	if err := binary.Read(sr, f.ByteOrder, &otherTrie); err != nil {
		return 0, err
	}

	r := bytes.NewReader(otherTrie)

	if _, err = trie.WalkTrie(r, path); err != nil {
		return 0, fmt.Errorf("failed to walk dlopen other image trie data: %v", err)
	}

	imageNum, err := trie.ReadUleb128(r)
	if err != nil {
		return 0, fmt.Errorf("failed to read ULEB at image node in dlopen other image trie: %v", err)
	}

	return imageNum, nil
}

func (f *File) parseClosureContainers(r *bytes.Reader) error {
	var container typedBytes

	for {
		err := binary.Read(r, binary.LittleEndian, &container)

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch container.Type() {
		case launchClosure: // contains TypedBytes of closure attributes including imageArray
			dat := make([]byte, container.PayloadLength())
			if _, err := r.Read(dat); err != nil {
				return fmt.Errorf("failed to read launchClosure data: %v", err)
			}
			if err := f.parseLaunchClosure(bytes.NewReader(dat)); err != nil {
				return fmt.Errorf("failed to parse launch closure: %v", err)
			}
		case imageArray: // sizeof(ImageArray) + sizeof(uint32_t)*count + size of all images
			if _, err := r.Seek(-int64(sizeOfTypeBytes), io.SeekCurrent); err != nil {
				return fmt.Errorf("failed to rewind the reader: %v", err)
			}
			dat := make([]byte, container.PayloadLength()+sizeOfTypeBytes)
			if _, err := r.Read(dat); err != nil {
				return fmt.Errorf("failed to read imageArray data: %v", err)
			}
			cimages, err := f.parseClosureImageArray(bytes.NewReader(dat))
			if err != nil {
				return fmt.Errorf("failed to parse closure image array: %v", err)
			}
			for idx, cimg := range cimages {
				if _, ok := f.ImageArray[cimg.ID]; ok {
					return fmt.Errorf("image array map already contains image ID %d at index %d", cimg.ID, idx)
				}
				f.ImageArray[cimg.ID] = cimg
			}
		case image: // contains TypedBytes of image attributes
			panic("closure container image not implimented")
		case dlopenClosure: // contains TypedBytes of closure attributes including imageArray
			panic("closure container dlopenClosure not implimented")
		default:
			return fmt.Errorf("got unexpected cointainer type %s", container.Type())
		}
	}

	return nil
}

func (f *File) parseLaunchClosure(r *bytes.Reader) error {
	lc := &LaunchClosure{}

	var tbytes typedBytes
	for {
		err := binary.Read(r, binary.LittleEndian, &tbytes)

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch tbytes.Type() {
		case imageArray:
			if _, err := r.Seek(-int64(sizeOfTypeBytes), io.SeekCurrent); err != nil {
				return fmt.Errorf("failed to rewind the reader: %v", err)
			}
			dat := make([]byte, tbytes.PayloadLength()+sizeOfTypeBytes)
			if _, err := r.Read(dat); err != nil {
				return fmt.Errorf("failed to read imageArray data: %v", err)
			}
			cimages, err := f.parseClosureImageArray(bytes.NewReader(dat))
			if err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
			lc.Images = append(lc.Images, cimages...)
		case closureFlags: // sizeof(Closure::Flags)
			if err := binary.Read(r, binary.LittleEndian, &lc.Flags); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case dyldCacheUUID: // 16
			if err := binary.Read(r, binary.LittleEndian, &lc.DyldUUID); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case missingFiles:
			if tbytes.PayloadLength() > 0 {
				dat := make([]byte, tbytes.PayloadLength())
				if _, err := r.Read(dat); err != nil {
					return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
				}
				sr := bytes.NewBuffer(dat)
				for {
					s, err := sr.ReadString('\x00')
					if err == io.EOF {
						break
					}
					if err != nil {
						return fmt.Errorf("failed to read string: %v", err)
					}
					s = strings.Trim(s, "\x00")
					if len(s) > 0 {
						lc.MissingFiles = append(lc.MissingFiles, s)
					}
				}
			}
		case envVar: // "DYLD_BLAH=stuff"
			if tbytes.PayloadLength() > 0 {
				dat := make([]byte, tbytes.PayloadLength())
				if _, err := r.Read(dat); err != nil {
					return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
				}
				lc.EnvVars = append(lc.EnvVars, string(dat))
			}
		case topImage: // sizeof(ImageNum)
			if err := binary.Read(r, binary.LittleEndian, &lc.TopImage); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case libDyldEntry: // sizeof(ResolvedSymbolTarget)
			if err := binary.Read(r, binary.LittleEndian, &lc.LibDyldEntry); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case libSystemNum: // sizeof(ImageNum)
			if err := binary.Read(r, binary.LittleEndian, &lc.LibSystemNum); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case mainEntry: // sizeof(ResolvedSymbolTarget)
			if err := binary.Read(r, binary.LittleEndian, &lc.MainEntry); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case startEntry: // sizeof(ResolvedSymbolTarget)     // used by programs built with crt1.o
			if err := binary.Read(r, binary.LittleEndian, &lc.StartEntry); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case cacheOverrides: // sizeof(PatchEntry) * count       // used if process uses interposing or roots (cached dylib overrides)
			lc.DyldCacheFixups = make([]PatchEntry, tbytes.PayloadLength()/uint32(binary.Size(PatchEntry{})))
			if err := binary.Read(r, binary.LittleEndian, &lc.DyldCacheFixups); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		case interposeTuples: // sizeof(InterposingTuple) * count
			panic("launch closure type interposeTuples not implimented")
		case existingFiles: // uint64_t + (SkippedFiles * count)
			panic("launch closure type existingFiles not implimented")
		case selectorTable: // uint32_t + (sizeof(ObjCSelectorImage) * count) + hashTable size
			// panic("not implimented")
			// utils.Indent(log.Debug, 2)("selectorTable - Skipping") // TODO: FINISH THESE !!!! 🤬
			r.Seek(int64(tbytes.PayloadLength()), io.SeekCurrent)
		case classTable: // (3 * uint32_t) + (sizeof(ObjCClassImage) * count) + classHashTable size + protocolHashTable size
			// panic("not implimented")
			// utils.Indent(log.Debug, 2)("classTable - Skipping")
			r.Seek(int64(tbytes.PayloadLength()), io.SeekCurrent)
		case warning: // len = uint32_t + length path + 1 use one entry per warning
			var warn warningType
			if err := binary.Read(r, binary.LittleEndian, &warn.Type); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
			warn.Message = make([]byte, tbytes.PayloadLength()-uint32(binary.Size(warn.Type)))
			if err := binary.Read(r, binary.LittleEndian, &warn.Message); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
			lc.Warnings = append(lc.Warnings, warn)
		case duplicateClassesTable: // duplicateClassesHashTable
			// var s stringHash
			// if err := binary.Read(r, binary.LittleEndian, &s); err != nil {
			// 	return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			// }
			// fmt.Printf("delta: %#x\n", tbytes.PayloadLength()-uint32(binary.Size(s)))
			// fmt.Println(s)
			// panic("not implimented")
			// utils.Indent(log.Debug, 2)("duplicateClassesTable - Skipping")
			r.Seek(int64(tbytes.PayloadLength()), io.SeekCurrent)
		case progVars: // sizeof(uint32_t)
			if err := binary.Read(r, binary.LittleEndian, &lc.ProgVars); err != nil {
				return fmt.Errorf("failed to parse %s: %v", tbytes.Type(), err)
			}
		default:
			return fmt.Errorf("found unsupported launch closure type %s", tbytes.Type())
		}
	}

	f.Closures = append(f.Closures, lc)

	return nil
}

func (f *File) parseClosureImageArray(r *bytes.Reader) ([]*CImage, error) {
	var itype typedBytes
	var iarray ImageArray
	var cimages []*CImage

	if err := binary.Read(r, binary.LittleEndian, &iarray.imageArrayType); err != nil {
		return nil, err
	}

	iarray.Offsets = make([]uint32, iarray.CR.Count())
	if err := binary.Read(r, binary.LittleEndian, &iarray.Offsets); err != nil {
		return nil, err
	}

	for i := uint32(0); i < iarray.CR.Count(); i++ {
		if err := binary.Read(r, binary.LittleEndian, &itype); err != nil {
			return nil, err
		}

		if itype.Type() != image {
			return nil, fmt.Errorf("got unexpected type %s; expected image", itype.Type())
		}

		dat := make([]byte, itype.PayloadLength())
		if _, err := r.Read(dat); err != nil {
			return nil, fmt.Errorf("failed to read image data: %v", err)
		}

		ci, err := parseClosureImage(bytes.NewReader(dat))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %v", itype, err)
		}

		if ci.ID != 0 { // TODO: why do these zeroed out images exist?
			cimages = append(cimages, ci)
		}
	}

	return cimages, nil
}

func parseClosureImage(r *bytes.Reader) (*CImage, error) {
	var tbytes typedBytes

	ci := &CImage{}

	for { // parse image
		err := binary.Read(r, binary.LittleEndian, &tbytes)

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		switch tbytes.Type() {
		case imageFlags:
			if err := binary.Read(r, binary.LittleEndian, &ci.Flags); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
			ci.ID = ci.GetID()
		case pathWithHash:
			if err := binary.Read(r, binary.LittleEndian, &ci.Hash); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
			dat := make([]byte, tbytes.PayloadLength()-uint32(binary.Size(uint32(0))))
			if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
			ci.Name = strings.Trim(string(dat), "\x00")
		case fileInodeAndTime:
			if err := binary.Read(r, binary.LittleEndian, &ci.FileInfo); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case cdHash:
			if tbytes.PayloadLength() != 20 {
				return nil, fmt.Errorf("found unexpected cdhash of length %d; expected 20", tbytes.PayloadLength())
			}
			ci.CDHash = make([]byte, tbytes.PayloadLength())
			if err := binary.Read(r, binary.LittleEndian, &ci.CDHash); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case uuid:
			if err := binary.Read(r, binary.LittleEndian, &ci.UUID); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case mappingInfo:
			if err := binary.Read(r, binary.LittleEndian, &ci.MappingInfo); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case diskSegment:
			ci.DiskSegments = make([]diskSegmentType, tbytes.PayloadLength()/uint32(binary.Size(diskSegmentType(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.DiskSegments); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case cacheSegment:
			ci.CacheSegments = make([]cacheSegmentType, tbytes.PayloadLength()/uint32(binary.Size(cacheSegmentType(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.CacheSegments); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case dependents:
			ci.Dependents = make([]linkedImage, tbytes.PayloadLength()/uint32(binary.Size(linkedImage(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.Dependents); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case initOffsets:
			ci.InitializerOffsets = make([]uint32, tbytes.PayloadLength()/uint32(binary.Size(uint32(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.InitializerOffsets); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case dofOffsets:
			ci.DofOffsets = make([]uint32, tbytes.PayloadLength()/uint32(binary.Size(uint32(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.DofOffsets); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case codeSignLoc:
			if err := binary.Read(r, binary.LittleEndian, &ci.CodeSignatureLocation); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case farPlayLoc:
			if err := binary.Read(r, binary.LittleEndian, &ci.FarPlayLocation); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case rebaseFixups:
			ci.Rebases = make([]rebasePatternType, tbytes.PayloadLength()/uint32(binary.Size(rebasePatternType(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.Rebases); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case bindFixups:
			ci.Binds = make([]BindPattern, tbytes.PayloadLength()/uint32(binary.Size(BindPattern{})))
			if err := binary.Read(r, binary.LittleEndian, &ci.Binds); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case cachePatchInfo:
			return nil, fmt.Errorf("found deprecated type %s", tbytes.Type())
		case textFixups:
			ci.TextFixups = make([]TextFixupPattern, tbytes.PayloadLength()/uint32(binary.Size(TextFixupPattern{})))
			if err := binary.Read(r, binary.LittleEndian, &ci.TextFixups); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case imageOverride:
			if err := binary.Read(r, binary.LittleEndian, &ci.ImageOverride); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case initBefores:
			ci.InitOrder = make([]uint32, tbytes.PayloadLength()/uint32(binary.Size(uint32(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.InitOrder); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case initsSection:
			ci.InitializerSections = make([]initializerSectionRangeType, tbytes.PayloadLength()/uint32(binary.Size(initializerSectionRangeType{})))
			if err := binary.Read(r, binary.LittleEndian, &ci.InitializerSections); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case chainedFixupsTargets:
			ci.ChainedFixupsTargets = make([]resolvedSymbolTarget, tbytes.PayloadLength()/uint32(binary.Size(resolvedSymbolTarget(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.ChainedFixupsTargets); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case termOffsets:
			ci.TerminatorOffsets = make([]uint32, tbytes.PayloadLength()/uint32(binary.Size(uint32(0))))
			if err := binary.Read(r, binary.LittleEndian, &ci.TerminatorOffsets); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case chainedStartsOffset:
			if err := binary.Read(r, binary.LittleEndian, &ci.ChainedStartsOffset); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
		case objcFixups:
			contentSize := int(tbytes.PayloadLength())
			if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.objcFixupsType); err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
			}
			contentSize -= binary.Size(objcFixupsType{})
			if ci.ObjcFixups.ProtocolFixupCount > 0 {
				ci.ObjcFixups.ProtocolISAFixups = make([]protocolISAFixup, ci.ObjcFixups.ProtocolFixupCount)
				if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.ProtocolISAFixups); err != nil {
					return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
				}
				contentSize -= binary.Size(ci.ObjcFixups.ProtocolISAFixups)
			}
			if ci.ObjcFixups.SelRefFixupCount > 0 {
				ci.ObjcFixups.SelRefFixups = make([]SelectorReferenceFixup, ci.ObjcFixups.SelRefFixupCount)
				if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.SelRefFixups); err != nil {
					return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
				}
				contentSize -= binary.Size(ci.ObjcFixups.SelRefFixups)
			}
			if contentSize > 0 {
				if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.StableSwiftFixupCount); err != nil {
					return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
				}
				if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.MethodListFixupCount); err != nil {
					return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
				}
				if ci.ObjcFixups.StableSwiftFixupCount > 0 {
					ci.ObjcFixups.ClassStableSwiftFixups = make([]classStableSwiftFixup, ci.ObjcFixups.StableSwiftFixupCount)
					if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.ClassStableSwiftFixups); err != nil {
						return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
					}
				}
				if ci.ObjcFixups.MethodListFixupCount > 0 {
					ci.ObjcFixups.MethodListFixups = make([]methodListFixup, ci.ObjcFixups.MethodListFixupCount)
					if err := binary.Read(r, binary.LittleEndian, &ci.ObjcFixups.MethodListFixups); err != nil {
						return nil, fmt.Errorf("failed to parse %s: %v", tbytes, err)
					}
				}
			}
		default:
			return nil, fmt.Errorf("found unsupported type %s", tbytes.Type())
		}
	}

	return ci, nil
}
