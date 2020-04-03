package types

import (
	"encoding/binary"
	"fmt"
)

// A LoadCmd is a Mach-O load command.
type LoadCmd uint32

func (c LoadCmd) Command() LoadCmd { return c }

func (c LoadCmd) Put(b []byte, o binary.ByteOrder) int {
	panic(fmt.Sprintf("Put not implemented for %s", c.String()))
}

const (
	LcReqDyld       LoadCmd = 0x80000000
	LcSegment       LoadCmd = 0x1  // segment of this file to be mapped
	LcSymtab        LoadCmd = 0x2  // link-edit stab symbol table info
	LcSymseg        LoadCmd = 0x3  // link-edit gdb symbol table info (obsolete)
	LcThread        LoadCmd = 0x4  // thread
	LcUnixThread    LoadCmd = 0x5  // thread+stack
	LcLoadfvmlib    LoadCmd = 0x6  // load a specified fixed VM shared library
	LcIdfvmlib      LoadCmd = 0x7  // fixed VM shared library identification
	LcIdent         LoadCmd = 0x8  // object identification info (obsolete)
	LcFvmfile       LoadCmd = 0x9  // fixed VM file inclusion (internal use)
	LcPrepage       LoadCmd = 0xa  // prepage command (internal use)
	LcDysymtab      LoadCmd = 0xb  // dynamic link-edit symbol table info
	LcDylib         LoadCmd = 0xc  // load dylib command
	LcDylibID       LoadCmd = 0xd  // id dylib command
	LcDylinker      LoadCmd = 0xe  // load a dynamic linker
	LcDylinkerID    LoadCmd = 0xf  // id dylinker command (not load dylinker command)
	LcPreboundDylib LoadCmd = 0x10 // modules prebound for a dynamically linked shared library
	LcRoutines      LoadCmd = 0x11 // image routines
	LcSubFramework  LoadCmd = 0x12 // sub framework
	LcSubUmbrella   LoadCmd = 0x13 // sub umbrella
	LcSubClient     LoadCmd = 0x14 // sub client
	LcSubLibrary    LoadCmd = 0x15 // sub library
	LcTwolevelHints LoadCmd = 0x16 // two-level namespace lookup hints
	LcPrebindCksum  LoadCmd = 0x17 // prebind checksum
	/*
	 * load a dynamically linked shared library that is allowed to be missing
	 * (all symbols are weak imported).
	 */
	LcLoadWeakDylib          LoadCmd = (0x18 | LcReqDyld)
	LcSegment64              LoadCmd = 0x19               // 64-bit segment of this file to be mapped
	LcRoutines64             LoadCmd = 0x1a               // 64-bit image routines
	LcUUID                   LoadCmd = 0x1b               // the uuid
	LcRpath                  LoadCmd = (0x1c | LcReqDyld) // runpath additions
	LcCodeSignature          LoadCmd = 0x1d               // local of code signature
	LcSegmentSplitInfo       LoadCmd = 0x1e               // local of info to split segments
	LcReexportDylib          LoadCmd = (0x1f | LcReqDyld) // load and re-export dylib
	LcLazyLoadDylib          LoadCmd = 0x20               // delay load of dylib until first use
	LcEncryptionInfo         LoadCmd = 0x21               // encrypted segment information
	LcDyldInfo               LoadCmd = 0x22               // compressed dyld information
	LcDyldInfoOnly           LoadCmd = (0x22 | LcReqDyld) // compressed dyld information only
	LcLoadUpwardDylib        LoadCmd = (0x23 | LcReqDyld) // load upward dylib
	LcVersionMinMacosx       LoadCmd = 0x24               // build for MacOSX min OS version
	LcVersionMinIphoneos     LoadCmd = 0x25               // build for iPhoneOS min OS version
	LcFunctionStarts         LoadCmd = 0x26               // compressed table of function start addresses
	LcDyldEnvironment        LoadCmd = 0x27               // string for dyld to treat like environment variable
	LcMain                   LoadCmd = (0x28 | LcReqDyld) // replacement for LC_UNIXTHREAD
	LcDataInCode             LoadCmd = 0x29               // table of non-instructions in __text
	LcSourceVersion          LoadCmd = 0x2A               // source version used to build binary
	LcDylibCodeSignDrs       LoadCmd = 0x2B               // Code signing DRs copied from linked dylibs
	LcEncryptionInfo64       LoadCmd = 0x2C               // 64-bit encrypted segment information
	LcLinkerOption           LoadCmd = 0x2D               // linker options in MH_OBJECT files
	LcLinkerOptimizationHint LoadCmd = 0x2E               // optimization hints in MH_OBJECT files
	LcVersionMinTvos         LoadCmd = 0x2F               // build for AppleTV min OS version
	LcVersionMinWatchos      LoadCmd = 0x30               // build for Watch min OS version
	LcNote                   LoadCmd = 0x31               // arbitrary data included within a Mach-O file
	LcBuildVersion           LoadCmd = 0x32               // build for platform min OS version
	LcDyldExportsTrie        LoadCmd = (0x33 | LcReqDyld) // used with linkedit_data_command, payload is trie
	LcDyldChainedFixups      LoadCmd = (0x34 | LcReqDyld) // used with linkedit_data_command
)

var cmdStrings = []intName{
	{uint32(LcSegment), "LoadCmdSegment"},
	{uint32(LcSymtab), "LoadCmdSymtab"},
	{uint32(LcSymseg), "LoadCmdSymseg"},
	{uint32(LcThread), "LoadCmdThread"},
	{uint32(LcUnixThread), "LoadCmdUnixThread"},
	{uint32(LcLoadfvmlib), "LoadCmdLoadfvmlib"},
	{uint32(LcIdfvmlib), "LoadCmdIdfvmlib"},
	{uint32(LcIdent), "LoadCmdIdent"},
	{uint32(LcFvmfile), "LoadCmdFvmfile"},
	{uint32(LcPrepage), "LoadCmdPrepage"},
	{uint32(LcDysymtab), "LoadCmdDysymtab"},
	{uint32(LcDylib), "LoadCmdDylib"},
	{uint32(LcDylibID), "LoadCmdDylibID"},
	{uint32(LcDylinker), "LoadCmdDylinker"},
	{uint32(LcPreboundDylib), "LoadCmdPreboundDylib"},
	{uint32(LcRoutines), "LoadCmdRoutines"},
	{uint32(LcSubFramework), "LoadCmdSubFramework"},
	{uint32(LcSubUmbrella), "LoadCmdSubUmbrella"},
	{uint32(LcSubClient), "LoadCmdSubClient"},
	{uint32(LcSubLibrary), "LoadCmdSubLibrary"},
	{uint32(LcTwolevelHints), "LoadCmdTwolevelHints"},
	{uint32(LcPrebindCksum), "LoadCmdPrebindCksum"},
	{uint32(LcLoadWeakDylib), "LoadCmdLoadWeakDylib"},
	{uint32(LcSegment64), "LoadCmdSegment64"},
	{uint32(LcRoutines64), "LoadCmdRoutines64"},
	{uint32(LcUUID), "LoadCmdUUID"},
	{uint32(LcRpath), "LoadCmdRpath"},
	{uint32(LcCodeSignature), "LoadCmdCodeSignature"},
	{uint32(LcSegmentSplitInfo), "LoadCmdSegmentSplitInfo"},
	{uint32(LcReexportDylib), "LoadCmdReexportDylib"},
	{uint32(LcLazyLoadDylib), "LoadCmdLazyLoadDylib"},
	{uint32(LcEncryptionInfo), "LoadCmdEncryptionInfo"},
	{uint32(LcDyldInfo), "LoadCmdDyldInfo"},
	{uint32(LcDyldInfoOnly), "LoadCmdDyldInfoOnly"},
	{uint32(LcLoadUpwardDylib), "LoadCmdLoadUpwardDylib"},
	{uint32(LcVersionMinMacosx), "LoadCmdVersionMinMacosx"},
	{uint32(LcVersionMinIphoneos), "LoadCmdVersionMinIphoneos"},
	{uint32(LcFunctionStarts), "LoadCmdFunctionStarts"},
	{uint32(LcDyldEnvironment), "LoadCmdDyldEnvironment"},
	{uint32(LcMain), "LoadCmdMain"},
	{uint32(LcDataInCode), "LoadCmdDataInCode"},
	{uint32(LcSourceVersion), "LoadCmdSourceVersion"},
	{uint32(LcDylibCodeSignDrs), "LoadCmdDylibCodeSignDrs"},
	{uint32(LcEncryptionInfo64), "LoadCmdEncryptionInfo64"},
	{uint32(LcLinkerOption), "LoadCmdLinkerOption"},
	{uint32(LcLinkerOptimizationHint), "LoadCmdLinkerOptimizationHint"},
	{uint32(LcVersionMinTvos), "LoadCmdVersionMinTvos"},
	{uint32(LcVersionMinWatchos), "LoadCmdVersionMinWatchos"},
	{uint32(LcNote), "LoadCmdNote"},
	{uint32(LcBuildVersion), "LoadCmdBuildVersion"},
	{uint32(LcDyldExportsTrie), "LoadCmdDyldExportsTrie"},
	{uint32(LcDyldChainedFixups), "LoadCmdDyldChainedFixups"},
}

func (i LoadCmd) String() string   { return stringName(uint32(i), cmdStrings, false) }
func (i LoadCmd) GoString() string { return stringName(uint32(i), cmdStrings, true) }

type SegFlag uint32

/* Constants for the flags field of the segment_command */
const (
	HighVM SegFlag = 0x1 /* the file contents for this segment is for
	   the high part of the VM space, the low part
	   is zero filled (for stacks in core files) */
	FvmLib SegFlag = 0x2 /* this segment is the VM that is allocated by
	   a fixed VM library, for overlap checking in
	   the link editor */
	NoReLoc SegFlag = 0x4 /* this segment has nothing that was relocated
	   in it and nothing relocated to it, that is
	   it maybe safely replaced without relocation*/
	ProtectedVersion1 SegFlag = 0x8 /* This segment is protected.  If the
	   segment starts at file offset 0, the
	   first page of the segment is not
	   protected.  All other pages of the
	   segment are protected. */
	ReadOnly SegFlag = 0x10 /* This segment is made read-only after fixups */
)

// A Segment32 is a 32-bit Mach-O segment load command.
type Segment32 struct {
	LoadCmd              /* LC_SEGMENT */
	Len     uint32       /* includes sizeof section structs */
	Name    [16]byte     /* segment name */
	Addr    uint32       /* memory address of this segment */
	Memsz   uint32       /* memory size of this segment */
	Offset  uint32       /* file offset of this segment */
	Filesz  uint32       /* amount to map from the file */
	Maxprot VmProtection /* maximum VM protection */
	Prot    VmProtection /* initial VM protection */
	Nsect   uint32       /* number of sections in segment */
	Flag    SegFlag      /* flags */
}

// A SymtabCmd is a Mach-O symbol table command.
type SymtabCmd struct {
	LoadCmd // LC_SYMTAB
	Len     uint32
	Symoff  uint32
	Nsyms   uint32
	Stroff  uint32
	Strsize uint32
}

/*
 * The symseg_command contains the offset and size of the GNU style
 * symbol table information as described in the header file <symseg.h>.
 * The symbol roots of the symbol segments must also be aligned properly
 * in the file.  So the requirement of keeping the offsets aligned to a
 * multiple of a 4 bytes translates to the length field of the symbol
 * roots also being a multiple of a long.  Also the padding must again be
 * zeroed. (THIS IS OBSOLETE and no longer supported).
 */
type SymsegCommand struct {
	LoadCmd        /* LC_SYMSEG */
	Len     uint32 /* sizeof(struct symseg_command) */
	Offset  uint32 /* symbol segment offset */
	Size    uint32 /* symbol segment size in bytes */
}

// A Thread is a Mach-O thread state command.
type Thread struct {
	LoadCmd // LC_THREAD
	Len     uint32
	Type    uint32
	Data    []uint32
}

// A UnixThreadCmd is a Mach-O unix thread command.
type UnixThreadCmd struct {
	LoadCmd // LC_UNIXTHREAD
	Len     uint32
}

// A LoadFvmLibCmd is a Mach-O load a specified fixed VM shared library command.
type LoadFvmLibCmd struct {
	LoadCmd      // LC_IDFVMLIB or LC_LOADFVMLIB
	Len          uint32
	Name         uint32 // library's target pathname
	MinorVersion uint32
	HeaderAddr   uint32
}

// A IDFvmLibCmd is a Mach-O fixed VM shared library identification command.
type IDFvmLibCmd LoadFvmLibCmd // LC_IDFVMLIB
// A IdentCmd is a Mach-O object identification info (obsolete)  command.
type IdentCmd struct {
	LoadCmd // LC_IDENT
	Len     uint32
}

// A FvmFileCmd is a Mach-O fixed VM file inclusion (internal use) command.
type FvmFileCmd struct {
	LoadCmd    // LC_FVMFILE
	Len        uint32
	Name       uint32 // files pathname
	HeaderAddr uint32 // files virtual address
}

// A PrePageCmd is a Mach-O prepage command (internal use) command.
type PrePageCmd interface{} // LC_PREPAGE
// A DysymtabCmd is a Mach-O dynamic symbol table command.
type DysymtabCmd struct {
	LoadCmd        // LC_DYSYMTAB
	Len            uint32
	Ilocalsym      uint32
	Nlocalsym      uint32
	Iextdefsym     uint32
	Nextdefsym     uint32
	Iundefsym      uint32
	Nundefsym      uint32
	Tocoffset      uint32
	Ntoc           uint32
	Modtaboff      uint32
	Nmodtab        uint32
	Extrefsymoff   uint32
	Nextrefsyms    uint32
	Indirectsymoff uint32
	Nindirectsyms  uint32
	Extreloff      uint32
	Nextrel        uint32
	Locreloff      uint32
	Nlocrel        uint32
}

// A DylibCmd is a Mach-O load dynamic library command.
// LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,LC_REEXPORT_DYLIB
type DylibCmd struct {
	LoadCmd        // LC_LOAD_DYLIB
	Len            uint32
	Name           uint32
	Time           uint32
	CurrentVersion Version
	CompatVersion  Version
}

// A DylibID represents a Mach-O load dynamic library ident command.
type DylibID DylibCmd // LC_ID_DYLIB
// A DylinkerCmd is a Mach-O dynamic load a dynamic linker command.
type DylinkerCmd struct {
	Cmd  LoadCmd // LC_LOAD_DYLINKER
	Len  uint32
	Name uint32 // dynamic linker's path name
}

// A DylinkerIDCmd is a Mach-O dynamic linker identification command.
type DylinkerIDCmd DylinkerCmd // LC_ID_DYLINKER
// PreboundDylibCmd are modules prebound for a dynamically linked shared library
type PreboundDylibCmd struct {
	LoadCmd       // LC_PREBOUND_DYLIB
	Len           uint32
	Name          uint32 // library's path name
	NumModules    uint32 // number of modules in library
	LinkedModules uint32 // bit vector of linked modules
}

// A RoutinesCmd is a Mach-O image routines command.
type RoutinesCmd struct {
	LoadCmd     // LC_ROUTINES
	Len         uint32
	InitAddress uint32
	InitModule  uint32
	Reserved1   uint32
	Reserved2   uint32
	Reserved3   uint32
	Reserved4   uint32
	Reserved5   uint32
	Reserved6   uint32
}

// A SubFrameworkCmd is a Mach-O dynamic sub_framework_command.
type SubFrameworkCmd struct {
	LoadCmd   // LC_SUB_FRAMEWORK
	Len       uint32
	Framework uint32
}

// A SubUmbrellaCmd is a Mach-O dynamic sub_umbrella_command.
type SubUmbrellaCmd struct {
	LoadCmd  // LC_SUB_UMBRELLA
	Len      uint32
	Umbrella uint32
}

// A SubClientCmd is a Mach-O dynamic sub client command.
type SubClientCmd struct {
	LoadCmd // LC_SUB_CLIENT
	Len     uint32
	Client  uint32
}

// A SubLibraryCmd is a Mach-O dynamic sub_library_command.
type SubLibraryCmd struct {
	LoadCmd // LC_SUB_LIBRARY
	Len     uint32
	Library uint32
}

// A TwolevelHintsCmd is a Mach-O two-level namespace lookup hints command.
type TwolevelHintsCmd struct {
	LoadCmd  // LC_TWOLEVEL_HINTS
	Len      uint32
	Offset   uint32
	NumHints uint32
}

// A PrebindCksumCmd is a Mach-O prebind checksum command.
type PrebindCksumCmd struct {
	LoadCmd  // LC_PREBIND_CKSUM
	Len      uint32
	CheckSum uint32
}

// A WeakDylibCmd is a Mach-O load a dynamically linked shared library that is allowed to be missing
// (all symbols are weak imported) command.
type WeakDylibCmd DylibCmd // LC_LOAD_WEAK_DYLIB
// A Segment64 is a 64-bit Mach-O segment load command.
type Segment64 struct {
	LoadCmd              /* LC_SEGMENT_64 */
	Len     uint32       /* includes sizeof section_64 structs */
	Name    [16]byte     /* segment name */
	Addr    uint64       /* memory address of this segment */
	Memsz   uint64       /* memory size of this segment */
	Offset  uint64       /* file offset of this segment */
	Filesz  uint64       /* amount to map from the file */
	Maxprot VmProtection /* maximum VM protection */
	Prot    VmProtection /* initial VM protection */
	Nsect   uint32       /* number of sections in segment */
	Flag    SegFlag      /* flags */
}

// A Routines64Cmd is a Mach-O 64-bit image routines command.
type Routines64Cmd struct {
	LoadCmd     // LC_ROUTINES_64
	Len         uint32
	InitAddress uint64
	InitModule  uint64
	Reserved1   uint64
	Reserved2   uint64
	Reserved3   uint64
	Reserved4   uint64
	Reserved5   uint64
	Reserved6   uint64
}

// A UUIDCmd is a Mach-O uuid load command contains a single
// 128-bit unique random number that identifies an object produced
// by the static link editor.
type UUIDCmd struct {
	LoadCmd // LC_UUID
	Len     uint32
	UUID    UUID
}

// A RpathCmd is a Mach-O rpath command.
type RpathCmd struct {
	LoadCmd // LC_RPATH
	Len     uint32
	Path    uint32
}

// A LinkEditDataCmd is a Mach-O linkedit data command.
type LinkEditDataCmd struct {
	LoadCmd
	Len    uint32
	Offset uint32
	Size   uint32
}

// A CodeSignatureCmd is a Mach-O code signature command.
type CodeSignatureCmd LinkEditDataCmd // LC_CODE_SIGNATURE
// A SegmentSplitInfoCmd is a Mach-O code info to split segments command.
type SegmentSplitInfoCmd LinkEditDataCmd // LC_SEGMENT_SPLIT_INFO
// A ReExportDylibCmd is a Mach-O load and re-export dylib command.
type ReExportDylibCmd DylibCmd // LC_REEXPORT_DYLIB
// A LazyLoadDylibCmd is a Mach-O delay load of dylib until first use command.
type LazyLoadDylibCmd DylibCmd // LC_LAZY_LOAD_DYLIB
// A EncryptionInfoCmd is a Mach-O encrypted segment information command.
type EncryptionInfoCmd struct {
	LoadCmd // LC_ENCRYPTION_INFO
	Len     uint32
	Offset  uint32 // file offset of encrypted range
	Size    uint32 // file size of encrypted range
	CryptID uint32 // which enryption system, 0 means not-encrypted yet
}

// A DyldInfoCmd is a Mach-O id dyld info command.
type DyldInfoCmd struct {
	LoadCmd      // LC_DYLD_INFO
	Len          uint32
	RebaseOff    uint32 // file offset to rebase info
	RebaseSize   uint32 //  size of rebase info
	BindOff      uint32 // file offset to binding info
	BindSize     uint32 // size of binding info
	WeakBindOff  uint32 // file offset to weak binding info
	WeakBindSize uint32 //  size of weak binding info
	LazyBindOff  uint32 // file offset to lazy binding info
	LazyBindSize uint32 //  size of lazy binding info
	ExportOff    uint32 // file offset to export info
	ExportSize   uint32 //  size of export info
}

// A DyldInfoOnlyCmd is a Mach-O compressed dyld information only command.
type DyldInfoOnlyCmd DyldInfoCmd // LC_DYLD_INFO_ONLY
// A UpwardDylibCmd is a Mach-O load upward dylibcommand.
type UpwardDylibCmd DylibCmd // LC_LOAD_UPWARD_DYLIB
// A VersionMinCmd is a Mach-O version min command.
type VersionMinCmd struct {
	LoadCmd
	Len     uint32
	Version Version
	Sdk     Version
}

// A VersionMinMacOSCmd is a Mach-O build for macOS min OS version command.
type VersionMinMacOSCmd VersionMinCmd // LC_VERSION_MIN_MACOSX
// A VersionMinIPhoneOSCmd is a Mach-O build for iPhoneOS min OS version command.
type VersionMinIPhoneOSCmd VersionMinCmd // LC_VERSION_MIN_IPHONEOS
// A FunctionStartsCmd is a Mach-O compressed table of function start addresses command.
type FunctionStartsCmd LinkEditDataCmd // LC_FUNCTION_STARTS
// A DyldEnvironmentCmd is a Mach-O string for dyld to treat like environment variable command.
type DyldEnvironmentCmd DylinkerCmd // LC_DYLD_ENVIRONMENT
// A EntryPointCmd is a Mach-O main command.
type EntryPointCmd struct {
	LoadCmd          // LC_MAIN only used in MH_EXECUTE filetypes
	Len       uint32 // 24
	Offset    uint64 // file (__TEXT) offset of main()
	StackSize uint64 // if not zero, initial stack size
}

// A DataInCodeCmd is a Mach-O data in code command.
type DataInCodeCmd LinkEditDataCmd // LC_DATA_IN_CODE
// A SourceVersionCmd is a Mach-O source version command.
type SourceVersionCmd struct {
	LoadCmd // LC_SOURCE_VERSION
	Len     uint32
	Version SrcVersion // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

// A DylibCodeSignDrsCmd is a Mach-O code signing DRs copied from linked dylibs command.
type DylibCodeSignDrsCmd LinkEditDataCmd // LC_DYLIB_CODE_SIGN_DRS
// A EncryptionInfo64Cmd is a Mach-O 64-bit encrypted segment information command.
type EncryptionInfo64Cmd struct {
	LoadCmd // LC_ENCRYPTION_INFO_64
	Len     uint32
	Offset  uint32 // file offset of encrypted range
	Size    uint32 // file size of encrypted range
	CryptID uint32 // which enryption system, 0 means not-encrypted yet
	Pad     uint32 // padding to make this struct's size a multiple of 8 bytes
}

// A LinkerOptionCmd is a Mach-O main command.
type LinkerOptionCmd struct {
	LoadCmd // LC_LINKER_OPTION only used in MH_OBJECT filetypes
	Len     uint32
	Count   uint32 // number of strings concatenation of zero terminated UTF8 strings. Zero filled at end to align
}

// A LinkerOptimizationHintCmd is a Mach-O optimization hints command.
type LinkerOptimizationHintCmd LinkEditDataCmd // LC_LINKER_OPTIMIZATION_HINT
// A VersionMinTvOSCmd is a Mach-O build for tvOS min OS version command.
type VersionMinTvOSCmd VersionMinCmd // LC_VERSION_MIN_TVOS
// A VersionMinWatchOSCmd is a Mach-O build for watchOS min OS version command.
type VersionMinWatchOSCmd VersionMinCmd // LC_VERSION_MIN_WATCHOS
// A NoteCmd is a Mach-O note command.
type NoteCmd struct {
	LoadCmd   // LC_NOTE
	Len       uint32
	DataOwner [16]byte
	Offset    uint64
	Size      uint64
}

/*
* The build_version_command contains the min OS version on which this
* binary was built to run for its platform.  The list of known platforms and
* tool values following it.
 */
type BuildVersionCmd struct {
	LoadCmd        /* LC_BUILD_VERSION */
	Len     uint32 /* sizeof(struct build_version_command) plus */
	/* ntools * sizeof(struct build_tool_version) */
	Platform Platform /* platform */
	Minos    Version  /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
	Sdk      Version  /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
	NumTools uint32   /* number of tool entries following this */
}

// A DyldExportsTrieCmd is used with linkedit_data_command, payload is trie command.
type DyldExportsTrieCmd LinkEditDataCmd // LC_DYLD_EXPORTS_TRIE
// A DyldChainedFixupsCmd is used with linkedit_data_command command.
type DyldChainedFixupsCmd LinkEditDataCmd // LC_DYLD_CHAINED_FIXUPS
