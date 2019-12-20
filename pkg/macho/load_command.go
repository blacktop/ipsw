package macho

import (
	"encoding/binary"
	"fmt"
)

// A LoadCmd is a Mach-O load command.
type LoadCmd uint32

const (
	LoadCmdReqDyld       LoadCmd = 0x80000000
	LoadCmdSegment       LoadCmd = 0x1  // segment of this file to be mapped
	LoadCmdSymtab        LoadCmd = 0x2  // link-edit stab symbol table info
	LoadCmdSymseg        LoadCmd = 0x3  // link-edit gdb symbol table info (obsolete)
	LoadCmdThread        LoadCmd = 0x4  // thread
	LoadCmdUnixThread    LoadCmd = 0x5  // thread+stack
	LoadCmdLoadfvmlib    LoadCmd = 0x6  // load a specified fixed VM shared library
	LoadCmdIdfvmlib      LoadCmd = 0x7  // fixed VM shared library identification
	LoadCmdIdent         LoadCmd = 0x8  // object identification info (obsolete)
	LoadCmdFvmfile       LoadCmd = 0x9  // fixed VM file inclusion (internal use)
	LoadCmdPrepage       LoadCmd = 0xa  // prepage command (internal use)
	LoadCmdDysymtab      LoadCmd = 0xb  // dynamic link-edit symbol table info
	LoadCmdDylib         LoadCmd = 0xc  // load dylib command
	LoadCmdDylibID       LoadCmd = 0xd  // id dylib command
	LoadCmdDylinker      LoadCmd = 0xf  // id dylinker command (not load dylinker command)
	LoadCmdPreboundDylib LoadCmd = 0x10 // modules prebound for a dynamically linked shared library
	LoadCmdRoutines      LoadCmd = 0x11 // image routines
	LoadCmdSubFramework  LoadCmd = 0x12 // sub framework
	LoadCmdSubUmbrella   LoadCmd = 0x13 // sub umbrella
	LoadCmdSubClient     LoadCmd = 0x14 // sub client
	LoadCmdSubLibrary    LoadCmd = 0x15 // sub library
	LoadCmdTwolevelHints LoadCmd = 0x16 // two-level namespace lookup hints
	LoadCmdPrebindCksum  LoadCmd = 0x17 // prebind checksum
	/*
	 * load a dynamically linked shared library that is allowed to be missing
	 * (all symbols are weak imported).
	 */
	LoadCmdLoadWeakDylib          LoadCmd = (0x18 | LoadCmdReqDyld)
	LoadCmdSegment64              LoadCmd = 0x19                    // 64-bit segment of this file to be mapped
	LoadCmdRoutines64             LoadCmd = 0x1a                    // 64-bit image routines
	LoadCmdUUID                   LoadCmd = 0x1b                    // the uuid
	LoadCmdRpath                  LoadCmd = 0x1c | LoadCmdReqDyld   // runpath additions
	LoadCmdCodeSignature          LoadCmd = 0x1d                    // local of code signature
	LoadCmdSegmentSplitInfo       LoadCmd = 0x1e                    // local of info to split segments
	LoadCmdReexportDylib          LoadCmd = (0x1f | LoadCmdReqDyld) // load and re-export dylib
	LoadCmdLazyLoadDylib          LoadCmd = 0x20                    // delay load of dylib until first use
	LoadCmdEncryptionInfo         LoadCmd = 0x21                    // encrypted segment information
	LoadCmdDyldInfo               LoadCmd = 0x22                    // compressed dyld information
	LoadCmdDyldInfoOnly           LoadCmd = (0x22 | LoadCmdReqDyld) // compressed dyld information only
	LoadCmdLoadUpwardDylib        LoadCmd = (0x23 | LoadCmdReqDyld) // load upward dylib
	LoadCmdVersionMinMacosx       LoadCmd = 0x24                    // build for MacOSX min OS version
	LoadCmdVersionMinIphoneos     LoadCmd = 0x25                    // build for iPhoneOS min OS version
	LoadCmdFunctionStarts         LoadCmd = 0x26                    // compressed table of function start addresses
	LoadCmdDyldEnvironment        LoadCmd = 0x27                    // string for dyld to treat like environment variable
	LoadCmdMain                   LoadCmd = (0x28 | LoadCmdReqDyld) // replacement for LC_UNIXTHREAD
	LoadCmdDataInCode             LoadCmd = 0x29                    // table of non-instructions in __text
	LoadCmdSourceVersion          LoadCmd = 0x2A                    // source version used to build binary
	LoadCmdDylibCodeSignDrs       LoadCmd = 0x2B                    // Code signing DRs copied from linked dylibs
	LoadCmdEncryptionInfo64       LoadCmd = 0x2C                    // 64-bit encrypted segment information
	LoadCmdLinkerOption           LoadCmd = 0x2D                    // linker options in MH_OBJECT files
	LoadCmdLinkerOptimizationHint LoadCmd = 0x2E                    // optimization hints in MH_OBJECT files
	LoadCmdVersionMinTvos         LoadCmd = 0x2F                    // build for AppleTV min OS version
	LoadCmdVersionMinWatchos      LoadCmd = 0x30                    // build for Watch min OS version
	LoadCmdNote                   LoadCmd = 0x31                    // arbitrary data included within a Mach-O file
	LoadCmdBuildVersion           LoadCmd = 0x32                    // build for platform min OS version
	LoadCmdDyldExportsTrie        LoadCmd = (0x33 | LoadCmdReqDyld) // used with linkedit_data_command, payload is trie
	LoadCmdDyldChainedFixups      LoadCmd = (0x34 | LoadCmdReqDyld) // used with linkedit_data_command
)

var cmdStrings = []intName{
	{uint32(LoadCmdSegment), "LoadCmdSegment"},
	{uint32(LoadCmdSymtab), "LoadCmdSymtab"},
	{uint32(LoadCmdSymseg), "LoadCmdSymseg"},
	{uint32(LoadCmdThread), "LoadCmdThread"},
	{uint32(LoadCmdUnixThread), "LoadCmdUnixThread"},
	{uint32(LoadCmdLoadfvmlib), "LoadCmdLoadfvmlib"},
	{uint32(LoadCmdIdfvmlib), "LoadCmdIdfvmlib"},
	{uint32(LoadCmdIdent), "LoadCmdIdent"},
	{uint32(LoadCmdFvmfile), "LoadCmdFvmfile"},
	{uint32(LoadCmdPrepage), "LoadCmdPrepage"},
	{uint32(LoadCmdDysymtab), "LoadCmdDysymtab"},
	{uint32(LoadCmdDylib), "LoadCmdDylib"},
	{uint32(LoadCmdDylibID), "LoadCmdDylibID"},
	{uint32(LoadCmdDylinker), "LoadCmdDylinker"},
	{uint32(LoadCmdPreboundDylib), "LoadCmdPreboundDylib"},
	{uint32(LoadCmdRoutines), "LoadCmdRoutines"},
	{uint32(LoadCmdSubFramework), "LoadCmdSubFramework"},
	{uint32(LoadCmdSubUmbrella), "LoadCmdSubUmbrella"},
	{uint32(LoadCmdSubClient), "LoadCmdSubClient"},
	{uint32(LoadCmdSubLibrary), "LoadCmdSubLibrary"},
	{uint32(LoadCmdTwolevelHints), "LoadCmdTwolevelHints"},
	{uint32(LoadCmdPrebindCksum), "LoadCmdPrebindCksum"},
	{uint32(LoadCmdLoadWeakDylib), "LoadCmdLoadWeakDylib"},
	{uint32(LoadCmdSegment64), "LoadCmdSegment64"},
	{uint32(LoadCmdRoutines64), "LoadCmdRoutines64"},
	{uint32(LoadCmdUUID), "LoadCmdUUID"},
	{uint32(LoadCmdRpath), "LoadCmdRpath"},
	{uint32(LoadCmdCodeSignature), "LoadCmdCodeSignature"},
	{uint32(LoadCmdSegmentSplitInfo), "LoadCmdSegmentSplitInfo"},
	{uint32(LoadCmdReexportDylib), "LoadCmdReexportDylib"},
	{uint32(LoadCmdLazyLoadDylib), "LoadCmdLazyLoadDylib"},
	{uint32(LoadCmdEncryptionInfo), "LoadCmdEncryptionInfo"},
	{uint32(LoadCmdDyldInfo), "LoadCmdDyldInfo"},
	{uint32(LoadCmdDyldInfoOnly), "LoadCmdDyldInfoOnly"},
	{uint32(LoadCmdLoadUpwardDylib), "LoadCmdLoadUpwardDylib"},
	{uint32(LoadCmdVersionMinMacosx), "LoadCmdVersionMinMacosx"},
	{uint32(LoadCmdVersionMinIphoneos), "LoadCmdVersionMinIphoneos"},
	{uint32(LoadCmdFunctionStarts), "LoadCmdFunctionStarts"},
	{uint32(LoadCmdDyldEnvironment), "LoadCmdDyldEnvironment"},
	{uint32(LoadCmdMain), "LoadCmdMain"},
	{uint32(LoadCmdDataInCode), "LoadCmdDataInCode"},
	{uint32(LoadCmdSourceVersion), "LoadCmdSourceVersion"},
	{uint32(LoadCmdDylibCodeSignDrs), "LoadCmdDylibCodeSignDrs"},
	{uint32(LoadCmdEncryptionInfo64), "LoadCmdEncryptionInfo64"},
	{uint32(LoadCmdLinkerOption), "LoadCmdLinkerOption"},
	{uint32(LoadCmdLinkerOptimizationHint), "LoadCmdLinkerOptimizationHint"},
	{uint32(LoadCmdVersionMinTvos), "LoadCmdVersionMinTvos"},
	{uint32(LoadCmdVersionMinWatchos), "LoadCmdVersionMinWatchos"},
	{uint32(LoadCmdNote), "LoadCmdNote"},
	{uint32(LoadCmdBuildVersion), "LoadCmdBuildVersion"},
	{uint32(LoadCmdDyldExportsTrie), "LoadCmdDyldExportsTrie"},
	{uint32(LoadCmdDyldChainedFixups), "LoadCmdDyldChainedFixups"},
}

func (i LoadCmd) String() string   { return stringName(uint32(i), cmdStrings, false) }
func (i LoadCmd) GoString() string { return stringName(uint32(i), cmdStrings, true) }

type version uint32

func (v version) String() string {
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, uint32(v))
	return fmt.Sprintf("%d.%d.%d", binary.BigEndian.Uint16(s[:2]), s[2], s[3])
}

type srcVersion uint64

func (sv srcVersion) String() string {
	a := sv >> 40
	b := (sv >> 30) & 0x3ff
	c := (sv >> 20) & 0x3ff
	d := (sv >> 10) & 0x3ff
	e := sv & 0x3ff
	return fmt.Sprintf("%d.%d.%d.%d.%d", a, b, c, d, e)
}

type platform uint32

const (
	unknown          platform = 0
	macOS            platform = 1  // PLATFORM_MACOS
	iOS              platform = 2  // PLATFORM_IOS
	tvOS             platform = 3  // PLATFORM_TVOS
	watchOS          platform = 4  // PLATFORM_WATCHOS
	bridgeOS         platform = 5  // PLATFORM_BRIDGEOS
	macCatalyst      platform = 6  // PLATFORM_MACCATALYST
	iOSSimulator     platform = 7  // PLATFORM_IOSSIMULATOR
	tvOSSimulator    platform = 8  // PLATFORM_TVOSSIMULATOR
	watchOSSimulator platform = 9  // PLATFORM_WATCHOSSIMULATOR
	driverKit        platform = 10 // PLATFORM_DRIVERKIT
)

type tool uint32

const (
	clang tool = 1 // TOOL_CLANG
	swift tool = 2 // TOOL_SWIFT
	ld    tool = 3 // TOOL_LD
)

type buildToolVersion struct {
	Tool    tool    /* enum for the tool */
	Version version /* version number of the tool */
}

type uuid [16]byte

func (u uuid) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[0], u[1], u[2], u[3],
		u[4], u[5], u[6], u[7],
		u[8], u[9], u[10], u[11],
		u[12], u[13], u[14], u[15])
}

type DataInCodeEntry struct {
	Offset uint32
	Length uint16
	Kind   diceKind
}

type diceKind uint16

const (
	DiceKindData           diceKind = 0x0001
	DiceKindJumpTable8     diceKind = 0x0002
	DiceKindJumpTable16    diceKind = 0x0003
	DiceKindJumpTable32    diceKind = 0x0004
	DiceKindAbsJumpTable32 diceKind = 0x0005
)

type (
	// A Segment32 is a 32-bit Mach-O segment load command.
	Segment32 struct {
		Cmd     LoadCmd
		Len     uint32
		Name    [16]byte
		Addr    uint32
		Memsz   uint32
		Offset  uint32
		Filesz  uint32
		Maxprot uint32
		Prot    uint32
		Nsect   uint32
		Flag    uint32
	}

	// A Segment64 is a 64-bit Mach-O segment load command.
	Segment64 struct {
		Cmd     LoadCmd
		Len     uint32
		Name    [16]byte
		Addr    uint64
		Memsz   uint64
		Offset  uint64
		Filesz  uint64
		Maxprot uint32
		Prot    uint32
		Nsect   uint32
		Flag    uint32
	}

	// A SymtabCmd is a Mach-O symbol table command.
	SymtabCmd struct {
		Cmd     LoadCmd
		Len     uint32
		Symoff  uint32
		Nsyms   uint32
		Stroff  uint32
		Strsize uint32
	}

	// A DysymtabCmd is a Mach-O dynamic symbol table command.
	DysymtabCmd struct {
		Cmd            LoadCmd
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
	DylibCmd struct {
		Cmd            LoadCmd
		Len            uint32
		Name           uint32
		Time           uint32
		CurrentVersion uint32
		CompatVersion  uint32
	}

	// A DylibIDCmd is a Mach-O id dynamic library command.
	DylibIDCmd struct {
		Cmd            LoadCmd
		Len            uint32
		Name           uint32
		Time           uint32
		CurrentVersion version
		CompatVersion  version
	}

	// A DyldInfoCmd is a Mach-O id dyld info command.
	DyldInfoCmd struct {
		Cmd          LoadCmd
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

	// A RpathCmd is a Mach-O rpath command.
	RpathCmd struct {
		Cmd  LoadCmd
		Len  uint32
		Path uint32
	}

	// A LinkEditDataCmd is a Mach-O linkedit data command.
	LinkEditDataCmd struct {
		Cmd    LoadCmd
		Len    uint32
		Offset uint32
		Size   uint32
	}

	// A Thread is a Mach-O thread state command.
	Thread struct {
		Cmd  LoadCmd
		Len  uint32
		Type uint32
		Data []uint32
	}

	// A SourceVersionCmd is a Mach-O source version command.
	SourceVersionCmd struct {
		Cmd     LoadCmd
		Len     uint32
		Version srcVersion // A.B.C.D.E packed as a24.b10.c10.d10.e10
	}

	/*
	 * The build_version_command contains the min OS version on which this
	 * binary was built to run for its platform.  The list of known platforms and
	 * tool values following it.
	 */
	BuildVersionCmd struct {
		Cmd LoadCmd /* LC_BUILD_VERSION */
		Len uint32  /* sizeof(struct build_version_command) plus */
		/* ntools * sizeof(struct build_tool_version) */
		Platform platform /* platform */
		Minos    version  /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
		Sdk      version  /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
		Ntools   uint32   /* number of tool entries following this */
	}

	// A UUIDCmd is a Mach-O uuid load command contains a single
	// 128-bit unique random number that identifies an object produced
	// by the static link editor.
	UUIDCmd struct {
		Cmd  LoadCmd
		Len  uint32
		UUID uuid
	}
)
