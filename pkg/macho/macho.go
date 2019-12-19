// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Mach-O header data structures
// Originally at:
// http://developer.apple.com/mac/library/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html (since deleted by Apply)
// Archived copy at:
// https://web.archive.org/web/20090819232456/http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachORuntime/index.html
// For cloned PDF see:
// https://github.com/aidansteele/osx-abi-macho-file-format-reference

package macho

//go:generate stringer -type=platform,tool

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// A FileHeader represents a Mach-O file header.
type FileHeader struct {
	Magic  uint32
	Cpu    Cpu
	SubCpu uint32
	Type   Type
	Ncmd   uint32
	Cmdsz  uint32
	Flags  uint32
}

const (
	fileHeaderSize32 = 7 * 4
	fileHeaderSize64 = 8 * 4
)

const (
	Magic32  uint32 = 0xfeedface
	Magic64  uint32 = 0xfeedfacf
	MagicFat uint32 = 0xcafebabe
)

// A Type is the Mach-O file type, e.g. an object file, executable, or dynamic library.
type Type uint32

const (
	TypeObj                        Type = 1
	TypeExec                       Type = 2
	TypeDylib                      Type = 6
	TypeBundle                     Type = 8
	TypeNlistOutofsyncWithDyldinfo Type = 0x04000000 /* The external symbols
	   listed in the nlist symbol table do
	   not include all the symbols listed in
	   the dyld info. */
	TypeDylibInCache Type = 0x80000000 /* Only for use on dylibs. When this bit
	   is set, the dylib is part of the dyld
	   shared cache, rather than loose in
	   the filesystem. */
)

var typeStrings = []intName{
	{uint32(TypeObj), "Obj"},
	{uint32(TypeExec), "Exec"},
	{uint32(TypeDylib), "Dylib"},
	{uint32(TypeBundle), "Bundle"},
	{uint32(TypeNlistOutofsyncWithDyldinfo), "Nlist Out of sync With Dyldinfo"},
	{uint32(TypeDylibInCache), "Dylib in Cache"},
}

func (t Type) String() string   { return stringName(uint32(t), typeStrings, false) }
func (t Type) GoString() string { return stringName(uint32(t), typeStrings, true) }

// A Cpu is a Mach-O cpu type.
type Cpu uint32

const cpuArch64 = 0x01000000

const (
	Cpu386   Cpu = 7
	CpuAmd64 Cpu = Cpu386 | cpuArch64
	CpuArm   Cpu = 12
	CpuArm64 Cpu = CpuArm | cpuArch64
	CpuPpc   Cpu = 18
	CpuPpc64 Cpu = CpuPpc | cpuArch64
)

var cpuStrings = []intName{
	{uint32(Cpu386), "Cpu386"},
	{uint32(CpuAmd64), "CpuAmd64"},
	{uint32(CpuArm), "CpuArm"},
	{uint32(CpuArm64), "CpuArm64"},
	{uint32(CpuPpc), "CpuPpc"},
	{uint32(CpuPpc64), "CpuPpc64"},
}

func (i Cpu) String() string   { return stringName(uint32(i), cpuStrings, false) }
func (i Cpu) GoString() string { return stringName(uint32(i), cpuStrings, true) }

// A LoadCmd is a Mach-O load command.
type LoadCmd uint32

const (
	LoadCmdSegment      LoadCmd = 0x1
	LoadCmdSymtab       LoadCmd = 0x2
	LoadCmdThread       LoadCmd = 0x4
	LoadCmdUnixThread   LoadCmd = 0x5 // thread+stack
	LoadCmdDysymtab     LoadCmd = 0xb
	LoadCmdDylib        LoadCmd = 0xc // load dylib command
	LoadCmdDylinker     LoadCmd = 0xf // id dylinker command (not load dylinker command)
	LoadCmdSegment64    LoadCmd = 0x19
	LoadCmdBuildVersion LoadCmd = 0x32
	LoadCmdRpath        LoadCmd = 0x8000001c
)

var cmdStrings = []intName{
	{uint32(LoadCmdSegment), "LoadCmdSegment"},
	{uint32(LoadCmdThread), "LoadCmdThread"},
	{uint32(LoadCmdUnixThread), "LoadCmdUnixThread"},
	{uint32(LoadCmdDylib), "LoadCmdDylib"},
	{uint32(LoadCmdSegment64), "LoadCmdSegment64"},
	{uint32(LoadCmdRpath), "LoadCmdRpath"},
}

func (i LoadCmd) String() string   { return stringName(uint32(i), cmdStrings, false) }
func (i LoadCmd) GoString() string { return stringName(uint32(i), cmdStrings, true) }

type version uint32

func (v version) String() string {
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, uint32(v))
	return fmt.Sprintf("%d.%d.%d", binary.BigEndian.Uint16(s[:2]), s[2], s[3])
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

// func (p platform) String() string {
// 	names := [...]string{
// 		"unknown",
// 		"macOS",
// 		"iOS",
// 		"tvOS",
// 		"watchOS",
// 		"bridgeOS",
// 		"mac Catalyst",
// 		"iOS Simulator",
// 		"tvOS Simulator",
// 		"watchOS Simulator",
// 		"driver Kit"}
// 	return names[p]
// }

type tool uint32

const (
	clang tool = 1 // TOOL_CLANG
	swift tool = 2 // TOOL_SWIFT
	ld    tool = 3 // TOOL_LD
)

// func (t tool) String() string {
// 	names := [...]string{
// 		"clang",
// 		"swift",
// 		"ld"}
// 	return names[t]
// }

type buildToolVersion struct {
	Tool    tool    /* enum for the tool */
	Version version /* version number of the tool */
}

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

	// A RpathCmd is a Mach-O rpath command.
	RpathCmd struct {
		Cmd  LoadCmd
		Len  uint32
		Path uint32
	}

	// A Thread is a Mach-O thread state command.
	Thread struct {
		Cmd  LoadCmd
		Len  uint32
		Type uint32
		Data []uint32
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
)

const (
	FlagNoUndefs              uint32 = 0x1
	FlagIncrLink              uint32 = 0x2
	FlagDyldLink              uint32 = 0x4
	FlagBindAtLoad            uint32 = 0x8
	FlagPrebound              uint32 = 0x10
	FlagSplitSegs             uint32 = 0x20
	FlagLazyInit              uint32 = 0x40
	FlagTwoLevel              uint32 = 0x80
	FlagForceFlat             uint32 = 0x100
	FlagNoMultiDefs           uint32 = 0x200
	FlagNoFixPrebinding       uint32 = 0x400
	FlagPrebindable           uint32 = 0x800
	FlagAllModsBound          uint32 = 0x1000
	FlagSubsectionsViaSymbols uint32 = 0x2000
	FlagCanonical             uint32 = 0x4000
	FlagWeakDefines           uint32 = 0x8000
	FlagBindsToWeak           uint32 = 0x10000
	FlagAllowStackExecution   uint32 = 0x20000
	FlagRootSafe              uint32 = 0x40000
	FlagSetuidSafe            uint32 = 0x80000
	FlagNoReexportedDylibs    uint32 = 0x100000
	FlagPIE                   uint32 = 0x200000
	FlagDeadStrippableDylib   uint32 = 0x400000
	FlagHasTLVDescriptors     uint32 = 0x800000
	FlagNoHeapExecution       uint32 = 0x1000000
	FlagAppExtensionSafe      uint32 = 0x2000000
)

// A Section32 is a 32-bit Mach-O section header.
type Section32 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint32
	Size     uint32
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    uint32
	Reserve1 uint32
	Reserve2 uint32
}

// A Section64 is a 64-bit Mach-O section header.
type Section64 struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint64
	Size     uint64
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    uint32
	Reserve1 uint32
	Reserve2 uint32
	Reserve3 uint32
}

// An Nlist32 is a Mach-O 32-bit symbol table entry.
type Nlist32 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint32
}

// An Nlist64 is a Mach-O 64-bit symbol table entry.
type Nlist64 struct {
	Name  uint32
	Type  uint8
	Sect  uint8
	Desc  uint16
	Value uint64
}

// Regs386 is the Mach-O 386 register structure.
type Regs386 struct {
	AX    uint32
	BX    uint32
	CX    uint32
	DX    uint32
	DI    uint32
	SI    uint32
	BP    uint32
	SP    uint32
	SS    uint32
	FLAGS uint32
	IP    uint32
	CS    uint32
	DS    uint32
	ES    uint32
	FS    uint32
	GS    uint32
}

// RegsAMD64 is the Mach-O AMD64 register structure.
type RegsAMD64 struct {
	AX    uint64
	BX    uint64
	CX    uint64
	DX    uint64
	DI    uint64
	SI    uint64
	BP    uint64
	SP    uint64
	R8    uint64
	R9    uint64
	R10   uint64
	R11   uint64
	R12   uint64
	R13   uint64
	R14   uint64
	R15   uint64
	IP    uint64
	FLAGS uint64
	CS    uint64
	FS    uint64
	GS    uint64
}

type intName struct {
	i uint32
	s string
}

func stringName(i uint32, names []intName, goSyntax bool) string {
	for _, n := range names {
		if n.i == i {
			if goSyntax {
				return "macho." + n.s
			}
			return n.s
		}
	}
	return strconv.FormatUint(uint64(i), 10)
}
