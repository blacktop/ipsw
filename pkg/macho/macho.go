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

//go:generate stringer -type=Platform,tool,diceKind,segFlag -output macho_string.go

import (
	"fmt"
	"strconv"
)

// A FileHeader represents a Mach-O file header.
type FileHeader struct {
	Magic  magic
	Cpu    CPU
	SubCpu CPUSubtype
	Type   Type
	Ncmd   uint32
	Cmdsz  uint32
	Flags  headerFlags
}

const (
	fileHeaderSize32 = 7 * 4
	fileHeaderSize64 = 8 * 4
)

type magic uint32

const (
	Magic32  magic = 0xfeedface
	Magic64  magic = 0xfeedfacf
	MagicFat magic = 0xcafebabe
)

var magicStrings = []intName{
	{uint32(Magic32), "32-bit MachO"},
	{uint32(Magic64), "64-bit MachO"},
	{uint32(MagicFat), "Fat MachO"},
}

func (i magic) Int() uint32      { return uint32(i) }
func (i magic) String() string   { return stringName(uint32(i), magicStrings, false) }
func (i magic) GoString() string { return stringName(uint32(i), magicStrings, true) }

type VmProtection int32

func (v VmProtection) Read() bool {
	return (v & 0x01) != 0
}

func (v VmProtection) Write() bool {
	return (v & 0x02) != 0
}

func (v VmProtection) Execute() bool {
	return (v & 0x04) != 0
}

func (v VmProtection) String() string {
	var protStr string
	if v.Read() {
		protStr += "r"
	} else {
		protStr += "-"
	}
	if v.Write() {
		protStr += "w"
	} else {
		protStr += "-"
	}
	if v.Execute() {
		protStr += "x"
	} else {
		protStr += "-"
	}
	return protStr
}

// UUID is a macho uuid object
type UUID [16]byte

func (u UUID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
}

// Platform is a macho platform object
type Platform uint32

const (
	unknown          Platform = 0
	macOS            Platform = 1  // PLATFORM_MACOS
	iOS              Platform = 2  // PLATFORM_IOS
	tvOS             Platform = 3  // PLATFORM_TVOS
	watchOS          Platform = 4  // PLATFORM_WATCHOS
	bridgeOS         Platform = 5  // PLATFORM_BRIDGEOS
	macCatalyst      Platform = 6  // PLATFORM_MACCATALYST
	iOSSimulator     Platform = 7  // PLATFORM_IOSSIMULATOR
	tvOSSimulator    Platform = 8  // PLATFORM_TVOSSIMULATOR
	watchOSSimulator Platform = 9  // PLATFORM_WATCHOSSIMULATOR
	driverKit        Platform = 10 // PLATFORM_DRIVERKIT
)

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

// RegsARM is the Mach-O ARM register structure.
type RegsARM struct {
	R0   uint32
	R1   uint32
	R2   uint32
	R3   uint32
	R4   uint32
	R5   uint32
	R6   uint32
	R7   uint32
	R8   uint32
	R9   uint32
	R10  uint32
	R11  uint32
	R12  uint32
	SP   uint32
	LR   uint32
	PC   uint32
	CPSR uint32
}

// RegsARM64 is the Mach-O ARM 64 register structure.
type RegsARM64 struct {
	X0   uint64
	X1   uint64
	X2   uint64
	X3   uint64
	X4   uint64
	X5   uint64
	X6   uint64
	X7   uint64
	X8   uint64
	X9   uint64
	X10  uint64
	X11  uint64
	X12  uint64
	X13  uint64
	X14  uint64
	X15  uint64
	X16  uint64
	X17  uint64
	X18  uint64
	X19  uint64
	X20  uint64
	X21  uint64
	X22  uint64
	X23  uint64
	X24  uint64
	X25  uint64
	X26  uint64
	X27  uint64
	X28  uint64
	FP   uint64
	LR   uint64
	SP   uint64
	PC   uint64
	CPSR uint32
	PAD  uint32
}

type intName struct {
	i uint32
	s string
}

func (h FileHeader) String() string {

	return fmt.Sprintf(
		"Magic         = %s\n"+
			"Type          = %s\n"+
			"CPU           = %s, %s\n"+
			"Commands      = %d (Size: %d)\n"+
			"Flags         = %s\n",
		h.Magic,
		h.Type,
		h.Cpu, h.SubCpu.String(h.Cpu),
		h.Ncmd,
		h.Cmdsz,
		h.Flags,
	)
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
