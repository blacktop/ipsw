package types

//go:generate stringer -type=Platform,Tool,DiceKind -output types_string.go

import (
	"encoding/binary"
	"fmt"
)

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

type Version uint32

func (v Version) String() string {
	s := make([]byte, 4)
	binary.BigEndian.PutUint32(s, uint32(v))
	return fmt.Sprintf("%d.%d.%d", binary.BigEndian.Uint16(s[:2]), s[2], s[3])
}

type SrcVersion uint64

func (sv SrcVersion) String() string {
	a := sv >> 40
	b := (sv >> 30) & 0x3ff
	c := (sv >> 20) & 0x3ff
	d := (sv >> 10) & 0x3ff
	e := sv & 0x3ff
	return fmt.Sprintf("%d.%d.%d.%d.%d", a, b, c, d, e)
}

type Tool uint32

const (
	clang Tool = 1 // TOOL_CLANG
	swift Tool = 2 // TOOL_SWIFT
	ld    Tool = 3 // TOOL_LD
)

type BuildToolVersion struct {
	Tool    Tool    /* enum for the tool */
	Version Version /* version number of the tool */
}

type DataInCodeEntry struct {
	Offset uint32
	Length uint16
	Kind   DiceKind
}

type DiceKind uint16

const (
	KindData           DiceKind = 0x0001
	KindJumpTable8     DiceKind = 0x0002
	KindJumpTable16    DiceKind = 0x0003
	KindJumpTable32    DiceKind = 0x0004
	KindAbsJumpTable32 DiceKind = 0x0005
)
