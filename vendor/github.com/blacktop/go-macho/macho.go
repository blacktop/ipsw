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
