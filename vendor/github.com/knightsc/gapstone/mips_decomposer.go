/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

// #cgo LDFLAGS: -lcapstone
// #cgo freebsd CFLAGS: -I/usr/local/include
// #cgo freebsd LDFLAGS: -L/usr/local/lib
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"

import (
	"reflect"
	"unsafe"
)

// Accessed via insn.Mips.XXX
type MipsInstruction struct {
	Operands []MipsOperand
}

// Number of Operands of a given MIPS_OP_* type
func (insn MipsInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type MipsOperand struct {
	Type uint // MIPS_OP_* - determines which field is set below
	Reg  uint
	Imm  int64
	Mem  MipsMemoryOperand
}

type MipsMemoryOperand struct {
	Base uint
	Disp int64
}

func fillMipsHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_mips := (*C.cs_mips)(unsafe.Pointer(&raw.detail.anon0[0]))

	mips := MipsInstruction{}

	// Cast the op_info to a []C.cs_mips_op
	var ops []C.cs_mips_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_mips.operands[0]))
	oih.Len = int(cs_mips.op_count)
	oih.Cap = int(cs_mips.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == MIPS_OP_INVALID {
			break
		}

		gop := new(MipsOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case MIPS_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case MIPS_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case MIPS_OP_MEM:
			cmop := (*C.mips_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = MipsMemoryOperand{
				Base: uint(cmop.base),
				Disp: int64(cmop.disp),
			}
		}

		mips.Operands = append(mips.Operands, *gop)

	}
	insn.Mips = &mips
}

func decomposeMips(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillMipsHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
