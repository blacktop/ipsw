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

// import "fmt"

// Accessed via insn.Sparc.XXX
type SparcInstruction struct {
	CC       uint
	Hint     uint
	OpCnt    uint8
	Operands []SparcOperand
}

// Number of Operands of a given SPARC_OP_* type
func (insn SparcInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type SparcOperand struct {
	Type uint // SPARC_OP_* - determines which field is set below
	Reg  uint
	Imm  int64
	Mem  SparcMemoryOperand
}

type SparcMemoryOperand struct {
	Base  uint8
	Index uint8
	Disp  int32
}

func fillSparcHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_sparc := (*C.cs_sparc)(unsafe.Pointer(&raw.detail.anon0[0]))

	sparc := SparcInstruction{
		CC:    uint(cs_sparc.cc),
		Hint:  uint(cs_sparc.hint),
		OpCnt: uint8(cs_sparc.op_count),
	}

	// Cast the op_info to a []C.cs_sparc_op
	var ops []C.cs_sparc_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_sparc.operands[0]))
	oih.Len = int(cs_sparc.op_count)
	oih.Cap = int(cs_sparc.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == SPARC_OP_INVALID {
			break
		}

		gop := new(SparcOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case SPARC_OP_IMM:
			gop.Imm = int64(*(*C.int32_t)(unsafe.Pointer(&cop.anon0[0])))
		case SPARC_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case SPARC_OP_MEM:
			cmop := (*C.sparc_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = SparcMemoryOperand{
				Base:  uint8(cmop.base),
				Index: uint8(cmop.index),
				Disp:  int32(cmop.disp),
			}
		}

		sparc.Operands = append(sparc.Operands, *gop)

	}
	insn.Sparc = &sparc
}

func decomposeSparc(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillSparcHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
