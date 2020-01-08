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

// Accessed via insn.Xcore.XXX
type XcoreInstruction struct {
	OpCnt    uint8
	Operands []XcoreOperand
}

// Number of Operands of a given XCORE_OP_* type
func (insn XcoreInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type XcoreOperand struct {
	Type uint // XCORE_OP_* - determines which field is set below
	Reg  uint
	Imm  int32
	Mem  XcoreMemoryOperand
}

type XcoreMemoryOperand struct {
	Base   uint8
	Index  uint8
	Disp   int32
	Direct int
}

func fillXcoreHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_xcore := (*C.cs_xcore)(unsafe.Pointer(&raw.detail.anon0[0]))

	xcore := XcoreInstruction{
		OpCnt: uint8(cs_xcore.op_count),
	}

	// Cast the op_info to a []C.cs_xcore_op
	var ops []C.cs_xcore_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_xcore.operands[0]))
	oih.Len = int(cs_xcore.op_count)
	oih.Cap = int(cs_xcore.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == XCORE_OP_INVALID {
			break
		}

		gop := XcoreOperand{
			Type: uint(cop._type),
		}

		switch cop._type {
		// fake a union by setting only the correct struct member
		case XCORE_OP_IMM:
			gop.Imm = int32(*(*C.int32_t)(unsafe.Pointer(&cop.anon0[0])))
		case XCORE_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case XCORE_OP_MEM:
			cmop := (*C.xcore_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = XcoreMemoryOperand{
				Base:   uint8(cmop.base),
				Index:  uint8(cmop.index),
				Disp:   int32(cmop.disp),
				Direct: int(cmop.direct),
			}
		}

		xcore.Operands = append(xcore.Operands, gop)

	}
	insn.Xcore = &xcore
}

func decomposeXcore(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillXcoreHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
