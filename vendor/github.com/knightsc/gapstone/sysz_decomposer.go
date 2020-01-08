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

// Accessed via insn.SysZ.XXX
type SysZInstruction struct {
	CC       uint
	OpCnt    uint8
	Operands []SysZOperand
}

// Number of Operands of a given SYSZ_OP_* type
func (insn SysZInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type SysZOperand struct {
	Type uint // SYSZ_OP_* - determines which field is set below
	Reg  uint
	Imm  int64
	Mem  SysZMemoryOperand
}

type SysZMemoryOperand struct {
	Base   uint8
	Index  uint8
	Length uint64
	Disp   int64
}

func fillSysZHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_sysz := (*C.cs_sysz)(unsafe.Pointer(&raw.detail.anon0[0]))

	sysz := SysZInstruction{
		CC:    uint(cs_sysz.cc),
		OpCnt: uint8(cs_sysz.op_count),
	}

	// Cast the op_info to a []C.cs_sysz_op
	var ops []C.cs_sysz_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_sysz.operands[0]))
	oih.Len = int(cs_sysz.op_count)
	oih.Cap = int(cs_sysz.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == SYSZ_OP_INVALID {
			break
		}

		gop := new(SysZOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case SYSZ_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case SYSZ_OP_REG, SYSZ_OP_ACREG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case SYSZ_OP_MEM:
			cmop := (*C.sysz_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = SysZMemoryOperand{
				Base:   uint8(cmop.base),
				Index:  uint8(cmop.index),
				Length: uint64(cmop.length),
				Disp:   int64(cmop.disp),
			}
		}

		sysz.Operands = append(sysz.Operands, *gop)

	}
	insn.SysZ = &sysz
}

func decomposeSysZ(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillSysZHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
