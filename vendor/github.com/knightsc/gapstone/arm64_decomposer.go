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

// import "C" needs to be on its own line. cgo, amirite? XD
import (
	"reflect"
	"unsafe"
)

// Accessed via insn.Arm64.XXX
type Arm64Instruction struct {
	CC          uint
	UpdateFlags bool
	Writeback   bool
	Operands    []Arm64Operand
}

type Arm64Shifter struct {
	Type  uint
	Value uint
}

type Arm64Operand struct {
	VectorIndex int
	Vas         int
	Shift       Arm64Shifter
	Ext         uint
	Type        uint // ARM64_OP_* - determines which field is set below
	Reg         uint
	Imm         int64
	FP          float64
	Mem         Arm64MemoryOperand
	PState      int
	Sys         uint
	Prefetch    int
	Barrier     int
	Access      uint
}

type Arm64MemoryOperand struct {
	Base  uint
	Index uint
	Disp  int32
}

// Number of Operands of a given ARM64_OP_* type
func (insn Arm64Instruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

func fillArm64Header(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_arm64 := (*C.cs_arm64)(unsafe.Pointer(&raw.detail.anon0[0]))

	arm64 := Arm64Instruction{
		CC:          uint(cs_arm64.cc),
		UpdateFlags: bool(cs_arm64.update_flags),
		Writeback:   bool(cs_arm64.writeback),
	}

	// Cast the op_info to a []C.cs_arm6464_op
	var ops []C.cs_arm64_op
	h := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	h.Data = uintptr(unsafe.Pointer(&cs_arm64.operands[0]))
	h.Len = int(cs_arm64.op_count)
	h.Cap = int(cs_arm64.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == ARM64_OP_INVALID {
			break
		}

		gop := Arm64Operand{
			Shift: Arm64Shifter{
				Type:  uint(cop.shift._type),
				Value: uint(cop.shift.value),
			},
			Type:        uint(cop._type),
			Ext:         uint(cop.ext),
			VectorIndex: int(cop.vector_index),
			Vas:         int(cop.vas),
			Access:      uint(cop.access),
		}

		switch cop._type {
		// fake a union by setting only the correct struct member
		case ARM64_OP_IMM, ARM64_OP_CIMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_FP:
			gop.FP = float64(*(*C.double)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_REG, ARM64_OP_REG_MRS, ARM64_OP_REG_MSR:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_MEM:
			cmop := (*C.arm64_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = Arm64MemoryOperand{
				Base:  uint(cmop.base),
				Index: uint(cmop.index),
				Disp:  int32(cmop.disp),
			}
		case ARM64_OP_PREFETCH:
			gop.Prefetch = int(*(*C.int)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_PSTATE:
			gop.PState = int(*(*C.int)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_BARRIER:
			gop.Barrier = int(*(*C.int)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_SYS:
			gop.Sys = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		}

		arm64.Operands = append(arm64.Operands, gop)

	}
	insn.Arm64 = &arm64
}

func decomposeArm64(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillArm64Header(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
