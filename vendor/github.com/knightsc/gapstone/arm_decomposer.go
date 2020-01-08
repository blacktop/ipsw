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

// Accessed via insn.Arm.XXX
type ArmInstruction struct {
	UserMode    bool
	VectorSize  int
	VectorData  int
	CPSMode     int
	CPSFlag     int
	CC          uint
	UpdateFlags bool
	Writeback   bool
	MemBarrier  int
	Operands    []ArmOperand
}

type ArmShifter struct {
	Type  uint
	Value uint
}

type ArmOperand struct {
	VectorIndex int
	Shift       ArmShifter
	Type        uint // ARM_OP_* - determines which field is set below
	Reg         uint
	Imm         int32
	FP          float64
	Mem         ArmMemoryOperand
	Setend      int
	Subtracted  bool
	Access      uint
	NeonLane    int
}

type ArmMemoryOperand struct {
	Base   uint
	Index  uint
	Scale  int
	Disp   int
	LShift int
}

// Number of Operands of a given ARM_OP_* type
func (insn ArmInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

func fillArmHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_arm := (*C.cs_arm)(unsafe.Pointer(&raw.detail.anon0[0]))

	arm := ArmInstruction{
		UserMode:    bool(cs_arm.usermode),
		VectorSize:  int(cs_arm.vector_size),
		VectorData:  int(cs_arm.vector_data),
		CPSMode:     int(cs_arm.cps_mode),
		CPSFlag:     int(cs_arm.cps_flag),
		CC:          uint(cs_arm.cc),
		UpdateFlags: bool(cs_arm.update_flags),
		Writeback:   bool(cs_arm.writeback),
		MemBarrier:  int(cs_arm.mem_barrier),
	}

	// Cast the op_info to a []C.cs_arm_op
	var ops []C.cs_arm_op
	h := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	h.Data = uintptr(unsafe.Pointer(&cs_arm.operands[0]))
	h.Len = int(cs_arm.op_count)
	h.Cap = int(cs_arm.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {
		if cop._type == ARM_OP_INVALID {
			break
		}
		gop := ArmOperand{
			Shift: ArmShifter{
				Type:  uint(cop.shift._type),
				Value: uint(cop.shift.value),
			},
			Type:        uint(cop._type),
			VectorIndex: int(cop.vector_index),
			Subtracted:  bool(cop.subtracted),
			Access:      uint(cop.access),
			NeonLane:    int(cop.neon_lane),
		}
		switch cop._type {
		// fake a union by setting only the correct struct member
		case ARM_OP_IMM, ARM_OP_CIMM, ARM_OP_PIMM:
			gop.Imm = int32(*(*C.int32_t)(unsafe.Pointer(&cop.anon0[0])))
		case ARM_OP_FP:
			gop.FP = float64(*(*C.double)(unsafe.Pointer(&cop.anon0[0])))
		case ARM_OP_REG, ARM_OP_SYSREG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case ARM_OP_MEM:
			cmop := (*C.arm_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = ArmMemoryOperand{
				Base:   uint(cmop.base),
				Index:  uint(cmop.index),
				Scale:  int(cmop.scale),
				Disp:   int(cmop.disp),
				LShift: int(cmop.lshift),
			}
		case ARM_OP_SETEND:
			gop.Setend = int(*(*C.int)(unsafe.Pointer(&cop.anon0[0])))
		}
		arm.Operands = append(arm.Operands, gop)
	}
	insn.Arm = &arm
}

func decomposeArm(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(e, raw, decomp)
		fillArmHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
