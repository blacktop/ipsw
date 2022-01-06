package emu

import (
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

var regs = []int{
	// ARM64 registers
	uc.ARM64_REG_X0,
	uc.ARM64_REG_X1,
	uc.ARM64_REG_X2,
	uc.ARM64_REG_X3,
	uc.ARM64_REG_X4,
	uc.ARM64_REG_X5,
	uc.ARM64_REG_X6,
	uc.ARM64_REG_X7,
	uc.ARM64_REG_X8,
	uc.ARM64_REG_X9,
	uc.ARM64_REG_X10,
	uc.ARM64_REG_X11,
	uc.ARM64_REG_X12,
	uc.ARM64_REG_X13,
	uc.ARM64_REG_X14,
	uc.ARM64_REG_X15,
	uc.ARM64_REG_X16,
	uc.ARM64_REG_X17,
	uc.ARM64_REG_X18,
	uc.ARM64_REG_X19,
	uc.ARM64_REG_X20,
	uc.ARM64_REG_X21,
	uc.ARM64_REG_X22,
	uc.ARM64_REG_X23,
	uc.ARM64_REG_X24,
	uc.ARM64_REG_X25,
	uc.ARM64_REG_X26,
	uc.ARM64_REG_X27,
	uc.ARM64_REG_X28,
	uc.ARM64_REG_X29, // ARM64_REG_FP
	uc.ARM64_REG_X30, // ARM64_REG_LR
	uc.ARM64_REG_NZCV,
	uc.ARM64_REG_SP,
	uc.ARM64_REG_WSP,
	uc.ARM64_REG_WZR,
	uc.ARM64_REG_XZR,
	// pseudo registers
	uc.ARM64_REG_PC,
	uc.ARM64_REG_CPACR_EL1,
	// thread registers
	uc.ARM64_REG_TPIDR_EL0,
	uc.ARM64_REG_TPIDRRO_EL0,
	uc.ARM64_REG_TPIDR_EL1,
	uc.ARM64_REG_PSTATE,
	// exception link registers
	uc.ARM64_REG_ELR_EL0,
	uc.ARM64_REG_ELR_EL1,
	uc.ARM64_REG_ELR_EL2,
	uc.ARM64_REG_ELR_EL3,
	// stack pointers registers
	uc.ARM64_REG_SP_EL0,
	uc.ARM64_REG_SP_EL1,
	uc.ARM64_REG_SP_EL2,
	uc.ARM64_REG_SP_EL3,
	// other CP15 registers
	uc.ARM64_REG_TTBR0_EL1,
	uc.ARM64_REG_TTBR1_EL1,
	uc.ARM64_REG_ESR_EL0,
	uc.ARM64_REG_ESR_EL1,
	uc.ARM64_REG_ESR_EL2,
	uc.ARM64_REG_ESR_EL3,
	uc.ARM64_REG_FAR_EL0,
	uc.ARM64_REG_FAR_EL1,
	uc.ARM64_REG_FAR_EL2,
	uc.ARM64_REG_FAR_EL3,
	uc.ARM64_REG_PAR_EL1,
	uc.ARM64_REG_MAIR_EL1,
	uc.ARM64_REG_VBAR_EL0,
	uc.ARM64_REG_VBAR_EL1,
	uc.ARM64_REG_VBAR_EL2,
	uc.ARM64_REG_VBAR_EL3,
}

// Registers emulation registers object
type Registers map[int]uint64

// GetState refreshes the internal register state
func (e *Emulation) GetState() error {
	regs := make([]int, uc.ARM64_REG_ENDING-uc.ARM64_REG_INVALID+1)
	for i := range regs {
		regs[i] = uc.ARM64_REG_INVALID + i

	}
	vals, err := e.mu.RegReadBatch(regs)
	if err != nil {
		return err
	}
	for idx, val := range vals {
		e.regs[regs[idx]] = val
	}

	return nil
}

func (r Registers) String() string {
	return fmt.Sprintf(colorHook("[REGISTERS]\n") +
		colorDetails(
			"     x0: %#-18x  x1: %#-18x  x2: %#-18x  x3: %#-18x\n"+
				"     x4: %#-18x  x5: %#-18x  x6: %#-18x  x7: %#-18x\n"+
				"     x8: %#-18x  x9: %#-18x x10: %#-18x x11: %#-18x\n"+
				"    x12: %#-18x x13: %#-18x x14: %#-18x x15: %#-18x\n"+
				"    x16: %#-18x x17: %#-18x x18: %#-18x x19: %#-18x\n"+
				"    x20: %#-18x x21: %#-18x x22: %#-18x x23: %#-18x\n"+
				"    x24: %#-18x x25: %#-18x x26: %#-18x x27: %#-18x\n"+
				"    x28: %#-18x  fp: %#-18x  lr: %#-18x\n"+
				"     pc: %#-18x  sp: %#-18x cpsr: 0x%08x %s",
			r[uc.ARM64_REG_X0], r[uc.ARM64_REG_X1], r[uc.ARM64_REG_X2], r[uc.ARM64_REG_X3],
			r[uc.ARM64_REG_X4], r[uc.ARM64_REG_X5], r[uc.ARM64_REG_X6], r[uc.ARM64_REG_X7],
			r[uc.ARM64_REG_X8], r[uc.ARM64_REG_X9], r[uc.ARM64_REG_X10], r[uc.ARM64_REG_X11],
			r[uc.ARM64_REG_X12], r[uc.ARM64_REG_X13], r[uc.ARM64_REG_X14], r[uc.ARM64_REG_X15],
			r[uc.ARM64_REG_X16], r[uc.ARM64_REG_X17], r[uc.ARM64_REG_X18], r[uc.ARM64_REG_X19],
			r[uc.ARM64_REG_X20], r[uc.ARM64_REG_X21], r[uc.ARM64_REG_X22], r[uc.ARM64_REG_X23],
			r[uc.ARM64_REG_X24], r[uc.ARM64_REG_X25], r[uc.ARM64_REG_X26], r[uc.ARM64_REG_X27],
			r[uc.ARM64_REG_X28], r[uc.ARM64_REG_FP], r[uc.ARM64_REG_LR],
			r[uc.ARM64_REG_PC], r[uc.ARM64_REG_SP], r[uc.ARM64_REG_PSTATE], pstate(r[uc.ARM64_REG_PSTATE]),
		))
}

type pstate uint32

// NZCV
func (p pstate) N() bool {
	return types.ExtractBits(uint64(p), 31, 1) != 0
}
func (p pstate) Z() bool {
	return types.ExtractBits(uint64(p), 30, 1) != 0
}
func (p pstate) C() bool {
	return types.ExtractBits(uint64(p), 29, 1) != 0
}
func (p pstate) V() bool {
	return types.ExtractBits(uint64(p), 28, 1) != 0
}

// DAIF
func (p pstate) D() bool {
	return types.ExtractBits(uint64(p), 9, 1) != 0
}
func (p pstate) A() bool {
	return types.ExtractBits(uint64(p), 8, 1) != 0
}
func (p pstate) I() bool {
	return types.ExtractBits(uint64(p), 7, 1) != 0
}
func (p pstate) F() bool {
	return types.ExtractBits(uint64(p), 6, 1) != 0
}

// func (p pstate) PAN() bool {
// 	return types.ExtractBits(uint64(p), 23, 1) != 0
// }
// func (p pstate) UAO() bool {
// 	return types.ExtractBits(uint64(p), 22, 1) != 0
// }
// func (p pstate) DIT() bool {
// 	return types.ExtractBits(uint64(p), 21, 1) != 0
// }
// func (p pstate) TCO() bool {
// 	return types.ExtractBits(uint64(p), 20, 1) != 0
// }
func (p pstate) BType() branchType {
	return branchType(types.ExtractBits(uint64(p), 10, 2))
}
func (p pstate) SS() bool {
	return types.ExtractBits(uint64(p), 21, 1) != 0
}
func (p pstate) IL() bool {
	return types.ExtractBits(uint64(p), 20, 1) != 0
}

// func (p pstate) EL() uint64 {
// 	return types.ExtractBits(uint64(p), 15, 2)
// }
// func (p pstate) Q() bool {
// 	return types.ExtractBits(uint64(p), 11, 1) != 0
// }
// func (p pstate) GE() bool {
// 	return types.ExtractBits(uint64(p), 10, 4) != 0
// }
// func (p pstate) SSBS() bool {
// 	return types.ExtractBits(uint64(p), 9, 1) != 0
// }
// func (p pstate) IT() bool {
// 	return types.ExtractBits(uint64(p), 1, 8) != 0
// }
// func (p pstate) J() bool {
// 	return types.ExtractBits(uint64(p), 0, 1) != 0
// }
// func (p pstate) T() bool {
// 	return types.ExtractBits(uint64(p), 0, 1) != 0
// }
// func (p pstate) E() bool {
// 	return types.ExtractBits(uint64(p), 0, 1) != 0
// }
func (p pstate) NRW() bool {
	return types.ExtractBits(uint64(p), 5, 1) != 0
}
func (p pstate) M() pstateMode {
	return pstateMode(types.ExtractBits(uint64(p), 0, 4))
}
func (p pstate) SP() bool {
	return types.ExtractBits(uint64(p), 0, 1) != 0
}

func (p pstate) String() string {
	var flags []string
	if p.N() {
		flags = append(flags, "N")
	}
	if p.Z() {
		flags = append(flags, "Z")
	}
	if p.C() {
		flags = append(flags, "C")
	}
	if p.V() {
		flags = append(flags, "V")
	}
	if p.D() {
		flags = append(flags, "D")
	}
	if p.A() {
		flags = append(flags, "A")
	}
	if p.I() {
		flags = append(flags, "I")
	}
	if p.F() {
		flags = append(flags, "F")
	}
	if p.BType() > 0 {
		flags = append(flags, p.BType().String())
	}
	flags = append(flags, p.M().String())
	return colorDetails("[%s]", strings.Join(flags, " "))
}

// func (p pstate) String() string {
// 	return actionColor(
// 		" N: %t, Z: %t, C: %t, V: %t, D: %t, A: %t, I: %t, F: %t\n"+
// 			" PAN: %t, UAO: %t, DIT: %t, TCO: %t, BType: %d, SS: %t, IL: %t\n"+
// 			" EL: %d, 32bit: %t, SP: %t",
// 		p.N(), p.Z(), p.C(), p.V(), p.D(), p.A(), p.I(), p.F(),
// 		p.PAN(), p.UAO(), p.DIT(), p.TCO(), p.BType(), p.SS(), p.IL(),
// 		p.EL(), p.NRW(), p.SP(),
// 	)
// }
