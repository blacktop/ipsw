package emu

import (
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/types"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type register struct {
	Name      string
	Alias     string
	Value     uint64
	DidChange bool
}

func (r register) GetName() string {
	if r.Name == "x29" || r.Name == "x30" {
		return r.Alias
	}
	return r.Name
}

func (r register) String() string {
	if r.DidChange && (r.Name != "pc") {
		return fmt.Sprintf("%s %s", colorHook(r.GetName()+":"), colorChanged("%#-19x", r.Value))
	} else {
		return fmt.Sprintf("%s %s", colorHook(r.GetName()+":"), colorDetails("%#-19x", r.Value))
	}
}

// Registers emulation registers object
type Registers map[int]*register

func InitRegisters() Registers {
	return map[int]*register{
		uc.ARM64_REG_INVALID:     {Name: "invalid"},
		uc.ARM64_REG_X29:         {Name: "x29", Alias: "fp"},
		uc.ARM64_REG_X30:         {Name: "x30", Alias: "lr"},
		uc.ARM64_REG_NZCV:        {Name: "nzcv"},
		uc.ARM64_REG_SP:          {Name: "sp"},
		uc.ARM64_REG_WSP:         {Name: "wsp"},
		uc.ARM64_REG_WZR:         {Name: "wzr"},
		uc.ARM64_REG_XZR:         {Name: "xzr"},
		uc.ARM64_REG_B0:          {Name: "b0"},
		uc.ARM64_REG_B1:          {Name: "b1"},
		uc.ARM64_REG_B2:          {Name: "b2"},
		uc.ARM64_REG_B3:          {Name: "b3"},
		uc.ARM64_REG_B4:          {Name: "b4"},
		uc.ARM64_REG_B5:          {Name: "b5"},
		uc.ARM64_REG_B6:          {Name: "b6"},
		uc.ARM64_REG_B7:          {Name: "b7"},
		uc.ARM64_REG_B8:          {Name: "b8"},
		uc.ARM64_REG_B9:          {Name: "b9"},
		uc.ARM64_REG_B10:         {Name: "b10"},
		uc.ARM64_REG_B11:         {Name: "b11"},
		uc.ARM64_REG_B12:         {Name: "b12"},
		uc.ARM64_REG_B13:         {Name: "b13"},
		uc.ARM64_REG_B14:         {Name: "b14"},
		uc.ARM64_REG_B15:         {Name: "b15"},
		uc.ARM64_REG_B16:         {Name: "b16"},
		uc.ARM64_REG_B17:         {Name: "b17"},
		uc.ARM64_REG_B18:         {Name: "b18"},
		uc.ARM64_REG_B19:         {Name: "b19"},
		uc.ARM64_REG_B20:         {Name: "b20"},
		uc.ARM64_REG_B21:         {Name: "b21"},
		uc.ARM64_REG_B22:         {Name: "b22"},
		uc.ARM64_REG_B23:         {Name: "b23"},
		uc.ARM64_REG_B24:         {Name: "b24"},
		uc.ARM64_REG_B25:         {Name: "b25"},
		uc.ARM64_REG_B26:         {Name: "b26"},
		uc.ARM64_REG_B27:         {Name: "b27"},
		uc.ARM64_REG_B28:         {Name: "b28"},
		uc.ARM64_REG_B29:         {Name: "b29"},
		uc.ARM64_REG_B30:         {Name: "b30"},
		uc.ARM64_REG_B31:         {Name: "b31"},
		uc.ARM64_REG_D0:          {Name: "d0"},
		uc.ARM64_REG_D1:          {Name: "d1"},
		uc.ARM64_REG_D2:          {Name: "d2"},
		uc.ARM64_REG_D3:          {Name: "d3"},
		uc.ARM64_REG_D4:          {Name: "d4"},
		uc.ARM64_REG_D5:          {Name: "d5"},
		uc.ARM64_REG_D6:          {Name: "d6"},
		uc.ARM64_REG_D7:          {Name: "d7"},
		uc.ARM64_REG_D8:          {Name: "d8"},
		uc.ARM64_REG_D9:          {Name: "d9"},
		uc.ARM64_REG_D10:         {Name: "d10"},
		uc.ARM64_REG_D11:         {Name: "d11"},
		uc.ARM64_REG_D12:         {Name: "d12"},
		uc.ARM64_REG_D13:         {Name: "d13"},
		uc.ARM64_REG_D14:         {Name: "d14"},
		uc.ARM64_REG_D15:         {Name: "d15"},
		uc.ARM64_REG_D16:         {Name: "d16"},
		uc.ARM64_REG_D17:         {Name: "d17"},
		uc.ARM64_REG_D18:         {Name: "d18"},
		uc.ARM64_REG_D19:         {Name: "d19"},
		uc.ARM64_REG_D20:         {Name: "d20"},
		uc.ARM64_REG_D21:         {Name: "d21"},
		uc.ARM64_REG_D22:         {Name: "d22"},
		uc.ARM64_REG_D23:         {Name: "d23"},
		uc.ARM64_REG_D24:         {Name: "d24"},
		uc.ARM64_REG_D25:         {Name: "d25"},
		uc.ARM64_REG_D26:         {Name: "d26"},
		uc.ARM64_REG_D27:         {Name: "d27"},
		uc.ARM64_REG_D28:         {Name: "d28"},
		uc.ARM64_REG_D29:         {Name: "d29"},
		uc.ARM64_REG_D30:         {Name: "d30"},
		uc.ARM64_REG_D31:         {Name: "d31"},
		uc.ARM64_REG_H0:          {Name: "h0"},
		uc.ARM64_REG_H1:          {Name: "h1"},
		uc.ARM64_REG_H2:          {Name: "h2"},
		uc.ARM64_REG_H3:          {Name: "h3"},
		uc.ARM64_REG_H4:          {Name: "h4"},
		uc.ARM64_REG_H5:          {Name: "h5"},
		uc.ARM64_REG_H6:          {Name: "h6"},
		uc.ARM64_REG_H7:          {Name: "h7"},
		uc.ARM64_REG_H8:          {Name: "h8"},
		uc.ARM64_REG_H9:          {Name: "h9"},
		uc.ARM64_REG_H10:         {Name: "h10"},
		uc.ARM64_REG_H11:         {Name: "h11"},
		uc.ARM64_REG_H12:         {Name: "h12"},
		uc.ARM64_REG_H13:         {Name: "h13"},
		uc.ARM64_REG_H14:         {Name: "h14"},
		uc.ARM64_REG_H15:         {Name: "h15"},
		uc.ARM64_REG_H16:         {Name: "h16"},
		uc.ARM64_REG_H17:         {Name: "h17"},
		uc.ARM64_REG_H18:         {Name: "h18"},
		uc.ARM64_REG_H19:         {Name: "h19"},
		uc.ARM64_REG_H20:         {Name: "h20"},
		uc.ARM64_REG_H21:         {Name: "h21"},
		uc.ARM64_REG_H22:         {Name: "h22"},
		uc.ARM64_REG_H23:         {Name: "h23"},
		uc.ARM64_REG_H24:         {Name: "h24"},
		uc.ARM64_REG_H25:         {Name: "h25"},
		uc.ARM64_REG_H26:         {Name: "h26"},
		uc.ARM64_REG_H27:         {Name: "h27"},
		uc.ARM64_REG_H28:         {Name: "h28"},
		uc.ARM64_REG_H29:         {Name: "h29"},
		uc.ARM64_REG_H30:         {Name: "h30"},
		uc.ARM64_REG_H31:         {Name: "h31"},
		uc.ARM64_REG_Q0:          {Name: "q0"},
		uc.ARM64_REG_Q1:          {Name: "q1"},
		uc.ARM64_REG_Q2:          {Name: "q2"},
		uc.ARM64_REG_Q3:          {Name: "q3"},
		uc.ARM64_REG_Q4:          {Name: "q4"},
		uc.ARM64_REG_Q5:          {Name: "q5"},
		uc.ARM64_REG_Q6:          {Name: "q6"},
		uc.ARM64_REG_Q7:          {Name: "q7"},
		uc.ARM64_REG_Q8:          {Name: "q8"},
		uc.ARM64_REG_Q9:          {Name: "q9"},
		uc.ARM64_REG_Q10:         {Name: "q10"},
		uc.ARM64_REG_Q11:         {Name: "q11"},
		uc.ARM64_REG_Q12:         {Name: "q12"},
		uc.ARM64_REG_Q13:         {Name: "q13"},
		uc.ARM64_REG_Q14:         {Name: "q14"},
		uc.ARM64_REG_Q15:         {Name: "q15"},
		uc.ARM64_REG_Q16:         {Name: "q16"},
		uc.ARM64_REG_Q17:         {Name: "q17"},
		uc.ARM64_REG_Q18:         {Name: "q18"},
		uc.ARM64_REG_Q19:         {Name: "q19"},
		uc.ARM64_REG_Q20:         {Name: "q20"},
		uc.ARM64_REG_Q21:         {Name: "q21"},
		uc.ARM64_REG_Q22:         {Name: "q22"},
		uc.ARM64_REG_Q23:         {Name: "q23"},
		uc.ARM64_REG_Q24:         {Name: "q24"},
		uc.ARM64_REG_Q25:         {Name: "q25"},
		uc.ARM64_REG_Q26:         {Name: "q26"},
		uc.ARM64_REG_Q27:         {Name: "q27"},
		uc.ARM64_REG_Q28:         {Name: "q28"},
		uc.ARM64_REG_Q29:         {Name: "q29"},
		uc.ARM64_REG_Q30:         {Name: "q30"},
		uc.ARM64_REG_Q31:         {Name: "q31"},
		uc.ARM64_REG_S0:          {Name: "s0"},
		uc.ARM64_REG_S1:          {Name: "s1"},
		uc.ARM64_REG_S2:          {Name: "s2"},
		uc.ARM64_REG_S3:          {Name: "s3"},
		uc.ARM64_REG_S4:          {Name: "s4"},
		uc.ARM64_REG_S5:          {Name: "s5"},
		uc.ARM64_REG_S6:          {Name: "s6"},
		uc.ARM64_REG_S7:          {Name: "s7"},
		uc.ARM64_REG_S8:          {Name: "s8"},
		uc.ARM64_REG_S9:          {Name: "s9"},
		uc.ARM64_REG_S10:         {Name: "s10"},
		uc.ARM64_REG_S11:         {Name: "s11"},
		uc.ARM64_REG_S12:         {Name: "s12"},
		uc.ARM64_REG_S13:         {Name: "s13"},
		uc.ARM64_REG_S14:         {Name: "s14"},
		uc.ARM64_REG_S15:         {Name: "s15"},
		uc.ARM64_REG_S16:         {Name: "s16"},
		uc.ARM64_REG_S17:         {Name: "s17"},
		uc.ARM64_REG_S18:         {Name: "s18"},
		uc.ARM64_REG_S19:         {Name: "s19"},
		uc.ARM64_REG_S20:         {Name: "s20"},
		uc.ARM64_REG_S21:         {Name: "s21"},
		uc.ARM64_REG_S22:         {Name: "s22"},
		uc.ARM64_REG_S23:         {Name: "s23"},
		uc.ARM64_REG_S24:         {Name: "s24"},
		uc.ARM64_REG_S25:         {Name: "s25"},
		uc.ARM64_REG_S26:         {Name: "s26"},
		uc.ARM64_REG_S27:         {Name: "s27"},
		uc.ARM64_REG_S28:         {Name: "s28"},
		uc.ARM64_REG_S29:         {Name: "s29"},
		uc.ARM64_REG_S30:         {Name: "s30"},
		uc.ARM64_REG_S31:         {Name: "s31"},
		uc.ARM64_REG_W0:          {Name: "w0"},
		uc.ARM64_REG_W1:          {Name: "w1"},
		uc.ARM64_REG_W2:          {Name: "w2"},
		uc.ARM64_REG_W3:          {Name: "w3"},
		uc.ARM64_REG_W4:          {Name: "w4"},
		uc.ARM64_REG_W5:          {Name: "w5"},
		uc.ARM64_REG_W6:          {Name: "w6"},
		uc.ARM64_REG_W7:          {Name: "w7"},
		uc.ARM64_REG_W8:          {Name: "w8"},
		uc.ARM64_REG_W9:          {Name: "w9"},
		uc.ARM64_REG_W10:         {Name: "w10"},
		uc.ARM64_REG_W11:         {Name: "w11"},
		uc.ARM64_REG_W12:         {Name: "w12"},
		uc.ARM64_REG_W13:         {Name: "w13"},
		uc.ARM64_REG_W14:         {Name: "w14"},
		uc.ARM64_REG_W15:         {Name: "w15"},
		uc.ARM64_REG_W16:         {Name: "w16"},
		uc.ARM64_REG_W17:         {Name: "w17"},
		uc.ARM64_REG_W18:         {Name: "w18"},
		uc.ARM64_REG_W19:         {Name: "w19"},
		uc.ARM64_REG_W20:         {Name: "w20"},
		uc.ARM64_REG_W21:         {Name: "w21"},
		uc.ARM64_REG_W22:         {Name: "w22"},
		uc.ARM64_REG_W23:         {Name: "w23"},
		uc.ARM64_REG_W24:         {Name: "w24"},
		uc.ARM64_REG_W25:         {Name: "w25"},
		uc.ARM64_REG_W26:         {Name: "w26"},
		uc.ARM64_REG_W27:         {Name: "w27"},
		uc.ARM64_REG_W28:         {Name: "w28"},
		uc.ARM64_REG_W29:         {Name: "w29"},
		uc.ARM64_REG_W30:         {Name: "w30"},
		uc.ARM64_REG_X0:          {Name: "x0"},
		uc.ARM64_REG_X1:          {Name: "x1"},
		uc.ARM64_REG_X2:          {Name: "x2"},
		uc.ARM64_REG_X3:          {Name: "x3"},
		uc.ARM64_REG_X4:          {Name: "x4"},
		uc.ARM64_REG_X5:          {Name: "x5"},
		uc.ARM64_REG_X6:          {Name: "x6"},
		uc.ARM64_REG_X7:          {Name: "x7"},
		uc.ARM64_REG_X8:          {Name: "x8"},
		uc.ARM64_REG_X9:          {Name: "x9"},
		uc.ARM64_REG_X10:         {Name: "x10"},
		uc.ARM64_REG_X11:         {Name: "x11"},
		uc.ARM64_REG_X12:         {Name: "x12"},
		uc.ARM64_REG_X13:         {Name: "x13"},
		uc.ARM64_REG_X14:         {Name: "x14"},
		uc.ARM64_REG_X15:         {Name: "x15"},
		uc.ARM64_REG_X16:         {Name: "x16", Alias: "ip0"},
		uc.ARM64_REG_X17:         {Name: "x17", Alias: "ip1"},
		uc.ARM64_REG_X18:         {Name: "x18"},
		uc.ARM64_REG_X19:         {Name: "x19"},
		uc.ARM64_REG_X20:         {Name: "x20"},
		uc.ARM64_REG_X21:         {Name: "x21"},
		uc.ARM64_REG_X22:         {Name: "x22"},
		uc.ARM64_REG_X23:         {Name: "x23"},
		uc.ARM64_REG_X24:         {Name: "x24"},
		uc.ARM64_REG_X25:         {Name: "x25"},
		uc.ARM64_REG_X26:         {Name: "x26"},
		uc.ARM64_REG_X27:         {Name: "x27"},
		uc.ARM64_REG_X28:         {Name: "x28"},
		uc.ARM64_REG_V0:          {Name: "v0"},
		uc.ARM64_REG_V1:          {Name: "v1"},
		uc.ARM64_REG_V2:          {Name: "v2"},
		uc.ARM64_REG_V3:          {Name: "v3"},
		uc.ARM64_REG_V4:          {Name: "v4"},
		uc.ARM64_REG_V5:          {Name: "v5"},
		uc.ARM64_REG_V6:          {Name: "v6"},
		uc.ARM64_REG_V7:          {Name: "v7"},
		uc.ARM64_REG_V8:          {Name: "v8"},
		uc.ARM64_REG_V9:          {Name: "v9"},
		uc.ARM64_REG_V10:         {Name: "v10"},
		uc.ARM64_REG_V11:         {Name: "v11"},
		uc.ARM64_REG_V12:         {Name: "v12"},
		uc.ARM64_REG_V13:         {Name: "v13"},
		uc.ARM64_REG_V14:         {Name: "v14"},
		uc.ARM64_REG_V15:         {Name: "v15"},
		uc.ARM64_REG_V16:         {Name: "v16"},
		uc.ARM64_REG_V17:         {Name: "v17"},
		uc.ARM64_REG_V18:         {Name: "v18"},
		uc.ARM64_REG_V19:         {Name: "v19"},
		uc.ARM64_REG_V20:         {Name: "v20"},
		uc.ARM64_REG_V21:         {Name: "v21"},
		uc.ARM64_REG_V22:         {Name: "v22"},
		uc.ARM64_REG_V23:         {Name: "v23"},
		uc.ARM64_REG_V24:         {Name: "v24"},
		uc.ARM64_REG_V25:         {Name: "v25"},
		uc.ARM64_REG_V26:         {Name: "v26"},
		uc.ARM64_REG_V27:         {Name: "v27"},
		uc.ARM64_REG_V28:         {Name: "v28"},
		uc.ARM64_REG_V29:         {Name: "v29"},
		uc.ARM64_REG_V30:         {Name: "v30"},
		uc.ARM64_REG_V31:         {Name: "v31"},
		uc.ARM64_REG_PC:          {Name: "pc"},
		uc.ARM64_REG_CPACR_EL1:   {Name: "cpacr_el1"},
		uc.ARM64_REG_TPIDR_EL0:   {Name: "tpidr_el0"},
		uc.ARM64_REG_TPIDRRO_EL0: {Name: "tpidrro_el0"},
		uc.ARM64_REG_TPIDR_EL1:   {Name: "tpidr_el1"},
		uc.ARM64_REG_PSTATE:      {Name: "pstate"},
		uc.ARM64_REG_ELR_EL0:     {Name: "elr_el0"},
		uc.ARM64_REG_ELR_EL1:     {Name: "elr_el1"},
		uc.ARM64_REG_ELR_EL2:     {Name: "elr_el2"},
		uc.ARM64_REG_ELR_EL3:     {Name: "elr_el3"},
		uc.ARM64_REG_SP_EL0:      {Name: "sp_el0"},
		uc.ARM64_REG_SP_EL1:      {Name: "sp_el1"},
		uc.ARM64_REG_SP_EL2:      {Name: "sp_el2"},
		uc.ARM64_REG_SP_EL3:      {Name: "sp_el3"},
		uc.ARM64_REG_TTBR0_EL1:   {Name: "ttbr0_el1"},
		uc.ARM64_REG_TTBR1_EL1:   {Name: "ttbr1_el1"},
		uc.ARM64_REG_ESR_EL0:     {Name: "esr_el0"},
		uc.ARM64_REG_ESR_EL1:     {Name: "esr_el1"},
		uc.ARM64_REG_ESR_EL2:     {Name: "esr_el2"},
		uc.ARM64_REG_ESR_EL3:     {Name: "esr_el3"},
		uc.ARM64_REG_FAR_EL0:     {Name: "far_el0"},
		uc.ARM64_REG_FAR_EL1:     {Name: "far_el1"},
		uc.ARM64_REG_FAR_EL2:     {Name: "far_el2"},
		uc.ARM64_REG_FAR_EL3:     {Name: "far_el3"},
		uc.ARM64_REG_PAR_EL1:     {Name: "par_el1"},
		uc.ARM64_REG_MAIR_EL1:    {Name: "mair_el1"},
		uc.ARM64_REG_VBAR_EL0:    {Name: "vbar_el0"},
		uc.ARM64_REG_VBAR_EL1:    {Name: "vbar_el1"},
		uc.ARM64_REG_VBAR_EL2:    {Name: "vbar_el2"},
		uc.ARM64_REG_VBAR_EL3:    {Name: "vbar_el3"},
		uc.ARM64_REG_ENDING:      {Name: "ending"},
	}
}

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
		if e.regs[regs[idx]].Value == val {
			e.regs[regs[idx]].Value = val
			e.regs[regs[idx]].DidChange = false
		} else {
			e.regs[regs[idx]].Value = val
			e.regs[regs[idx]].DidChange = true
		}
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
				"     pc: %#-18x  sp: %#-18x  pstate: %#08x %s",
			r[uc.ARM64_REG_X0].Value, r[uc.ARM64_REG_X1].Value, r[uc.ARM64_REG_X2].Value, r[uc.ARM64_REG_X3].Value,
			r[uc.ARM64_REG_X4].Value, r[uc.ARM64_REG_X5].Value, r[uc.ARM64_REG_X6].Value, r[uc.ARM64_REG_X7].Value,
			r[uc.ARM64_REG_X8].Value, r[uc.ARM64_REG_X9].Value, r[uc.ARM64_REG_X10].Value, r[uc.ARM64_REG_X11].Value,
			r[uc.ARM64_REG_X12].Value, r[uc.ARM64_REG_X13].Value, r[uc.ARM64_REG_X14].Value, r[uc.ARM64_REG_X15].Value,
			r[uc.ARM64_REG_X16].Value, r[uc.ARM64_REG_X17].Value, r[uc.ARM64_REG_X18].Value, r[uc.ARM64_REG_X19].Value,
			r[uc.ARM64_REG_X20].Value, r[uc.ARM64_REG_X21].Value, r[uc.ARM64_REG_X22].Value, r[uc.ARM64_REG_X23].Value,
			r[uc.ARM64_REG_X24].Value, r[uc.ARM64_REG_X25].Value, r[uc.ARM64_REG_X26].Value, r[uc.ARM64_REG_X27].Value,
			r[uc.ARM64_REG_X28].Value, r[uc.ARM64_REG_FP].Value, r[uc.ARM64_REG_LR].Value,
			r[uc.ARM64_REG_PC].Value, r[uc.ARM64_REG_SP].Value, r[uc.ARM64_REG_PSTATE].Value, pstate(r[uc.ARM64_REG_PSTATE].Value),
		))
}

func (r Registers) Changed() string {
	return fmt.Sprintf(
		"     %s  %s  %s  %s\n"+
			"     %s  %s  %s  %s\n"+
			"     %s  %s %s %s\n"+
			"    %s %s %s %s\n"+
			"    %s %s %s %s\n"+
			"    %s %s %s %s\n"+
			"    %s %s %s %s\n"+
			"    %s  %s  %s\n"+
			"     %s  %s %s %s",
		r[uc.ARM64_REG_X0], r[uc.ARM64_REG_X1], r[uc.ARM64_REG_X2], r[uc.ARM64_REG_X3],
		r[uc.ARM64_REG_X4], r[uc.ARM64_REG_X5], r[uc.ARM64_REG_X6], r[uc.ARM64_REG_X7],
		r[uc.ARM64_REG_X8], r[uc.ARM64_REG_X9], r[uc.ARM64_REG_X10], r[uc.ARM64_REG_X11],
		r[uc.ARM64_REG_X12], r[uc.ARM64_REG_X13], r[uc.ARM64_REG_X14], r[uc.ARM64_REG_X15],
		r[uc.ARM64_REG_X16], r[uc.ARM64_REG_X17], r[uc.ARM64_REG_X18], r[uc.ARM64_REG_X19],
		r[uc.ARM64_REG_X20], r[uc.ARM64_REG_X21], r[uc.ARM64_REG_X22], r[uc.ARM64_REG_X23],
		r[uc.ARM64_REG_X24], r[uc.ARM64_REG_X25], r[uc.ARM64_REG_X26], r[uc.ARM64_REG_X27],
		r[uc.ARM64_REG_X28], r[uc.ARM64_REG_FP], r[uc.ARM64_REG_LR],
		r[uc.ARM64_REG_PC], r[uc.ARM64_REG_SP], r[uc.ARM64_REG_PSTATE], pstate(r[uc.ARM64_REG_PSTATE].Value),
	)
}

func (r Registers) AllChanged() string {
	var out string
	for _, val := range r {
		if val.DidChange {
			out += fmt.Sprintf("%s\n", val)
		}
	}
	return out
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

func (p pstate) PAN() bool {
	return types.ExtractBits(uint64(p), 23, 1) != 0
}
func (p pstate) UAO() bool {
	return types.ExtractBits(uint64(p), 22, 1) != 0
}
func (p pstate) BType() branchType {
	return branchType(types.ExtractBits(uint64(p), 10, 2))
}
func (p pstate) SS() bool {
	return types.ExtractBits(uint64(p), 21, 1) != 0
}
func (p pstate) IL() bool {
	return types.ExtractBits(uint64(p), 20, 1) != 0
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
	if p.UAO() {
		flags = append(flags, "UAO")
	}
	if p.PAN() {
		flags = append(flags, "PAN")
	}
	if p.SS() {
		flags = append(flags, "SS")
	}
	if p.IL() {
		flags = append(flags, "IL")
	}
	if p.BType() > 0 {
		flags = append(flags, p.BType().String())
	}
	if p.M() > 0 {
		flags = append(flags, p.M().String())
	}
	if len(flags) > 0 {
		return colorDetails("[%s]", strings.Join(flags, " "))
	}
	return ""
}
