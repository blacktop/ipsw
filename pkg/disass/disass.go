package disass

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/internal/utils"
)

type Disass interface {
	// ParseGOT() error
	// ParseObjC() error
	// ParseStubs() error
	// ParseHelpers() error
	Triage() error
	IsBranchLocation(uint64) bool
	FindSymbol(uint64) (string, bool)
	GetCString(uint64) (string, error)
	isMiddle() bool
	demangle() bool
	quite() bool
	asJSON() bool
	data() []byte
	startAddr() uint64
}

type opName uint32

const (
	AMXLDX opName = iota
	AMXLDY
	AMXSTX
	AMXSTY
	AMXLDZ
	AMXSTZ
	AMXLDZI
	AMXSTZI
	AMXEXTRX // amxextrx?
	AMXEXTRY // amxextry?
	AMXFMA64
	AMXFMS64
	AMXFMA32
	AMXFMS32
	AMXMAC16
	AMXFMA16
	AMXFMS16
	AMX17 // amxset / amxclr
	AMXVECINT
	AMXVECFP
	AMXMATINT
	AMXMATFP
	AMXGENLUT
)

func (o opName) String() string {
	switch o {
	case AMXLDX:
		return "amx_ldx"
	case AMXLDY:
		return "amx_ldy"
	case AMXSTX:
		return "amx_stx"
	case AMXSTY:
		return "amx_sty"
	case AMXLDZ:
		return "amx_ldz"
	case AMXSTZ:
		return "amx_stz"
	case AMXLDZI:
		return "amx_ldzi"
	case AMXSTZI:
		return "amx_stzi"
	case AMXEXTRX:
		return "amx_extrx"
	case AMXEXTRY:
		return "amx_extry"
	case AMXFMA64:
		return "amx_fma64"
	case AMXFMS64:
		return "amx_fms64"
	case AMXFMA32:
		return "amx_fma32"
	case AMXFMS32:
		return "amx_fms32"
	case AMXMAC16:
		return "amx_mac16"
	case AMXFMA16:
		return "amx_fma16"
	case AMXFMS16:
		return "amx_fms16"
	case AMX17:
		return "amx_op17"
	case AMXVECINT:
		return "amx_vecint"
	case AMXVECFP:
		return "amx_vecfp"
	case AMXMATINT:
		return "amx_matint"
	case AMXMATFP:
		return "amx_matfp"
	case AMXGENLUT:
		return "amx_genlut"
	default:
		return "unk"
	}
}

type Config struct {
	Image        string
	Data         []byte
	StartAddress uint64
	Middle       bool
	AsJSON       bool
	Demangle     bool
	Quite        bool
}

func Disassemble(d Disass) {
	var instrStr string
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction
	var instructions []disassemble.Instruction

	r := bytes.NewReader(d.data())

	if !d.asJSON() {
		if name, ok := d.FindSymbol(d.startAddr()); ok && !d.asJSON() {
			fmt.Printf("%s:\n", name)
		} else {
			fmt.Printf("sub_%x:\n", d.startAddr())
		}
	}

	startAddr := d.startAddr()

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		if !d.asJSON() {
			instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
			if err != nil {
				if instrValue == 0xfeedfacf {
					fmt.Printf("%#08x:  %s\t.long\t%#x ; (possible embedded MachO)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue)
					break
				} else if instrValue == 0x201420 {
					fmt.Printf("%#08x:  %s\tgenter\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue))
					continue
				} else if instrValue == 0x00201400 {
					fmt.Printf("%#08x:  %s\tgexit\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue))
					continue
				} else if instrValue == 0xe7ffdefe || instrValue == 0xe7ffdeff {
					fmt.Printf("%#08x:  %s\ttrap\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue))
					continue
				} else if instrValue > 0xffff0000 {
					fmt.Printf("%#08x:  %s\t.long\t%#x ; (probably a jump-table)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue)
					break
				} else if prevInstr != nil && strings.Contains(prevInstr.Operation.String(), "braa") {
					break
				} else if (instrValue & 0xfffffC00) == 0x00201000 {
					Xr := disassemble.Register((instrValue & 0x1F) + 34)
					m := (instrValue >> 5) & 0x1F
					if m == 17 {
						if instrValue&0x1F == 0 {
							fmt.Printf("%#08x:  %s\tamxset\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue))
						} else {
							fmt.Printf("%#08x:  %s\tamxclr\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue))
						}
					} else {
						fmt.Printf("%#08x:  %s\t%s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), opName(m), Xr.String())
					}
					continue
				} else if instrValue>>21 == 1 {
					fmt.Printf("%#08x:  %s\t.long\t%#x ; (possible unknown Apple instruction)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue)
					continue
				} else if cstr, err := d.GetCString(startAddr); err == nil {
					if utils.IsASCII(cstr) {
						if len(cstr) > 200 {
							fmt.Printf("%#08x:  %s\tDCB\t%#v\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), cstr[:200])
							break
						} else if len(cstr) > 1 {
							fmt.Printf("%#08x:  %s\tDCB\t%#v\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), cstr)
							break
						}
					}
				}
				fmt.Printf("%#08x:  %s\t.long\t%#x ; (%s)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue, err.Error())
				break
			}

			instrStr = instruction.String()

			if !d.quite() {
				if d.IsBranchLocation(instruction.Address) {
					fmt.Printf("%#08x:  ; loc_%x\n", instruction.Address, instruction.Address)
				}
				if instruction.Operation == disassemble.ARM64_MRS || instruction.Operation == disassemble.ARM64_MSR {
					var ops []string
					replaced := false
					for _, op := range instruction.Operands {
						if op.Class == disassemble.REG {
							ops = append(ops, op.Registers[0].String())
						} else if op.Class == disassemble.IMPLEMENTATION_SPECIFIC {
							sysRegFix := op.ImplSpec.GetSysReg().String()
							if len(sysRegFix) > 0 {
								ops = append(ops, sysRegFix)
								replaced = true
							}
						}
						if replaced {
							instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, strings.Join(ops, ", "))
						}
					}
				} else if instruction.Encoding == disassemble.ENC_BL_ONLY_BRANCH_IMM || instruction.Encoding == disassemble.ENC_B_ONLY_BRANCH_IMM {
					if name, ok := d.FindSymbol(uint64(instruction.Operands[0].Immediate)); ok {
						instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, name)
					}
				} else if instruction.Encoding == disassemble.ENC_CBZ_64_COMPBRANCH {
					if name, ok := d.FindSymbol(uint64(instruction.Operands[1].Immediate)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					}
				} else if instruction.Operation == disassemble.ARM64_ADR {
					adrImm := instruction.Operands[1].Immediate
					if name, ok := d.FindSymbol(uint64(adrImm)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					} else if cstr, err := d.GetCString(adrImm); err == nil {
						if utils.IsASCII(cstr) {
							if len(cstr) > 200 {
								instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
							} else if len(cstr) > 1 {
								instrStr += fmt.Sprintf(" ; %#v", cstr)
							}
						}
					}
				} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
					(instruction.Operation == disassemble.ARM64_ADD ||
						instruction.Operation == disassemble.ARM64_LDR ||
						instruction.Operation == disassemble.ARM64_LDRB) {
					adrpRegister := prevInstr.Operands[0].Registers[0]
					adrpImm := prevInstr.Operands[1].Immediate
					if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					} else if instruction.Operation == disassemble.ARM64_LDRB && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[2].Immediate
					}
					if name, ok := d.FindSymbol(uint64(adrpImm)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					} else if cstr, err := d.GetCString(adrpImm); err == nil {
						if utils.IsASCII(cstr) {
							if len(cstr) > 200 {
								instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
							} else if len(cstr) > 1 {
								instrStr += fmt.Sprintf(" ; %#v", cstr)
							}
						}
					}
				}

				if instruction.Encoding == disassemble.ENC_LDR_B_LDST_IMMPRE {
					fmt.Println(instrStr)
				}
			}

			if d.isMiddle() && d.startAddr() == startAddr {
				fmt.Printf("👉%08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr)
			} else {
				fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr)
			}

			prevInstr = instruction
		} else { // output as JSON
			instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
			if err != nil {
				log.Error(err.Error())
				continue // TODO: should we still capture this in the JSON?
			}
			instructions = append(instructions, *instruction)
		}

		startAddr += uint64(binary.Size(uint32(0)))
	}

	if d.asJSON() {
		if dat, err := json.MarshalIndent(instructions, "", "   "); err == nil {
			fmt.Println(string(dat))
		}
	}
}
