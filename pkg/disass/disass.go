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
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
)

type Disass interface {
	Triage() error
	IsFunctionStart(uint64) (bool, string)
	IsLocation(uint64) bool
	IsBranchLocation(uint64) (bool, uint64)
	IsData(uint64) (bool, *AddrDetails)
	FindSymbol(uint64) (string, bool)
	GetCString(uint64) (string, error)
	// getters
	IsMiddle() bool
	Demangle() bool
	Quite() bool
	AsJSON() bool
	Data() []byte
	StartAddr() uint64
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
type AddrDetails struct {
	Image   string
	Segment string
	Section string
}

func (d AddrDetails) String() string {
	return fmt.Sprintf("%s/%s.%s", d.Image, d.Segment, d.Section)
}

type Triage struct {
	Details   map[uint64]AddrDetails
	Function  *types.Function
	Addresses map[uint64]uint64
	Locations map[uint64][]uint64
}

func Disassemble(d Disass) {
	var instrStr string
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction
	var instructions []disassemble.Instruction

	r := bytes.NewReader(d.Data())

	startAddr := d.StartAddr()

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		if !d.AsJSON() {
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

			if !d.Quite() {
				// check for start of a new function
				if ok, fname := d.IsFunctionStart(instruction.Address); ok {
					if len(fname) > 0 {
						fmt.Printf("\n%s:\n", fname)
					} else {
						fmt.Printf("\nsub_%x:\n", instruction.Address)
					}
				}

				if d.IsLocation(instruction.Address) {
					fmt.Printf("%#08x:  ; loc_%x\n", instruction.Address, instruction.Address)
				}

				// if ok, imm := triage.HasLoc(i.Instruction.Address()); ok {
				// 	if detail, ok := triage.Details[imm]; ok {
				// 		if triage.IsData(imm) {
				// 			opStr += fmt.Sprintf(" ; %s", detail)
				// 		} else {
				// 			opStr += fmt.Sprintf(" ; %s", detail)
				// 		}
				// 	}
				// }

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
				} else if ok, loc := d.IsBranchLocation(instruction.Address); ok {
					opStr := strings.TrimPrefix(instrStr, fmt.Sprintf("%s\t", instruction.Operation))
					for _, operand := range instruction.Operands {
						if operand.Class == disassemble.LABEL {
							if name, ok := d.FindSymbol(uint64(operand.Immediate)); ok {
								opStr = name
							} else {
								direction := ""
								delta := int(loc) - int(instruction.Address)
								if delta > 0 {
									direction = fmt.Sprintf(" ; ⤵ %#x", delta)
								} else if delta == 0 {
									direction = " ; ∞ loop"
								} else {
									direction = fmt.Sprintf(" ; ⤴ %#x", delta)
								}
								opStr = strings.Replace(opStr, fmt.Sprintf("%#x", loc), fmt.Sprintf("loc_%x%s", loc, direction), 1)
							}
						}
					}
					instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, opStr)
				} else if instruction.Encoding == disassemble.ENC_BL_ONLY_BRANCH_IMM || instruction.Encoding == disassemble.ENC_B_ONLY_BRANCH_IMM {
					if name, ok := d.FindSymbol(uint64(instruction.Operands[0].Immediate)); ok {
						instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, name)
					}
				} else if strings.Contains(instruction.Encoding.String(), "loadlit") {
					if name, ok := d.FindSymbol(uint64(instruction.Operands[1].Immediate)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					}
				} else if instruction.Encoding == disassemble.ENC_CBZ_64_COMPBRANCH {
					if name, ok := d.FindSymbol(uint64(instruction.Operands[1].Immediate)); ok {
						instrStr += fmt.Sprintf(" ; %s", name)
					}
				} else if instruction.Operation == disassemble.ARM64_ADR {
					opStr := strings.TrimPrefix(instrStr, fmt.Sprintf("%s\t", instruction.Operation))
					for _, operand := range instruction.Operands {
						if operand.Class == disassemble.LABEL {
							if name, ok := d.FindSymbol(uint64(operand.Immediate)); ok {
								opStr = strings.Replace(opStr, fmt.Sprintf("%#x", operand.Immediate), name, 1)
							} else if cstr, err := d.GetCString(uint64(operand.Immediate)); err == nil {
								if utils.IsASCII(cstr) {
									if len(cstr) > 200 {
										instrStr += fmt.Sprintf(" ; %#v...", cstr[:200])
									} else if len(cstr) > 1 {
										instrStr += fmt.Sprintf(" ; %#v", cstr)
									}
								}
							}
						}
					}
					instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, opStr)
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
					} else if ok, detail := d.IsData(adrpImm); ok {
						instrStr += fmt.Sprintf(" ; dat_%x (%s)", adrpImm, detail)
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

			if d.IsMiddle() && d.StartAddr() == startAddr {
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

	if d.AsJSON() {
		if dat, err := json.MarshalIndent(instructions, "", "   "); err == nil {
			fmt.Println(string(dat))
		}
	}
}

func ParseGotPtrs(m *macho.File) (map[uint64]uint64, error) {

	gots := make(map[uint64]uint64)

	if authPtr := m.Section("__AUTH_CONST", "__auth_ptr"); authPtr != nil {
		dat, err := authPtr.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to get %s.%s section data: %v", authPtr.Seg, authPtr.Name, err)
		}

		ptrs := make([]uint64, authPtr.Size/8)
		if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
			return nil, fmt.Errorf("failed to read __AUTH_CONST.__auth_ptr ptrs; %v", err)
		}

		for idx, ptr := range ptrs {
			gots[authPtr.Addr+uint64(idx*8)] = m.SlidePointer(ptr)
		}
	}

	for _, sec := range m.Sections {
		if sec.Flags.IsNonLazySymbolPointers() || sec.Flags.IsLazySymbolPointers() { // TODO: make sure this doesn't break things
			dat, err := sec.Data()
			if err != nil {
				return nil, fmt.Errorf("failed to get %s.%s section data: %v", sec.Seg, sec.Name, err)
			}

			ptrs := make([]uint64, sec.Size/8)
			if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
				return nil, fmt.Errorf("failed to read %s.%s NonLazySymbol pointers; %v", sec.Seg, sec.Name, err)
			}

			for idx, ptr := range ptrs {
				gots[sec.Addr+uint64(idx*8)] = m.SlidePointer(ptr)
			}
		}
	}

	return gots, nil
}

func ParseStubsASM(m *macho.File) (map[uint64]uint64, error) {

	stubs := make(map[uint64]uint64)

	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {
			var adrpImm uint64
			var adrpAddr uint64
			var instrValue uint32
			var results [1024]byte
			var prevInst *disassemble.Instruction

			dat, err := sec.Data()
			if err != nil {
				return nil, err
			}

			r := bytes.NewReader(dat)

			startAddr := sec.Addr

			for {
				err = binary.Read(r, binary.LittleEndian, &instrValue)

				if err == io.EOF {
					break
				}

				instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
				if err != nil {
					startAddr += uint64(binary.Size(uint32(0)))
					continue
				}

				if (prevInst != nil && prevInst.Operation == disassemble.ARM64_ADRP) &&
					instruction.Operation == disassemble.ARM64_ADD {
					if instruction.Operands != nil && prevInst.Operands != nil {
						// adrp      	x17, #0x1e3be9000
						adrpRegister := prevInst.Operands[0].Registers[0] // x17
						adrpImm = prevInst.Operands[1].Immediate          // #0x1e3be9000
						// add       	x17, x17, #0x1c0
						if adrpRegister == instruction.Operands[0].Registers[0] {
							adrpImm += instruction.Operands[2].Immediate
							adrpAddr = prevInst.Address
						}
					}
				} else if (prevInst != nil && prevInst.Operation == disassemble.ARM64_ADRP) &&
					instruction.Operation == disassemble.ARM64_LDR {
					if instruction.Operands != nil && prevInst.Operands != nil {
						// adrp	x16, #0x1e3be9000
						adrpRegister := prevInst.Operands[0].Registers[0] // x16
						adrpImm = prevInst.Operands[1].Immediate          // #0x1e3be9000
						// ldr	x16, [x16, #0x560]
						if adrpRegister == instruction.Operands[0].Registers[0] {
							adrpImm += instruction.Operands[1].Immediate
							adrpAddr = prevInst.Address
							addr, err := m.GetPointerAtAddress(adrpImm)
							if err != nil {
								return nil, fmt.Errorf("failed to read pointer at %#x: %v", adrpImm, err)
							}
							stubs[adrpAddr] = addr
						}
					}
				} else if (prevInst != nil && prevInst.Operation == disassemble.ARM64_ADD) &&
					instruction.Operation == disassemble.ARM64_LDR {
					// add       	x17, x17, #0x1c0
					addRegister := prevInst.Operands[0].Registers[0] // x17
					// ldr       	x16, [x17]
					if addRegister == instruction.Operands[1].Registers[0] {
						addr, err := m.GetPointerAtAddress(adrpImm)
						if err != nil {
							return nil, fmt.Errorf("failed to read pointer at %#x: %v", adrpImm, err)
						}
						stubs[adrpAddr] = addr
					}
				} else if (prevInst != nil && prevInst.Operation == disassemble.ARM64_ADD) &&
					instruction.Operation == disassemble.ARM64_BR {
					// add       	x16, x16, #0x828
					addRegister := prevInst.Operands[0].Registers[0] // x16
					// br        	x16
					if addRegister == instruction.Operands[0].Registers[0] {
						stubs[adrpAddr] = m.SlidePointer(adrpImm)
					}
				}

				prevInst = instruction
				startAddr += uint64(binary.Size(uint32(0)))
			}
		}
	}

	return stubs, nil
}

func ParseHelpersASM(m *macho.File) (map[uint64]uint64, error) {
	var instrValue uint32
	var results [1024]byte

	helpers := make(map[uint64]uint64)

	if sec := m.Section("__TEXT", "__stub_helper"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, err
		}

		startAddr := sec.Addr
		stubHelperFnStart := startAddr

		r := bytes.NewReader(dat)

		for {
			err := binary.Read(r, binary.LittleEndian, &instrValue)

			if err == io.EOF {
				break
			}

			instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
			if err != nil {
				startAddr += uint64(binary.Size(uint32(0)))
				continue
			}

			if instruction.Encoding == disassemble.ENC_BR_64_BRANCH_REG { // check if branch location is a function
				startAddr += uint64(binary.Size(uint32(0)))
				stubHelperFnStart = startAddr
				// fmt.Printf("%#08x:  %s\t%s\n", instruction.Address, disassemble.GetOpCodeByteString(instrValue), instruction)
				// fmt.Println()
				continue
			}
			if instruction.Encoding == disassemble.ENC_BL_ONLY_BRANCH_IMM {
				helpers[stubHelperFnStart] = instruction.Operands[0].Immediate
			}
			// fmt.Printf("%#08x:  %s\t%s\n", instruction.Address, disassemble.GetOpCodeByteString(instrValue), instruction)
			startAddr += uint64(binary.Size(uint32(0)))
		}

		return helpers, nil
	}

	return nil, fmt.Errorf("dylib does NOT contain __TEXT.__stub_helper section: %w", macho.ErrMachOSectionNotFound)
}
