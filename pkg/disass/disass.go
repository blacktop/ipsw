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
	IsPointer(uint64) (bool, *AddrDetails)
	FindSymbol(uint64) (string, bool)
	GetCString(uint64) (string, error)
	// getters
	Demangle() bool
	Quite() bool
	Color() bool
	AsJSON() bool
	Data() []byte
	StartAddr() uint64
	Middle() uint64
	ReadAddr(uint64) (uint64, error)
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
	Middle       uint64
	AsJSON       bool
	Demangle     bool
	Quite        bool
	Color        bool
}
type AddrDetails struct {
	Image   string
	Segment string
	Section string
	Pointer uint64
}

func (d AddrDetails) String() string {
	if len(d.Image) > 0 {
		return fmt.Sprintf("%s/%s.%s", d.Image, d.Segment, d.Section)
	}
	return fmt.Sprintf("%s.%s", d.Segment, d.Section)
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
			var comment string
			instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
			if err != nil {
				var op string
				var oprs string
				if instrValue == 0xfeedfacf {
					op = ".long"
					oprs = fmt.Sprintf("%#x", instrValue)
					comment = " ; (possible embedded MachO)"
				} else if instrValue == 0x201420 {
					op = "genter"
				} else if instrValue == 0x00201400 {
					op = "gexit"
				} else if instrValue == 0xe7ffdefe || instrValue == 0xe7ffdeff {
					op = "trap"
				} else if instrValue > 0xffff0000 {
					op = ".long"
					oprs = fmt.Sprintf("%#x", instrValue)
					comment = " ; (probably a jump-table)"
				} else if prevInstr != nil && strings.Contains(prevInstr.Operation.String(), "braa") {
					break // TODO: why did I do this again?
				} else if (instrValue & 0xfffffC00) == 0x00201000 {
					Xr := disassemble.Register((instrValue & 0x1F) + 34)
					m := (instrValue >> 5) & 0x1F
					if m == 17 {
						if instrValue&0x1F == 0 {
							op = "amxset"
						} else {
							op = "amxclr"
						}
					} else {
						op = opName(m).String()
						oprs = Xr.String()
					}
				} else if instrValue>>21 == 1 {
					op = ".long"
					oprs = fmt.Sprintf("%#x", instrValue)
					comment = " ; (possible unknown Apple instruction)"
				} else if cstr, err := d.GetCString(startAddr); err == nil {
					op = "DCB"
					if utils.IsASCII(cstr) {
						if len(cstr) > 200 {
							comment = fmt.Sprintf("%#v", cstr[:200])
						} else if len(cstr) > 1 {
							comment = fmt.Sprintf("%#v", cstr)
						}
					}
					// TODO: should I advance startAddr past the end of the cstring ?
					// Otherwise it'll try and disass the rest of the string (that we already printed)
				} else {
					op = ".long"
					oprs = fmt.Sprintf("%#x", instrValue)
					comment = fmt.Sprintf(" ; (%s)", err.Error())
				}

				if d.Color() {
					fmt.Printf("%s:  %s   %s %s%s\n",
						colorAddr("%#08x", uint64(startAddr)),
						colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
						colorOp("%-7s", op),
						ColorOperands(" "+oprs),
						colorComment(comment),
					)
				} else {
					fmt.Printf("%#08x:  %s   %s\t%s%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), op, oprs, comment)
				}

				goto INCR_ADDR
			}

			instrStr = instruction.String()

			if !d.Quite() {
				// check for start of a new function
				if ok, fname := d.IsFunctionStart(instruction.Address); ok {
					if d.Color() {
						fmt.Print(colorOp("\n%s:\n", fname))
					} else {
						fmt.Printf("\n%s:\n", fname)
					}
				} else {
					if name, ok := d.FindSymbol(uint64(instruction.Address)); ok {
						if d.Color() {
							fmt.Print(colorOp("\n%s\n", name))
						} else {
							fmt.Printf("\n%s\n", name)
						}
					}
				}

				if d.IsLocation(instruction.Address) {
					if d.Color() {
						fmt.Printf("%s\n", colorLocation("loc_%x", instruction.Address))
					} else {
						fmt.Printf("%#08x:  ; loc_%x\n", instruction.Address, instruction.Address)
					}
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
									direction = " ; ∞ loop" // TODO: I should break these out into a comment var like in errors (might speed up colorization)
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
						comment = fmt.Sprintf(" ; %s", name)
					}
				} else if instruction.Encoding == disassemble.ENC_CBZ_64_COMPBRANCH {
					if name, ok := d.FindSymbol(uint64(instruction.Operands[1].Immediate)); ok {
						comment = fmt.Sprintf(" ; %s", name)
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
										comment = fmt.Sprintf(" ; %#v...", cstr[:200])
									} else if len(cstr) > 1 {
										comment = fmt.Sprintf(" ; %#v", cstr)
									}
								}
							}
						}
					}
					instrStr = fmt.Sprintf("%s\t%s", instruction.Operation, opStr)
				} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
					(instruction.Operation == disassemble.ARM64_ADD ||
						instruction.Operation == disassemble.ARM64_LDR ||
						instruction.Operation == disassemble.ARM64_LDRB ||
						instruction.Operation == disassemble.ARM64_LDRSW) {
					adrpRegister := prevInstr.Operands[0].Registers[0]
					adrpImm := prevInstr.Operands[1].Immediate
					if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					} else if instruction.Operation == disassemble.ARM64_LDRB && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[2].Immediate
					} else if instruction.Operation == disassemble.ARM64_LDRSW && adrpRegister == instruction.Operands[1].Registers[0] {
						adrpImm += instruction.Operands[1].Immediate
					}
					if name, ok := d.FindSymbol(uint64(adrpImm)); ok {
						if ok, detail := d.IsData(adrpImm); ok {
							_ = detail
							if ok, detail := d.IsPointer(adrpImm); ok {
								fmt.Printf("ptr_%x: .quad %s ; %s\n", adrpImm, detail, name)
							}
							if ptr, err := d.ReadAddr(adrpImm); err == nil {
								if ptrname, ok := d.FindSymbol(ptr); ok {
									comment = fmt.Sprintf(" ; %s _ptr.%s", name, ptrname)
								}
							}
						} else {
							comment = fmt.Sprintf(" ; %s", name)
						}
					} else if ok, detail := d.IsPointer(adrpImm); ok {
						if name, ok := d.FindSymbol(uint64(detail.Pointer)); ok {
							comment = fmt.Sprintf(" ; _ptr.%s", name)
						} else {
							comment = fmt.Sprintf(" ; _ptr.%x (%s)", detail.Pointer, detail)
						}
					} else if ok, detail := d.IsData(adrpImm); ok {
						instrStr += fmt.Sprintf(" ; dat_%x (%s)", adrpImm, detail)
					} else if cstr, err := d.GetCString(adrpImm); err == nil && len(cstr) > 0 {
						if utils.IsASCII(cstr) {
							if len(cstr) > 200 {
								comment = fmt.Sprintf(" ; %#v...", cstr[:200])
							} else if len(cstr) > 1 {
								comment = fmt.Sprintf(" ; %#v", cstr)
							}
						} else { // try again with immediate as pointer
							if ptr, err := d.ReadAddr(adrpImm); err == nil {
								if name, ok := d.FindSymbol(ptr); ok {
									comment = fmt.Sprintf(" ; _ptr.%s", name)
								}
							}
						}
					}
				}

				if instruction.Encoding == disassemble.ENC_LDR_B_LDST_IMMPRE {
					fmt.Println(instrStr)
				}
			}

			if d.Middle() != 0 && d.Middle() == startAddr {
				if d.Color() {
					opStr := strings.TrimSpace(strings.TrimPrefix(instrStr, instruction.Operation.String()))
					printCurLine("=>%08x:  %s   %-7s %s%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instruction.Operation, opStr, comment)
				} else {
					fmt.Printf("=>%08x:  %s\t%s%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr, comment)
				}
			} else {
				if d.Color() {
					opStr := strings.TrimSpace(strings.TrimPrefix(instrStr, instruction.Operation.String()))
					fmt.Printf("%s:  %s   %s %s%s\n",
						colorAddr("%#08x", uint64(startAddr)),
						colorOpCodes(disassemble.GetOpCodeByteString(instrValue)),
						colorOp("%-7s", instruction.Operation),
						ColorOperands(" "+opStr),
						colorComment(comment),
					)
				} else {
					fmt.Printf("%#08x:  %s   %s%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrStr, comment)
				}
			}

			prevInstr = instruction
		} else { // output as JSON
			instruction, err := disassemble.Decompose(startAddr, instrValue, &results) // TODO: it would probably be valuable to add a "comment" field and capture the analysis above for JSON peeps
			if err != nil {
				instructions = append(instructions, disassemble.Instruction{
					Address:     startAddr,
					Raw:         instrValue,
					Encoding:    0,
					Operation:   0,
					Operands:    nil,
					SetFlags:    0,
					Disassembly: fmt.Sprintf(".long\t%#x ; (%s)\n", instrValue, err.Error()), // TODO: same with error enhancements above
				})
				goto INCR_ADDR
			}
			instructions = append(instructions, *instruction)
		}
	INCR_ADDR:
		startAddr += uint64(binary.Size(uint32(0)))
	}

	if d.AsJSON() {
		var curFunc string
		funcsJSON := make(map[string][]disassemble.Instruction)
		for _, inst := range instructions {
			if ok, fname := d.IsFunctionStart(inst.Address); ok {
				curFunc = fname
				funcsJSON[curFunc] = append(funcsJSON[curFunc], inst)
			} else {
				if len(curFunc) > 0 {
					funcsJSON[curFunc] = append(funcsJSON[curFunc], inst)
				}
			}
		}
		if len(funcsJSON) > 0 {
			if dat, err := json.Marshal(funcsJSON); err == nil {
				fmt.Println(string(dat))
			}
		} else {
			if dat, err := json.Marshal(instructions); err == nil {
				fmt.Println(string(dat))
			}
		}
	}
}

func ParseGotPtrs(m *macho.File) (map[uint64]uint64, error) {

	gots := make(map[uint64]uint64)

	if authPtr := m.Section("__AUTH_CONST", "__auth_ptr"); authPtr != nil {

		dat, err := authPtr.Data()
		if err != nil {
			off, err := m.GetOffset(authPtr.Addr)
			if err != nil {
				return nil, fmt.Errorf("failed to get offset for __AUTH_CONST.__auth_ptr: %v", err)
			}
			dat = make([]byte, authPtr.Size)
			if n, err := m.ReadAt(dat, int64(off)); err != nil || n != len(dat) {
				return nil, fmt.Errorf("failed to read __AUTH_CONST.__auth_ptr data: %v", err)
			}
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
			if sec.Seg == "__AUTH_CONST" && sec.Name == "__auth_ptr" {
				continue
			}

			dat, err := sec.Data()
			if err != nil {
				off, err := m.GetOffset(sec.Addr)
				if err != nil {
					return nil, fmt.Errorf("failed to get offset for %s.%s section: %v", sec.Seg, sec.Name, err)
				}
				dat = make([]byte, sec.Size)
				if n, err := m.ReadAt(dat, int64(off)); err != nil || n != len(dat) {
					return nil, fmt.Errorf("failed to get %s.%s section data: %v", sec.Seg, sec.Name, err)
				}
			}

			ptrs := make([]uint64, sec.Size/8)
			if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
				return nil, fmt.Errorf("failed to read %s.%s NonLazySymbol pointers; %v", sec.Seg, sec.Name, err)
			}

			for idx, ptr := range ptrs {
				// gots[sec.Addr+uint64(idx*8)] = m.SlidePointer(ptr)
				gots[sec.Addr+uint64(idx*8)] = ptr
			}
		}
	}

	return gots, nil
}

func ParseStubsForMachO(m *macho.File) (map[uint64]uint64, error) {

	stubs := make(map[uint64]uint64)

	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {

			dat, err := sec.Data()
			if err != nil {
				off, err := m.GetOffset(sec.Addr)
				if err != nil {
					return nil, fmt.Errorf("failed to get offset for %s.%s section: %v", sec.Seg, sec.Name, err)
				}
				dat := make([]byte, sec.Size)
				if n, err := m.ReadAt(dat, int64(off)); err != nil || n != len(dat) {
					return nil, fmt.Errorf("failed to get %s.%s section data: %v", sec.Seg, sec.Name, err)
				}
			}

			sb, err := ParseStubsASM(dat, sec.Addr, func(u uint64) (uint64, error) {
				return m.GetPointerAtAddress(m.SlidePointer(u))
			})
			if err != nil {
				return nil, err
			}

			for k, v := range sb {
				stubs[k] = v
			}
		}
	}

	return stubs, nil
}

func ParseStubsASM(data []byte, begin uint64, readPtr func(uint64) (uint64, error)) (map[uint64]uint64, error) {
	var adrpImm uint64
	var adrpAddr uint64
	var instrValue uint32
	var results [1024]byte

	queue := make([]*disassemble.Instruction, 2)

	stubs := make(map[uint64]uint64)

	r := bytes.NewReader(data)

	startAddr := begin

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			queue[1] = queue[0] // push instruction onto const length FIFO queue
			queue[0] = instruction
			continue
		}

		if (queue[1] != nil && queue[1].Operation == disassemble.ARM64_ADRP) &&
			(queue[0] != nil && queue[0].Operation == disassemble.ARM64_ADD) &&
			instruction.Operation == disassemble.ARM64_LDR {
			// adrp     x17, 0x221baf000
			adrpRegister := queue[1].Operands[0].Registers[0] // x17
			adrpImm = queue[1].Operands[1].Immediate          // #0x221baf000
			// add      x17, x17, #0xbe0
			if adrpRegister == queue[0].Operands[0].Registers[0] { // check that adrp reg is the same as add reg
				adrpImm += queue[0].Operands[2].Immediate
				adrpAddr = queue[1].Address // addr of begining of stub (adrp)
			}
			// ldr      x16, [x17]
			if len(instruction.Operands[1].Registers) > 0 &&
				(queue[0].Operands[0].Registers[0] == instruction.Operands[1].Registers[0]) { // check add reg and ldr reg are the same
				if instruction.Operands[1].Immediate != 0 { // check for immediate
					adrpImm += instruction.Operands[1].Immediate
				}
				addr, err := readPtr(adrpImm)
				if err != nil {
					log.Debugf("%#08x:  %s\t%s", instruction.Address, disassemble.GetOpCodeByteString(instruction.Raw), instruction) // TODO: DRY this up
					for _, i := range queue {
						if i != nil {
							log.Debugf("%#08x:  %s\t%s", i.Address, disassemble.GetOpCodeByteString(i.Raw), i)
						}
					}
					return nil, fmt.Errorf("failed to read stub target pointer at %#x: %v", adrpImm, err)
				}
				// braa     x16, x17
				stubs[adrpAddr] = addr
			}
		} else if (queue[1] != nil && queue[1].Operation == disassemble.ARM64_ADRP) &&
			(queue[0] != nil && queue[0].Operation == disassemble.ARM64_ADD) &&
			strings.Contains(instruction.Encoding.String(), "branch") {
			// adrp     x16, 0x19089b000
			adrpRegister := queue[1].Operands[0].Registers[0] // x16
			adrpImm = queue[1].Operands[1].Immediate          // #0x221baf000
			// add      x16, x16, #0x94c ; ___stack_chk_fail
			if adrpRegister == queue[0].Operands[0].Registers[0] { // check that adrp reg is the same as add reg
				adrpImm += queue[0].Operands[2].Immediate
				adrpAddr = queue[1].Address // addr of begining of stub (adrp)
			}
			// br       x16
			stubs[adrpAddr] = adrpImm
			// brk      #0x1
		} else if (queue[0] != nil && queue[0].Operation == disassemble.ARM64_ADRP) &&
			instruction.Operation == disassemble.ARM64_LDR {
			if instruction.Operands != nil && queue[0].Operands != nil {
				// adrp	x16, #0x1e3be9000
				adrpRegister := queue[0].Operands[0].Registers[0] // x16
				adrpImm = queue[0].Operands[1].Immediate          // #0x1e3be9000
				// ldr	x16, [x16, #0x560]
				if adrpRegister == instruction.Operands[0].Registers[0] {
					adrpImm += instruction.Operands[1].Immediate
					adrpAddr = queue[0].Address
					addr, err := readPtr(adrpImm)
					if err != nil {
						log.Debugf("%#08x:  %s\t%s", instruction.Address, disassemble.GetOpCodeByteString(instruction.Raw), instruction)
						for _, i := range queue {
							if i != nil {
								log.Debugf("%#08x:  %s\t%s", i.Address, disassemble.GetOpCodeByteString(i.Raw), i)
							}
						}
						return nil, fmt.Errorf("failed to read stub target pointer at %#x: %v", adrpImm, err)
					}
					stubs[adrpAddr] = addr
				}
			}
		}

		queue[1] = queue[0] // push instruction onto const length FIFO queue
		queue[0] = instruction
		startAddr += uint64(binary.Size(uint32(0)))
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
			off, err := m.GetOffset(sec.Addr)
			if err != nil {
				return nil, fmt.Errorf("failed to get offset for %s.%s section: %v", sec.Seg, sec.Name, err)
			}
			dat := make([]byte, sec.Size)
			if n, err := m.ReadAt(dat, int64(off)); err != nil || n != len(dat) {
				return nil, fmt.Errorf("failed to get %s.%s section data: %v", sec.Seg, sec.Name, err)
			}
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
