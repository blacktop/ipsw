package kernelcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
)

type SandboxProfileCollection struct {
	Version        uint16
	OpNodeSize     uint16
	OpCount        uint16
	ProfileCount   uint16
	RegexItemCount uint16
	GlobalVarCount uint16
	MsgItemCount   uint16
}

func GetSandboxOpts(m *macho.File) ([]string, error) {
	var bcOpts []string

	if dconst := m.Section("__DATA_CONST", "__const"); dconst != nil {
		data, err := dconst.Data()
		if err != nil {
			return nil, err
		}
		ptrs := make([]uint64, dconst.Size/8)
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
			return nil, err
		}
		found := false
		for _, ptr := range ptrs {
			if ptr == 0 {
				continue
			}

			str, err := m.GetCString(ptr | tagPtrMask)
			if err != nil {
				if found {
					break
				}
				continue
			}

			if str == "default" {
				found = true
			}

			if found {
				bcOpts = append(bcOpts, str)
				if getTag(ptr) != 0x17 { // always directly followed by another pointer
					break
				}
			}
		}
	}

	// GetSandboxProfiles(m)

	return bcOpts, nil
}

// TODO: finish this (make it so when I look at it I don't want to 🤮)
func getSandboxData(m *macho.File, r *bytes.Reader, panic string) ([]byte, error) {
	var profiles []byte
	var sandboxKextStartVaddr uint64
	var sandboxKextStartOffset uint64
	var sandboxKextEndVaddr uint64

	panicStrVMAddr, err := findCStringVMaddr(m, panic)
	if err != nil {
		return nil, err
	}
	panicStrOffset, err := m.GetOffset(panicStrVMAddr)
	if err != nil {
		return nil, err
	}
	utils.Indent(log.WithFields(log.Fields{
		"vmaddr": fmt.Sprintf("%#x", panicStrVMAddr),
		"offset": fmt.Sprintf("%#x", panicStrOffset),
	}).Debug, 2)(fmt.Sprintf("Found: %v", panic))

	startAdders, err := getKextStartVMAddrs(m)
	if err != nil {
		return nil, err
	}

	infos, err := getKextInfos(m)
	if err != nil {
		return nil, err
	}

	for idx, info := range infos {
		if strings.Contains(string(info.Name[:]), "sandbox") {
			sandboxKextStartVaddr = startAdders[idx] | tagPtrMask
			sandboxKextEndVaddr = startAdders[idx+1] | tagPtrMask
			sandboxKextStartOffset, err = m.GetOffset(sandboxKextStartVaddr)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	// sandbox, err := macho.NewFile(io.NewSectionReader(r, int64(sandboxKextStartOffset), int64(sandboxKextEndVaddr-sandboxKextStartVaddr)), macho.FileConfig{
	// 	Offset:    int64(sandboxKextStartOffset),
	// 	SrcReader: io.NewSectionReader(r, 0, 1<<63-1),
	// })
	// if err != nil {
	// 	return nil, err
	// }

	// fmt.Println(sandbox.FileTOC.String())

	sbInstrData := make([]byte, sandboxKextEndVaddr-sandboxKextStartVaddr)
	_, err = m.ReadAt(sbInstrData, int64(sandboxKextStartOffset))
	if err != nil {
		return nil, err
	}

	var prevInstruction arm64.Instruction

	references := make(map[uint64]uint64)

	// extract all immediates
	for i := range arm64.Disassemble(bytes.NewReader(sbInstrData), arm64.Options{StartAddress: int64(sandboxKextStartVaddr)}) {

		if i.Error != nil {
			continue
		}

		operation := i.Instruction.Operation().String()

		if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
			if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
				adrpRegister := prevInstruction.Operands()[0].Reg[0]
				adrpImm := prevInstruction.Operands()[1].Immediate
				if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
					adrpImm += operands[1].Immediate
				} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
					adrpImm += operands[2].Immediate
				}
				references[i.Instruction.Address()] = adrpImm
			}
		}
		if operation == "cbnz" {
			if operands := i.Instruction.Operands(); operands != nil {
				for _, operand := range operands {
					if operand.OpClass == arm64.LABEL {
						references[i.Instruction.Address()] = operand.Immediate
					}
				}
			}
		}

		// fmt.Printf("%#08x:  %s\t%-10v%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), i.Instruction.OpStr())
		prevInstruction = *i.Instruction
	}

	var panicXrefVMAddr uint64
	for k, v := range references {
		if v == panicStrVMAddr {
			panicXrefVMAddr = k - 4
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Panic string Xref %#x => %#x", panicXrefVMAddr, v))
			break
		}
	}

	var failXrefVMAddr uint64
	for k, v := range references {
		if v == panicXrefVMAddr {
			failXrefVMAddr = k
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Failure path Xref %#x => %#x", failXrefVMAddr, v))
			break
		}
	}

	var profileVMAddr uint64
	var profileSize uint64

	for i := range arm64.Disassemble(bytes.NewReader(sbInstrData), arm64.Options{StartAddress: int64(sandboxKextStartVaddr)}) {

		if i.Error != nil {
			continue
		}

		operation := i.Instruction.Operation().String()

		// TODO: identify basic blocks so I could only disass the block that contains the Xref
		if failXrefVMAddr-0x20 < i.Instruction.Address() && i.Instruction.Address() < failXrefVMAddr {
			if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
				if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
					adrpRegister := prevInstruction.Operands()[0].Reg[0]
					adrpImm := prevInstruction.Operands()[1].Immediate
					if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[1].Immediate
					} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[2].Immediate
					}
					profileVMAddr = adrpImm
				}
			} else if operation == "mov" {
				if operands := i.Instruction.Operands(); operands != nil {
					for _, operand := range operands {
						if operand.OpClass == arm64.IMM64 {
							profileSize = operand.Immediate
						}
					}
				}
			} else if operation == "movk" && prevInstruction.Operation().String() == "mov" {
				if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
					movRegister := prevInstruction.Operands()[0].Reg[0]
					movImm := prevInstruction.Operands()[1].Immediate
					if movRegister == operands[0].Reg[0] {
						if operands[1].OpClass == arm64.IMM32 && operands[1].ShiftType == arm64.SHIFT_LSL {
							profileSize = movImm + (operands[1].Immediate << uint64(operands[1].ShiftValue))
						}
					}
				}
			}
		}

		prevInstruction = *i.Instruction
	}

	utils.Indent(log.WithFields(log.Fields{
		"vmaddr": fmt.Sprintf("%#x", profileVMAddr),
		"size":   fmt.Sprintf("%#x", profileSize),
	}).Info, 2)("Located data")

	profileOffset, err := m.GetOffset(profileVMAddr)
	if err != nil {
		return nil, err
	}

	profiles = make([]byte, profileSize)
	_, err = m.ReadAt(profiles, int64(profileOffset))
	if err != nil {
		return nil, err
	}

	return profiles, nil
}

func GetSandboxProfiles(m *macho.File, r *bytes.Reader) ([]byte, error) {
	log.Info("Searching for sandbox profile data")
	return getSandboxData(m, r, "\"failed to initialize platform sandbox\"")
}

func GetSandboxCollections(m *macho.File, r *bytes.Reader) ([]byte, error) {
	log.Info("Searching for sandbox collection data")
	return getSandboxData(m, r, "\"failed to initialize collection\"")
}

func ParseSandboxCollection(data []byte) error {
	var collection SandboxProfileCollection

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &collection); err != nil {
		return fmt.Errorf("failed to read sandbox profile collection structure: %v", err)
	}

	fmt.Printf("%#v\n", collection)

	profileSize := collection.OpCount*2 + uint16(binary.Size(uint16(0)))*2
	fmt.Printf("[+] profile size: %d\n", profileSize)

	globalVarStart := 2*collection.RegexItemCount + 12
	globalVarEnd := globalVarStart + 2*collection.GlobalVarCount
	fmt.Printf("[+] global var start: %#x, end: %#x\n", globalVarStart, globalVarEnd)

	opNodeStartTmp := globalVarEnd + 2*collection.MsgItemCount + profileSize*collection.ProfileCount
	fmt.Printf("[+] temp op node start: 0x%x\n", opNodeStartTmp)

	// delta op node start
	opNodeStartDelta := 8 - (opNodeStartTmp & 6)
	// if (opNodeStartTmp & 6) == 0 {
	// 	opNodeStartDelta = 0
	// }
	fmt.Printf("[+] delta op node start: 0x%x\n", opNodeStartDelta)

	// op node start
	opNodeStart := opNodeStartDelta + opNodeStartTmp
	fmt.Printf("[+] op node start: 0x%x\n", opNodeStart)

	// start address of regex, global, messsages
	baseAddr := opNodeStart + collection.OpNodeSize
	fmt.Printf("[+] start address of regex, global, messsages: 0x%x\n", baseAddr)

	// fmt.Printf("[+] op node start: %#x\n", opNodeStart)

	return nil
}

func getTag(ptr uint64) uint64 {
	return ptr >> 48
}

func unTag(ptr uint64) uint64 {
	return (ptr & ((1 << 48) - 1)) | (0xffff << 48)
}
