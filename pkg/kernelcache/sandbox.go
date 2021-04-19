package kernelcache

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
)

type SandboxProfileCollection struct {
	Version        uint16
	OpNodeSize     uint16
	OpCount        uint8
	GlobalVarCount uint8
	ProfileCount   uint16
	RegexItemCount uint16
	MsgItemCount   uint16
}

type SandboxOperation struct {
	Name  string
	Index uint16
	Value uint64
}

type SandboxProfile struct {
	Name       string
	Version    uint16
	Operations []SandboxOperation
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

func ParseSandboxCollection(data []byte, opsList []string) error {
	var collection SandboxProfileCollection
	var profiles []SandboxProfile

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &collection); err != nil {
		return fmt.Errorf("failed to read sandbox profile collection structure: %v", err)
	}

	regexOffsets := make([]uint16, collection.RegexItemCount)
	if err := binary.Read(r, binary.LittleEndian, &regexOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox profile regex offets: %v", err)
	}

	globalOffsets := make([]uint16, collection.GlobalVarCount)
	if err := binary.Read(r, binary.LittleEndian, &globalOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox profile global offets: %v", err)
	}

	msgOffsets := make([]uint16, collection.MsgItemCount)
	if err := binary.Read(r, binary.LittleEndian, &msgOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox profile message offets: %v", err)
	}

	profileSize := uint32(collection.OpCount+uint8(binary.Size(uint16(0)))) * 2
	log.Debugf("[+] profile size: %d", profileSize)

	globalVarStart := 2*uint32(collection.RegexItemCount) + 12
	globalVarEnd := globalVarStart + 2*uint32(collection.GlobalVarCount)
	log.Debugf("[+] global var start: %#x, end: %#x", globalVarStart, globalVarEnd)

	opNodeStartTmp := globalVarEnd + 2*uint32(collection.MsgItemCount) + profileSize*uint32(collection.ProfileCount)
	log.Debugf("[+] temp op node start: %#x", opNodeStartTmp)

	// delta op node start
	opNodeStartDelta := 8 - (opNodeStartTmp & 6)
	if (opNodeStartTmp & 6) == 0 {
		opNodeStartDelta = 0
	}
	log.Debugf("[+] delta op node start: %#x", opNodeStartDelta)

	// op node start
	opNodeStart := opNodeStartDelta + opNodeStartTmp
	log.Debugf("[+] op node start: %#x", opNodeStart)

	// start address of regex, global, messsages
	baseAddr := opNodeStart + uint32(collection.OpNodeSize)*8
	log.Debugf("[+] start address of regex, global, messsages: %#x", baseAddr)

	var profileDatas [][]byte
	for i := uint16(0); i < collection.ProfileCount; i++ {
		profile := make([]byte, profileSize)
		if err := binary.Read(r, binary.LittleEndian, &profile); err != nil {
			return fmt.Errorf("failed to read sandbox profiles: %v", err)
		}
		profileDatas = append(profileDatas, profile)
	}

	for idx, prof := range profileDatas {
		sp := SandboxProfile{}

		pr := bytes.NewReader(prof)

		var nameOffset uint16
		if err := binary.Read(pr, binary.LittleEndian, &nameOffset); err != nil {
			return fmt.Errorf("failed to read profile name offset for index %d: %v", idx, err)
		}

		if err := binary.Read(pr, binary.LittleEndian, &sp.Version); err != nil {
			return fmt.Errorf("failed to read profile version for index %d: %v", idx, err)
		}

		for i := 0; i < int(collection.OpCount); i++ {
			so := SandboxOperation{Name: opsList[i]}
			if err := binary.Read(pr, binary.LittleEndian, &so.Index); err != nil {
				return fmt.Errorf("failed to read sandbox operation index for %s: %v", opsList[i], err)
			}
			// TODO: lookup operation value
			sp.Operations = append(sp.Operations, so)
		}

		r.Seek(int64(baseAddr+8*uint32(nameOffset)), io.SeekStart)
		var nameLength uint16
		if err := binary.Read(r, binary.LittleEndian, &nameLength); err != nil {
			return fmt.Errorf("failed to read profile name length for index %d: %v", idx, err)
		}

		str := make([]byte, nameLength)
		_, err := r.Read(str)
		if err != nil {
			return err
		}

		sp.Name = strings.Trim(string(str[:]), "\x00")

		profiles = append(profiles, sp)
	}

	profileDatas = nil

	// fmt.Printf("\nOperation Nodes\n")
	// fmt.Println("===============")
	r.Seek(int64(opNodeStart), io.SeekStart)
	opNodeCount := (baseAddr - opNodeStart) / 8
	opNodeOffsets := make([]uint16, opNodeCount)
	if err := binary.Read(r, binary.LittleEndian, &opNodeOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox op node offets: %v", err)
	}
	opNodes := make([]uint64, opNodeCount)
	for _, opoff := range opNodeOffsets {
		var opNodeValue uint64
		r.Seek(int64(opoff), io.SeekStart)
		if err := binary.Read(r, binary.LittleEndian, &opNodeValue); err != nil {
			return fmt.Errorf("failed to read sandbox op node offets: %v", err)
		}
		opNodes = append(opNodes, opNodeValue)
	}

	for i, prof := range profiles {
		for j, o := range prof.Operations {
			profiles[i].Operations[j].Value = opNodes[o.Index]
		}
	}

	// fmt.Println("Messages")
	// fmt.Println("========")
	// for _, moff := range msgOffsets {
	// 	r.Seek(int64(baseAddr+uint32(moff)), io.SeekStart)

	// 	length, err := r.ReadByte()
	// 	if err != nil {
	// 		return err
	// 	}

	// 	str := make([]byte, length)
	// 	_, err = r.Read(str)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	fmt.Println(string(str[:]))
	// }

	fmt.Printf("\nGlobal Vars\n")
	fmt.Println("===========")
	for _, goff := range globalOffsets {
		r.Seek(int64(baseAddr+8*uint32(goff)), io.SeekStart)

		var globalLength uint16
		if err := binary.Read(r, binary.LittleEndian, &globalLength); err != nil {
			return fmt.Errorf("failed to read global variable length: %v", err)
		}

		str := make([]byte, globalLength)
		_, err := r.Read(str)
		if err != nil {
			return err
		}

		fmt.Println(strings.Trim(string(str[:]), "\x00"))
	}

	fmt.Printf("\nRegex Table\n")
	fmt.Println("===========")
	for idx, roff := range regexOffsets {

		r.Seek(int64(baseAddr+8*uint32(roff)), io.SeekStart)

		var itemLength uint16
		if err := binary.Read(r, binary.LittleEndian, &itemLength); err != nil {
			return fmt.Errorf("failed to read regex table offset: %v", err)
		}

		data := make([]byte, itemLength)
		_, err := r.Read(data)
		if err != nil {
			return err
		}

		fmt.Printf("[+] idx: %03d, offset: %#x, location: %#x, length: %#x\n", idx, baseAddr+8*uint32(roff), 8*roff, itemLength)
		fmt.Println(hex.Dump(data))
	}

	fmt.Printf("\nProfiles\n")
	fmt.Println("========")
	for _, prof := range profiles {
		fmt.Printf("\n[+] %s, verion: %d\n", prof.Name, prof.Version)
		for _, o := range prof.Operations {
			fmt.Printf("  name: %s, index: %#x, value: %#016x\n", o.Name, o.Index, o.Value)
		}
	}

	return nil
}

func getTag(ptr uint64) uint64 {
	return ptr >> 48
}

func unTag(ptr uint64) uint64 {
	return (ptr & ((1 << 48) - 1)) | (0xffff << 48)
}
