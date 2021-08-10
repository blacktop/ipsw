// +build cgo

package kernelcache

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	arm64 "github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
)

type Sandbox struct {
	Globals  map[uint16]string
	Regexes  map[uint16][]byte
	OpNodes  map[uint16]uint64
	Profiles []SandboxProfile
}

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

func (sp SandboxProfile) String() string {
	out := fmt.Sprintf("[+] %s, version: %d\n", sp.Name, sp.Version)
	for _, o := range sp.Operations {
		out += fmt.Sprintf("  name: %s, index: %#x, value: %#016x\n", o.Name, o.Index, o.Value)
	}
	return out
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
func getSandboxData(m *macho.File, r *bytes.Reader, panic string, dataRegister arm64.Register) ([]byte, error) {
	var profiles []byte
	// var sandboxKextStartVaddr uint64
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
	}).Debug, 2)(fmt.Sprintf("Found: %#v", panic))

	startAdders, err := getKextStartVMAddrs(m)
	if err != nil {
		return nil, err
	}

	infos, err := getKextInfos(m)
	if err != nil {
		return nil, err
	}

	var sandboxInfo KmodInfoT
	for idx, info := range infos {
		if strings.Contains(string(info.Name[:]), "sandbox") {
			log.Debug(info.String())
			sandboxInfo = info
			// sandboxKextStartVaddr = startAdders[idx] | tagPtrMask
			sandboxKextEndVaddr = startAdders[idx+1] | tagPtrMask
			sandboxKextStartOffset, err = m.GetOffset(sandboxInfo.StartAddr | tagPtrMask)
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

	sbInstrData := make([]byte, sandboxKextEndVaddr-sandboxInfo.StartAddr)
	_, err = m.ReadAt(sbInstrData, int64(sandboxKextStartOffset))
	if err != nil {
		return nil, err
	}

	instructions, err := arm64.GetInstructions(sandboxInfo.StartAddr, sbInstrData)
	if err != nil {
		return nil, err
	}

	var prev *arm64.Instruction

	references := make(map[uint64]uint64)

	// extract all immediates
	for idx, i := range instructions {

		// log.Debugf("%#08x:  %s\t%s", i.Address, i.OpCodes(), i)

		if idx == 0 {
			continue
		}

		prev = instructions[idx-1]

		op := i.Operation.String()

		if prev.Operation.String() == "adrp" && (op == "ldr" || op == "add") {
			adrpRegister := prev.Operands[0].Registers[0]
			adrpImm := prev.Operands[1].Immediate
			if op == "ldr" && adrpRegister == i.Operands[1].Registers[0] {
				adrpImm += i.Operands[1].Immediate
			} else if op == "add" && adrpRegister == i.Operands[1].Registers[0] {
				adrpImm += i.Operands[2].Immediate
			}
			references[i.Address] = adrpImm

		} else if op == "cbnz" {
			for _, operand := range i.Operands {
				if operand.Class == arm64.LABEL {
					references[i.Address] = operand.Immediate
				}
			}
		}
	}

	var panicXrefVMAddr uint64
	for k, v := range references {
		if v == panicStrVMAddr {
			panicXrefVMAddr = k - 4
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Panic string Xref %#x => %#x", panicXrefVMAddr, v))
			break
		}
	}

	if panicXrefVMAddr == 0 {
		return nil, fmt.Errorf("failed to find Xrefs to the panic cstring")
	}

	panicBlock, err := instructions.GetAddressBlock(panicXrefVMAddr)
	if err != nil {
		return nil, err
	}

	var failXrefVMAddr uint64
	for k, v := range references {
		if v == panicBlock[0].Address {
			failXrefVMAddr = k
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Failure path Xref %#x => %#x", failXrefVMAddr, v))
			break
		}
	}

	if failXrefVMAddr == 0 {
		return nil, fmt.Errorf("failed to find failure path Xrefs to the panic")
	}

	sandboxDataBlock, err := instructions.GetAddressBlock(failXrefVMAddr)
	if err != nil {
		return nil, err
	}

	var profileVMAddr uint64
	var profileSize uint64

	for idx, i := range sandboxDataBlock {

		log.Debugf("%#08x:  %s\t%s", i.Address, i.OpCodes(), i)

		if idx == 0 {
			continue
		}

		prev = sandboxDataBlock[idx-1]

		op := i.Operation.String()

		if prev.Operation.String() == "adrp" && (op == "ldr" || op == "add") {
			adrpRegister := prev.Operands[0].Registers[0]
			adrpImm := prev.Operands[1].Immediate
			if op == "ldr" && adrpRegister == i.Operands[1].Registers[0] {
				adrpImm += i.Operands[1].Immediate
			} else if op == "add" && adrpRegister == i.Operands[1].Registers[0] {
				adrpImm += i.Operands[2].Immediate
			}
			if i.Operands[0].Registers[0] == dataRegister { // sandbox data array ARG
				profileVMAddr = adrpImm
			}

		} else if op == "mov" {
			for _, operand := range i.Operands {
				if operand.Class == arm64.IMM64 {
					profileSize = operand.Immediate
				}
			}

		} else if prev.Operation.String() == "mov" && op == "movk" {
			movRegister := prev.Operands[0].Registers[0]
			movImm := prev.Operands[1].Immediate
			if movRegister == i.Operands[0].Registers[0] {
				if i.Operands[1].Class == arm64.IMM32 && i.Operands[1].ShiftType == arm64.SHIFT_TYPE_LSL {
					profileSize = movImm + (i.Operands[1].Immediate << uint64(i.Operands[1].ShiftValue))
				}
			}
		}
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
	log.Info("Searching for sandbox platform_profile_data")
	// return getSandboxData(m, r, "\"failed to initialize platform sandbox\"")
	return getSandboxData(m, r, "\"failed to initialize platform sandbox: %d\" @%s:%d", arm64.REG_X1) // _profile_init(_platform_profile, _platform_profile_data, data_size);
}

func GetSandboxCollections(m *macho.File, r *bytes.Reader) ([]byte, error) {
	log.Info("Searching for sandbox collection_data")
	// return getSandboxData(m, r, "\"failed to initialize collection\"")
	return getSandboxData(m, r, "\"failed to initialize builtin collection: %d\" @%s:%d", arm64.REG_X2)
}

func ParseSandboxCollection(data []byte, opsList []string) (*Sandbox, error) {
	var collection SandboxProfileCollection

	// init Sandbox
	sb := &Sandbox{}
	sb.Globals = make(map[uint16]string)
	sb.OpNodes = make(map[uint16]uint64)
	sb.Regexes = make(map[uint16][]byte)

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &collection); err != nil {
		return nil, fmt.Errorf("failed to read sandbox profile collection structure: %v", err)
	}

	regexOffsets := make([]uint16, collection.RegexItemCount)
	if err := binary.Read(r, binary.LittleEndian, &regexOffsets); err != nil {
		return nil, fmt.Errorf("failed to read sandbox profile regex offets: %v", err)
	}

	globalOffsets := make([]uint16, collection.GlobalVarCount)
	if err := binary.Read(r, binary.LittleEndian, &globalOffsets); err != nil {
		return nil, fmt.Errorf("failed to read sandbox profile global offets: %v", err)
	}

	msgOffsets := make([]uint16, collection.MsgItemCount)
	if err := binary.Read(r, binary.LittleEndian, &msgOffsets); err != nil {
		return nil, fmt.Errorf("failed to read sandbox profile message offets: %v", err)
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
			return nil, fmt.Errorf("failed to read sandbox profiles: %v", err)
		}
		profileDatas = append(profileDatas, profile)
	}

	for idx, prof := range profileDatas {
		sp := SandboxProfile{}

		pr := bytes.NewReader(prof)

		var nameOffset uint16
		if err := binary.Read(pr, binary.LittleEndian, &nameOffset); err != nil {
			return nil, fmt.Errorf("failed to read profile name offset for index %d: %v", idx, err)
		}

		if err := binary.Read(pr, binary.LittleEndian, &sp.Version); err != nil {
			return nil, fmt.Errorf("failed to read profile version for index %d: %v", idx, err)
		}

		for i := 0; i < int(collection.OpCount); i++ {
			so := SandboxOperation{Name: opsList[i]}
			if err := binary.Read(pr, binary.LittleEndian, &so.Index); err != nil {
				return nil, fmt.Errorf("failed to read sandbox operation index for %s: %v", opsList[i], err)
			}
			// TODO: lookup operation value
			sp.Operations = append(sp.Operations, so)
		}

		r.Seek(int64(baseAddr+8*uint32(nameOffset)), io.SeekStart)
		var nameLength uint16
		if err := binary.Read(r, binary.LittleEndian, &nameLength); err != nil {
			return nil, fmt.Errorf("failed to read profile name length for index %d: %v", idx, err)
		}

		str := make([]byte, nameLength)
		_, err := r.Read(str)
		if err != nil {
			return nil, err
		}

		sp.Name = strings.Trim(string(str[:]), "\x00")

		sb.Profiles = append(sb.Profiles, sp)
	}

	profileDatas = nil

	// fmt.Printf("\nOperation Nodes\n")
	// fmt.Println("===============")
	r.Seek(int64(opNodeStart), io.SeekStart)
	opNodeCount := (baseAddr - opNodeStart) / 8
	opNodeOffsets := make([]uint16, opNodeCount)
	if err := binary.Read(r, binary.LittleEndian, &opNodeOffsets); err != nil {
		return nil, fmt.Errorf("failed to read sandbox op node offets: %v", err)
	}
	// TODO: refactor to only use sb.OpNodes
	opNodes := make([]uint64, opNodeCount)
	for _, opoff := range opNodeOffsets {
		var opNodeValue uint64
		r.Seek(int64(opoff), io.SeekStart)
		if err := binary.Read(r, binary.LittleEndian, &opNodeValue); err != nil {
			return nil, fmt.Errorf("failed to read sandbox op node offets: %v", err)
		}
		opNodes = append(opNodes, opNodeValue)
		sb.OpNodes[opoff] = opNodeValue
	}

	for i, prof := range sb.Profiles {
		for j, o := range prof.Operations {
			sb.Profiles[i].Operations[j].Value = opNodes[o.Index]
		}
	}

	// fmt.Println("Messages")
	// fmt.Println("========")
	// for _, moff := range msgOffsets {
	// 	r.Seek(int64(baseAddr+uint32(moff)), io.SeekStart)

	// 	length, err := r.ReadByte()
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	str := make([]byte, length)
	// 	_, err = r.Read(str)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	fmt.Println(string(str[:]))
	// }

	for _, goff := range globalOffsets {
		r.Seek(int64(baseAddr+8*uint32(goff)), io.SeekStart)

		var globalLength uint16
		if err := binary.Read(r, binary.LittleEndian, &globalLength); err != nil {
			return nil, fmt.Errorf("failed to read global variable length: %v", err)
		}

		str := make([]byte, globalLength)
		_, err := r.Read(str)
		if err != nil {
			return nil, err
		}

		sb.Globals[goff] = strings.Trim(string(str[:]), "\x00")
	}

	for idx, roff := range regexOffsets {

		r.Seek(int64(baseAddr+8*uint32(roff)), io.SeekStart)

		var itemLength uint16
		if err := binary.Read(r, binary.LittleEndian, &itemLength); err != nil {
			return nil, fmt.Errorf("failed to read regex table offset: %v", err)
		}

		data := make([]byte, itemLength)
		if _, err := r.Read(data); err != nil {
			return nil, err
		}

		log.Debugf("[+] idx: %03d, offset: %#x, location: %#x, length: %#x\n\n%s", idx, baseAddr+8*uint32(roff), 8*roff, itemLength, hex.Dump(data))

		sb.Regexes[roff] = data
	}

	return sb, nil
}

func getTag(ptr uint64) uint64 {
	return ptr >> 48
}

func unTag(ptr uint64) uint64 {
	return (ptr & ((1 << 48) - 1)) | (0xffff << 48)
}
