package kernelcache

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/kernelcache/sandbox"
	"github.com/hashicorp/go-version"
)

const (
	typeProfile           = 0x0000
	typeCollection        = 0x8000
	profileInitPanic      = "failed to initialize platform sandbox"
	collectionInitPanic14 = "failed to initialize collection"
	collectionInitPanic15 = "failed to initialize builtin collection"
)

type SandboxProfileHeader14 struct {
	Type           uint16
	OpNodeCount    uint16
	OpCount        uint8
	GlobalVarCount uint8
	ProfileCount   uint16
	RegexItemCount uint16
	MsgItemCount   uint16
}

type SandboxProfileHeader15 struct {
	Type           uint16
	OpNodeCount    uint16
	OpCount        uint8
	GlobalVarCount uint8
	Unknown1       uint8
	Unknown2       uint8
	ProfileCount   uint16
	RegexItemCount uint16
	MsgItemCount   uint16
}

type operationNode uint64

type SandboxOperation struct {
	Name  string
	Index uint16
	Value uint64
	operationNode
}

type profile14 struct {
	NameOffset uint16
	Version    uint16
}

type profile15 struct {
	NameOffset uint16
	Version    uint16
	Unknown    uint16
}

type SandboxProfile struct {
	Name       string
	nameOffset uint16
	Version    uint16
	Operations []SandboxOperation
	ops        []uint16
}

func (sp SandboxProfile) String() string {
	out := fmt.Sprintf("[+] %s, version: %d\n", sp.Name, sp.Version)
	for _, o := range sp.Operations {
		out += fmt.Sprintf("  name: %s, index: %#x, value: %#016x\n", o.Name, o.Index, o.Value)
	}
	return out
}

type Sandbox struct {
	Hdr header

	Profiles  []SandboxProfile
	OpNodes   []operationNode
	Regexes   []*sandbox.Regex
	Globals   []string
	Modifiers []string

	operations          []string
	collectionData      []byte
	platformProfileData []byte

	kern          *macho.File
	darwin        *version.Version
	kextStartAddr uint64
	kextEndAddr   uint64
	xrefs         map[uint64]uint64
	config        Config
}

type header struct {
	Type           uint16
	OpNodeCount    uint16
	OpCount        uint8
	GlobalVarCount uint8
	ProfileCount   uint16
	RegexItemCount uint16
	MsgItemCount   uint16
}

type Config struct {
	sbHeader            any
	profileType         any
	profileInitPanic    string
	profileInitArgs     []string
	collectionInitPanic string
	collectionInitArgs  []string
}

func NewSandbox(m *macho.File) (*Sandbox, error) {
	sb := Sandbox{
		Profiles: make([]SandboxProfile, 0),
		kern:     m,
	}

	if _, err := sb.GetOperations(); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox operations: %w", err)
	}

	if kv, err := GetVersion(sb.kern); err != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", err)
	} else {
		sb.darwin, err = version.NewVersion(kv.Kernel.Darwin)
		if err != nil {
			return nil, fmt.Errorf("failed to parse darwin version: %w", err)
		}
	}

	// configure sandbox parser
	sb.config.profileInitPanic = profileInitPanic
	sb.config.profileInitArgs = []string{"x1", "w2"}

	iOS14x, err := version.NewConstraint(">= 20.0.0, < 21.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to parse darwin version constraint: %w", err)
	}
	iOS15x, err := version.NewConstraint(">= 21.0.0, < 22.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to parse darwin version constraint: %w", err)
	}

	if iOS14x.Check(sb.darwin) {
		sb.config.sbHeader = &SandboxProfileHeader14{}
		sb.config.profileType = &profile14{}
		sb.config.collectionInitPanic = collectionInitPanic14
		sb.config.collectionInitArgs = []string{"x1", "w2"}
	} else if iOS15x.Check(sb.darwin) {
		sb.config.sbHeader = &SandboxProfileHeader15{}
		sb.config.profileType = &profile15{}
		sb.config.collectionInitPanic = collectionInitPanic15
		sb.config.collectionInitArgs = []string{"x2", "w3"}
	} else {
		return nil, fmt.Errorf("unsupported darwin version: %s (only supports iOS14.x and iOS15.x)", sb.darwin)
	}

	return &sb, nil
}

func (sb *Sandbox) GetOperations() ([]string, error) {
	if len(sb.operations) > 0 {
		return sb.operations, nil
	}

	if dconst := sb.kern.Section("__DATA_CONST", "__const"); dconst != nil {
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

			str, err := sb.kern.GetCString(ptr | tagPtrMask)
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
				sb.operations = append(sb.operations, str)
				if getTag(ptr) != 0x17 { // always directly followed by another pointer
					break
				}
			}
		}
	}

	return sb.operations, nil
}

func (sb *Sandbox) GetCollectionData() ([]byte, error) {
	if len(sb.collectionData) > 0 {
		return sb.collectionData, nil
	}

	log.Info("Searching for sandbox collection data")
	regs, err := sb.emulateBlock(sb.config.collectionInitPanic)
	if err != nil {
		return nil, fmt.Errorf("failed to emulate block containing call to _collection_init(): %v", err)
	}

	collection_data_addr := regs[sb.config.collectionInitArgs[0]]
	collection_data_size := regs[sb.config.collectionInitArgs[1]]

	utils.Indent(log.Debug, 2)(fmt.Sprintf("emulated args:: _collection_init(%#x, \"builtin collection\", %#x, %#x, x4);",
		regs["x0"], // &_builtin_collection
		collection_data_addr,
		collection_data_size),
	)

	collectionOffset, err := sb.kern.GetOffset(collection_data_addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset for _collection_data: %w", err)
	}

	sb.collectionData = make([]byte, collection_data_size)
	if _, err = sb.kern.ReadAt(sb.collectionData, int64(collectionOffset)); err != nil {
		return nil, fmt.Errorf("failed to read _collection_data: %w", err)
	}
	return sb.collectionData, nil
}

func (sb *Sandbox) GetPlatformProfileData() ([]byte, error) {
	if len(sb.platformProfileData) > 0 {
		return sb.platformProfileData, nil
	}

	log.Info("Searching for sandbox platform profile data")
	regs, err := sb.emulateBlock(sb.config.profileInitPanic)
	if err != nil {
		return nil, fmt.Errorf("failed to emulate block containing call to _profile_init(): %v", err)
	}

	platform_profile_data_addr := regs[sb.config.profileInitArgs[0]]
	platform_profile_data_size := regs[sb.config.profileInitArgs[1]]

	utils.Indent(log.Debug, 2)(fmt.Sprintf("emulated args:: _profile_init(%#x, %#x, %#x);", regs["x0"], platform_profile_data_addr, platform_profile_data_size))

	profileOffset, err := sb.kern.GetOffset(platform_profile_data_addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset for _platform_profile_data: %w", err)
	}

	sb.platformProfileData = make([]byte, platform_profile_data_size)
	if _, err = sb.kern.ReadAt(sb.platformProfileData, int64(profileOffset)); err != nil {
		return nil, fmt.Errorf("failed to read _platform_profile_data: %w", err)
	}

	return sb.platformProfileData, nil
}

func (sb *Sandbox) ParseSandboxCollection() error {

	if _, err := sb.GetCollectionData(); err != nil {
		return err
	}

	log.Info("Parsing sandbox collection data")

	r := bytes.NewReader(sb.collectionData)

	if err := binary.Read(r, binary.LittleEndian, sb.config.sbHeader); err != nil {
		return fmt.Errorf("failed to read sandbox profile collection structure: %v", err)
	}
	if err := sb.parseHdr(sb.config.sbHeader); err != nil {
		return fmt.Errorf("failed to parse sandbox profile header structure: %v", err)
	}

	if sb.Hdr.Type != typeCollection {
		return fmt.Errorf("expected collection type, got %#x", sb.Hdr.Type)
	}

	regexOffsets := make([]uint16, sb.Hdr.RegexItemCount)
	if err := binary.Read(r, binary.LittleEndian, &regexOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox profile regex offets: %v", err)
	}

	globalOffsets := make([]uint16, sb.Hdr.GlobalVarCount)
	if err := binary.Read(r, binary.LittleEndian, &globalOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox profile global offets: %v", err)
	}

	msgOffsets := make([]uint16, sb.Hdr.MsgItemCount)
	if err := binary.Read(r, binary.LittleEndian, &msgOffsets); err != nil {
		return fmt.Errorf("failed to read sandbox profile message offets: %v", err)
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing profiles (%d)", sb.Hdr.ProfileCount))
	profileStart, _ := r.Seek(0, io.SeekCurrent)
	for i := uint16(0); i < sb.Hdr.ProfileCount; i++ {
		var err error
		var sbp SandboxProfile
		if err := binary.Read(r, binary.LittleEndian, sb.config.profileType); err != nil {
			return fmt.Errorf("failed to read sandbox profile structure: %v", err)
		}
		sbp.nameOffset, sbp.Version, err = sb.parseProfile(sb.config.profileType)
		if err != nil {
			return fmt.Errorf("failed to parse sandbox profile structure: %v", err)
		}
		sbp.ops = make([]uint16, sb.Hdr.OpCount)
		if err := binary.Read(r, binary.LittleEndian, sbp.ops); err != nil {
			return fmt.Errorf("failed to read sandbox profile structure: %v", err)
		}
		sb.Profiles = append(sb.Profiles, sbp)
	}
	profileEnd, _ := r.Seek(0, io.SeekCurrent)
	utils.Indent(log.WithFields(log.Fields{
		"start": fmt.Sprintf("%#x", profileStart),
		"end":   fmt.Sprintf("%#x", profileEnd),
		"size":  fmt.Sprintf("%#x", profileEnd-profileStart),
	}).Debug, 3)("profiles")

	r.Seek(int64(roundUp(uint64(profileEnd), 8)), io.SeekStart) // alignment

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing operation nodes (%d)", sb.Hdr.OpNodeCount))
	opNodeStart, _ := r.Seek(0, io.SeekCurrent)
	sb.OpNodes = make([]operationNode, sb.Hdr.OpNodeCount)
	if err := binary.Read(r, binary.LittleEndian, sb.OpNodes); err != nil {
		return fmt.Errorf("failed to read sandbox collection operation nodes: %v", err)
	}
	opNodeEnd, _ := r.Seek(0, io.SeekCurrent)
	utils.Indent(log.WithFields(log.Fields{
		"start": fmt.Sprintf("%#x", opNodeStart),
		"end":   fmt.Sprintf("%#x", opNodeEnd),
		"size":  fmt.Sprintf("%#x", opNodeEnd-opNodeStart),
	}).Debug, 3)("operation nodes")

	for idx, prof := range sb.Profiles {
		r.Seek(opNodeEnd+int64(prof.nameOffset)*8, io.SeekStart)
		var size uint16
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return fmt.Errorf("failed to read sandbox collection global variable size: %v", err)
		}
		name := make([]byte, size)
		if err := binary.Read(r, binary.LittleEndian, &name); err != nil {
			return fmt.Errorf("failed to read sandbox collection global variable data: %v", err)
		}
		sb.Profiles[idx].Name = strings.Trim(string(name[:]), "\x00")
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing regex (%d)", sb.Hdr.RegexItemCount))
	for idx, roff := range regexOffsets {
		loc, _ := r.Seek(opNodeEnd+int64(roff)*8, io.SeekStart)
		var size uint16
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return fmt.Errorf("failed to read sandbox collection regex size: %v", err)
		}
		rdat := make([]byte, size)
		if err := binary.Read(r, binary.LittleEndian, &rdat); err != nil {
			return fmt.Errorf("failed to read sandbox collection regex data: %v", err)
		}
		re, err := sandbox.NewRegex(rdat)
		if err != nil {
			return fmt.Errorf("failed to parse sandbox collection regex: %v", err)
		}
		utils.Indent(log.Debug, 3)(fmt.Sprintf("[regex] idx: %d, offset: %#x, version: %d, length: %#x\n\n%s", idx+1, loc, re.Version, re.Length, hex.Dump(re.Data)))
		sb.Regexes = append(sb.Regexes, re)
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing variables (%d)", sb.Hdr.GlobalVarCount))
	for idx, goff := range globalOffsets {
		r.Seek(opNodeEnd+int64(goff)*8, io.SeekStart)
		var size uint16
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return fmt.Errorf("failed to read sandbox collection global variable size: %v", err)
		}
		gdat := make([]byte, size)
		if err := binary.Read(r, binary.LittleEndian, &gdat); err != nil {
			return fmt.Errorf("failed to read sandbox collection global variable data: %v", err)
		}
		sb.Globals = append(sb.Globals, strings.Trim(string(gdat[:]), "\x00"))
		utils.Indent(log.Debug, 3)(sb.Globals[idx])
	}

	// utils.Indent(log.Debug, 2)("Parsing messages")
	// for _, moff := range msgOffsets {
	// 	// loc, _ := r.Seek(opNodeEnd+int64(moff)*8, io.SeekStart)
	// 	loc, _ := r.Seek(opNodeEnd+int64(moff), io.SeekStart)
	// 	fmt.Printf("mod loc: %#x\n", loc)
	// 	// var size uint16
	// 	var size byte
	// 	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
	// 		return fmt.Errorf("failed to read sandbox collection msg size: %v", err)
	// 	}
	// 	mdat := make([]byte, size)
	// 	if err := binary.Read(r, binary.LittleEndian, &mdat); err != nil {
	// 		return fmt.Errorf("failed to read sandbox collection msg data: %v", err)
	// 	}
	// 	sb.Modifiers = append(sb.Modifiers, string(mdat))
	// }

	return nil
}

func (sb *Sandbox) parseXrefs() error {
	if len(sb.xrefs) > 0 {
		return nil
	}

	var kextStartOffset uint64

	startAdders, err := getKextStartVMAddrs(sb.kern)
	if err != nil {
		return fmt.Errorf("failed to get kext start addresses: %w", err)
	}

	infos, err := getKextInfos(sb.kern)
	if err != nil {
		return fmt.Errorf("failed to get kext infos: %w", err)
	}

	for idx, info := range infos {
		if strings.Contains(string(info.Name[:]), "sandbox") {
			sb.kextStartAddr = startAdders[idx] | tagPtrMask
			sb.kextEndAddr = startAdders[idx+1] | tagPtrMask
			kextStartOffset, err = sb.kern.GetOffset(sb.kextStartAddr)
			if err != nil {
				return fmt.Errorf("failed to get sandbox kext start offset: %w", err)
			}
			break
		}
	}

	// TODO: only get function data (avoid parsing macho header etc)
	data := make([]byte, sb.kextEndAddr-sb.kextStartAddr)
	if _, err = sb.kern.ReadAt(data, int64(kextStartOffset)); err != nil {
		return fmt.Errorf("failed to read sandbox kext data: %w", err)
	}

	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	dr := bytes.NewReader(data)
	sb.xrefs = make(map[uint64]uint64)
	startAddr := sb.kextStartAddr

	for {
		err = binary.Read(dr, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}

		if strings.Contains(instruction.Encoding.String(), "branch") { // TODO: this could be slow?
			for _, op := range instruction.Operands {
				if op.Class == disassemble.LABEL {
					sb.xrefs[instruction.Address] = uint64(op.Immediate)
				}
			}
		} else if strings.Contains(instruction.Encoding.String(), "loadlit") { // TODO: this could be slow?
			sb.xrefs[instruction.Address] = uint64(instruction.Operands[1].Immediate)
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
			sb.xrefs[instruction.Address] = adrpImm
		}

		// fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instruction)

		prevInstr = instruction
		startAddr += uint64(binary.Size(uint32(0)))
	}

	return nil
}

// emulateBlock emulates the register state of a block of code that if fails branches to a given panic containing the given error message.
func (sb *Sandbox) emulateBlock(errmsg string) (map[string]uint64, error) {
	if err := sb.parseXrefs(); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox kext xrefs: %w", err)
	}

	panicStrVMAddr, err := findCStringVMaddr(sb.kern, errmsg)
	if err != nil {
		return nil, fmt.Errorf("failed to find panic string matching %s: %w", errmsg, err)
	}

	var panicXrefVMAddr uint64
	for k, v := range sb.xrefs {
		if v == panicStrVMAddr {
			panicXrefVMAddr = k - 4
			utils.Indent(log.Debug, 2)(fmt.Sprintf("panic string xref %#x => %#x", panicXrefVMAddr, v))
			break
		}
	}

	if panicXrefVMAddr == 0 {
		return nil, fmt.Errorf("failed to find panic string cross reference for given error message: %s", errmsg)
	}

	hook_policy_init, err := sb.kern.GetFunctionForVMAddr(panicXrefVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to find _hook_policy_init function: %w", err)
	}

	data, err := sb.kern.GetFunctionData(hook_policy_init)
	if err != nil {
		return nil, fmt.Errorf("failed to get _hook_policy_init function data: %w", err)
	}

	instrs, err := disassemble.GetInstructions(hook_policy_init.StartAddr, data)
	if err != nil {
		return nil, fmt.Errorf("failed to disassemble _hook_policy_init function: %w", err)
	}

	block, err := instrs.GetAddressBlock(panicXrefVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get _hook_policy_init function block containing address %#x: %w", panicXrefVMAddr, err)
	}

	var failXrefVMAddr uint64
	for k, v := range sb.xrefs {
		if v == block[0].Address {
			failXrefVMAddr = k
			utils.Indent(log.Debug, 2)(fmt.Sprintf("failure path xref %#x => %#x", failXrefVMAddr, v))
			break
		}
	}

	block, err = instrs.GetAddressBlock(failXrefVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get _hook_policy_init function block containing xref to failure path %#x: %w", failXrefVMAddr, err)
	}

	/*****************
	 * EMULATE BLOCK *
	 *****************/

	var prevInstr *disassemble.Instruction
	regs := make(map[string]uint64)

	for _, instruction := range block {
		if strings.Contains(instruction.Encoding.String(), "loadlit") { // TODO: this could be slow?
			regs[instruction.Operands[0].Registers[0].String()] = uint64(instruction.Operands[1].Immediate)
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
			regs[instruction.Operands[0].Registers[0].String()] = adrpImm
		} else if instruction.Operation == disassemble.ARM64_MOV {
			regs[instruction.Operands[0].Registers[0].String()] = instruction.Operands[1].Immediate
		} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_MOV) && instruction.Operation == disassemble.ARM64_MOVK {
			regs[instruction.Operands[0].Registers[0].String()] += instruction.Operands[1].GetImmediate()
		}
		prevInstr = instruction
	}

	return regs, nil
}

// TODO: replace with generics
func (sb *Sandbox) parseHdr(hdr any) error {
	switch v := hdr.(type) {
	case *SandboxProfileHeader14:
		sb.Hdr.Type = v.Type
		sb.Hdr.OpNodeCount = v.OpNodeCount
		sb.Hdr.OpCount = v.OpCount
		sb.Hdr.GlobalVarCount = v.GlobalVarCount
		sb.Hdr.ProfileCount = v.ProfileCount
		sb.Hdr.RegexItemCount = v.RegexItemCount
		sb.Hdr.MsgItemCount = v.MsgItemCount
	case *SandboxProfileHeader15:
		sb.Hdr.Type = v.Type
		sb.Hdr.OpNodeCount = v.OpNodeCount
		sb.Hdr.OpCount = v.OpCount
		sb.Hdr.GlobalVarCount = v.GlobalVarCount
		sb.Hdr.ProfileCount = v.ProfileCount
		sb.Hdr.RegexItemCount = v.RegexItemCount
		sb.Hdr.MsgItemCount = v.MsgItemCount
	default:
		return fmt.Errorf("unknown profile header type: %T", v)
	}
	return nil
}

func (sb *Sandbox) parseProfile(p any) (uint16, uint16, error) {
	switch v := p.(type) {
	case *profile14:
		return v.NameOffset, v.Version, nil
	case *profile15:
		return v.NameOffset, v.Version, nil
	default:
		return 0, 0, fmt.Errorf("unknown profile header type: %T", v)
	}
}

type FilterInfo struct {
	Name     string
	Category string
	Aliases  []Alias
	filterInfo
}

type filterInfo struct {
	NameAddr     uint64
	CategoryAddr uint64
	Unknown1     uint16
	Unknown2     uint16
	Unknown3     uint32
	AliasesAddr  uint64
}

type Alias struct {
	Name string
	alias
}

type alias struct {
	NameAddr uint64
	Value    uint16
	Unknown1 uint16
	Unknown2 uint16
	Unknown3 uint16
}

func GetFilterInfo(d *dyld.File) ([]FilterInfo, error) {
	var finfos []FilterInfo

	libsand, err := d.Image("libsandbox.1.dylib")
	if err != nil {
		return nil, fmt.Errorf("failed to get libsandbox.1.dylib image: %w", err)
	}

	m, err := libsand.GetMacho()
	if err != nil {
		return nil, fmt.Errorf("failed to get libsandbox.1.dylib macho: %w", err)
	}

	filterInfoAddr, err := m.FindSymbolAddress("_filter_info")
	if err != nil {
		return nil, fmt.Errorf("failed to find _filter_info symbol: %w", err)
	}
	uuid, filterInfoOff, err := d.GetOffset(filterInfoAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get _filter_info offset: %w", err)
	}

	// TODO: maybe get filter info count from xref to _lookup_filter_info (is 0x55 in test libsandbox)
	NUM_INFO_ENTRIES := 0x55
	dat, err := d.ReadBytesForUUID(uuid, int64(filterInfoOff), uint64((NUM_INFO_ENTRIES+1)*binary.Size(filterInfo{})))
	if err != nil {
		return nil, fmt.Errorf("failed to read _filter_info data: %w", err)
	}

	r := bytes.NewReader(dat)

	for i := 0; i <= NUM_INFO_ENTRIES; i++ {
		var fi FilterInfo
		if err := binary.Read(r, binary.LittleEndian, &fi.filterInfo); err != nil {
			return nil, fmt.Errorf("failed to read _filter_info item %d: %w", i, err)
		}
		if fi.NameAddr != 0 {
			fi.Name, err = d.GetCString(d.SlideInfo.SlidePointer(fi.NameAddr))
			if err != nil {
				return nil, fmt.Errorf("failed to read _filter_info item %d name: %w", i, err)
			}
		}
		if fi.CategoryAddr != 0 {
			fi.Category, err = d.GetCString(d.SlideInfo.SlidePointer(fi.CategoryAddr))
			if err != nil {
				return nil, fmt.Errorf("failed to read _filter_info item %d category: %w", i, err)
			}
		}
		if fi.AliasesAddr != 0 {
			// parse aliases
			next := uint64(0)
			sizeOfAlias := uint64(binary.Size(alias{}))
			for {
				var a Alias
				uuid, off, err := d.GetOffset(d.SlideInfo.SlidePointer(fi.AliasesAddr) + next)
				if err != nil {
					return nil, fmt.Errorf("failed to get alias offset for addr %#x: %w", d.SlideInfo.SlidePointer(fi.AliasesAddr)+next, err)
				}
				dat, err := d.ReadBytesForUUID(uuid, int64(off), sizeOfAlias)
				if err != nil {
					return nil, fmt.Errorf("failed to read alias data: %w", err)
				}
				if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &a.alias); err != nil {
					return nil, fmt.Errorf("failed to read alias: %w", err)
				}
				if a.NameAddr == 0 {
					break
				}
				a.Name, err = d.GetCString(d.SlideInfo.SlidePointer(a.NameAddr))
				if err != nil {
					return nil, fmt.Errorf("failed to read alias name: %w", err)
				}
				fi.Aliases = append(fi.Aliases, a)
				next += uint64(sizeOfAlias)
			}
		}
		finfos = append(finfos, fi)
	}

	return finfos, nil
}

type ModifierInfo struct {
	Name    string
	Aliases []Alias
	modifierInfo
}

type modifierInfo struct {
	NameAddr    uint64
	Unknown1    uint32
	Unknown2    uint32
	Unknown3    uint32
	Unknown4    uint32
	AliasesAddr uint64
}

func GetModifierInfo(d *dyld.File) ([]ModifierInfo, error) {
	var minfos []ModifierInfo

	libsand, err := d.Image("libsandbox.1.dylib")
	if err != nil {
		return nil, fmt.Errorf("failed to find libsandbox.1.dylib: %w", err)
	}

	m, err := libsand.GetMacho()
	if err != nil {
		return nil, fmt.Errorf("failed to get libsandbox.1.dylib macho: %w", err)
	}

	modifierInfoAddr, err := m.FindSymbolAddress("_modifier_info")
	if err != nil {
		return nil, fmt.Errorf("failed to find _modifier_info symbol: %w", err)
	}
	uuid, modifierInfoOff, err := d.GetOffset(modifierInfoAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get _modifier_info offset: %w", err)
	}

	// TODO: maybe get SB_MODIFIER_COUNT from xref to ___sb_modifiers_apply_action_flags_block_invoke (is 0x15 in test libsandbox)
	SB_MODIFIER_COUNT := 0x15
	dat, err := d.ReadBytesForUUID(uuid, int64(modifierInfoOff), uint64(SB_MODIFIER_COUNT*binary.Size(modifierInfo{})))
	if err != nil {
		return nil, fmt.Errorf("failed to read _modifier_info data: %w", err)
	}

	r := bytes.NewReader(dat)

	for i := 0; i < SB_MODIFIER_COUNT; i++ {
		var mi ModifierInfo
		if err := binary.Read(r, binary.LittleEndian, &mi.modifierInfo); err != nil {
			return nil, fmt.Errorf("failed to read _modifier_info item %d: %w", i, err)
		}
		if mi.NameAddr != 0 {
			mi.Name, err = d.GetCString(d.SlideInfo.SlidePointer(mi.NameAddr))
			if err != nil {
				return nil, fmt.Errorf("failed to read _modifier_info item %d name: %w", i, err)
			}
		}
		if mi.AliasesAddr != 0 {
			// parse aliases
			next := uint64(0)
			sizeOfAlias := uint64(binary.Size(alias{}))
			for {
				var a Alias
				uuid, off, err := d.GetOffset(d.SlideInfo.SlidePointer(mi.AliasesAddr) + next)
				if err != nil {
					return nil, fmt.Errorf("failed to get alias offset for addr %#x: %w", d.SlideInfo.SlidePointer(mi.AliasesAddr)+next, err)
				}
				dat, err := d.ReadBytesForUUID(uuid, int64(off), sizeOfAlias)
				if err != nil {
					return nil, fmt.Errorf("failed to read alias data: %w", err)
				}
				if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &a.alias); err != nil {
					return nil, fmt.Errorf("failed to read alias: %w", err)
				}
				if a.NameAddr == 0 {
					break
				}
				a.Name, err = d.GetCString(d.SlideInfo.SlidePointer(a.NameAddr))
				if err != nil {
					return nil, fmt.Errorf("failed to read alias name: %w", err)
				}
				mi.Aliases = append(mi.Aliases, a)
				next += uint64(sizeOfAlias)
			}
		}
		minfos = append(minfos, mi)
	}

	return minfos, nil
}

type OperationInfo struct {
	Name       string
	Modifiers  []string
	Categories []string
	operationInfo
}

type operationInfo struct {
	Unknown1       uint32
	Unknown2       uint32
	Unknown3       uint64
	CategoriesAddr uint64
	ModifiersAddr  uint64
	UnknownAddr    uint64
}

func GetOperationInfo(d *dyld.File) ([]OperationInfo, error) {
	var opNames []string
	var opInfos []OperationInfo

	libsand, err := d.Image("libsandbox.1.dylib")
	if err != nil {
		return nil, fmt.Errorf("failed to get image libsandbox.1.dylib: %w", err)
	}

	m, err := libsand.GetMacho()
	if err != nil {
		return nil, fmt.Errorf("failed to get macho for libsandbox.1.dylib: %w", err)
	}

	operationNamesAddr, err := m.FindSymbolAddress("_operation_names")
	if err != nil {
		return nil, fmt.Errorf("failed to find _operation_names symbol: %w", err)
	}
	uuid, operationNamesOff, err := d.GetOffset(operationNamesAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get _operation_names offset: %w", err)
	}

	operationInfoAddr, err := m.FindSymbolAddress("_operation_info")
	if err != nil {
		return nil, fmt.Errorf("failed to find _operation_info symbol: %w", err)
	}

	dat, err := d.ReadBytesForUUID(uuid, int64(operationNamesOff), operationInfoAddr-operationNamesAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to read _operation_names data: %w", err)
	}

	onAddrs := make([]uint64, len(dat)/binary.Size(uint64(0)))
	if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &onAddrs); err != nil {
		return nil, fmt.Errorf("failed to read _operation_names addrs: %w", err)
	}

	for _, addr := range onAddrs {
		name, err := d.GetCString(d.SlideInfo.SlidePointer(addr))
		if err != nil {
			return nil, fmt.Errorf("failed to read operation name: %w", err)
		}
		opNames = append(opNames, name)
	}

	uuid, operationInfoOff, err := d.GetOffset(operationInfoAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get _operation_info offset: %w", err)
	}

	dat, err = d.ReadBytesForUUID(uuid, int64(operationInfoOff), uint64(len(opNames)*binary.Size(operationInfo{})))
	if err != nil {
		return nil, fmt.Errorf("failed to read _operation_info data: %w", err)
	}

	oinfos := make([]operationInfo, len(opNames))
	if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &oinfos); err != nil {
		return nil, fmt.Errorf("failed to read _operation_info(s): %w", err)
	}

	for idx, oi := range oinfos {
		oinfo := OperationInfo{
			Name:          opNames[idx],
			operationInfo: oi,
		}
		if oi.CategoriesAddr != 0 {
			// parse catergories
			next := uint64(0)
			for {
				addr, err := d.ReadPointerAtAddress(d.SlideInfo.SlidePointer(oi.CategoriesAddr) + next)
				if err != nil {
					return nil, fmt.Errorf("failed to read category addr at %#x: %w", d.SlideInfo.SlidePointer(oi.CategoriesAddr)+next, err)
				}
				if addr == 0 {
					break
				}
				cat, err := d.GetCString(d.SlideInfo.SlidePointer(addr))
				if err != nil {
					return nil, fmt.Errorf("failed to read category at %#x: %w", addr, err)
				}
				oinfo.Categories = append(oinfo.Categories, cat)
				next += uint64(binary.Size(uint64(0)))
			}
		}
		if oi.ModifiersAddr != 0 {
			// parse modifiers
			next := uint64(0)
			for {
				addr, err := d.ReadPointerAtAddress(d.SlideInfo.SlidePointer(oi.ModifiersAddr) + next)
				if err != nil {
					return nil, fmt.Errorf("failed to read modifier addr at %#x: %w", d.SlideInfo.SlidePointer(oi.ModifiersAddr)+next, err)
				}
				if addr == 0 {
					break
				}
				mod, err := d.GetCString(d.SlideInfo.SlidePointer(addr))
				if err != nil {
					return nil, fmt.Errorf("failed to read modifier at %#x: %w", addr, err)
				}
				oinfo.Modifiers = append(oinfo.Modifiers, mod)
				next += uint64(binary.Size(uint64(0)))
			}
		}
		if oi.UnknownAddr != 0 {
			// TODO: read unknown struct
		}
		opInfos = append(opInfos, oinfo)
	}

	return opInfos, nil
}

func getTag(ptr uint64) uint64 {
	return ptr >> 48
}

func unTag(ptr uint64) uint64 {
	return (ptr & ((1 << 48) - 1)) | (0xffff << 48)
}

func roundUp(x, align uint64) uint64 {
	return uint64((x + align - 1) & -align)
}
