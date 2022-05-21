package sandbox

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/hashicorp/go-version"
)

const (
	typeProfile           = 0x0000
	typeCollection        = 0x8000
	tagPtrMask            = 0xffff000000000000
	profileInitPanic      = "failed to initialize platform sandbox"
	collectionInitPanic14 = "failed to initialize collection"
	collectionInitPanic15 = "failed to initialize builtin collection"
)

type Sandbox struct {
	Hdr header

	Profiles  []Profile
	OpNodes   []OperationNode
	Regexes   []*Regex
	Globals   []string
	Modifiers []string

	Operations []string
	sbData     []byte
	baseOffset int64

	darwin        *version.Version
	kextStartAddr uint64
	kextEndAddr   uint64
	xrefs         map[uint64]uint64
	config        Config
	db            *LibSandbox
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

type header14 struct {
	Type           uint16
	OpNodeCount    uint16
	OpCount        uint8
	GlobalVarCount uint8
	ProfileCount   uint16
	RegexItemCount uint16
	MsgItemCount   uint16
}

type header15 struct {
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

type profile14 struct {
	NameOffset uint16
	Version    uint16
}

type profile15 struct {
	NameOffset uint16
	Version    uint16
	Unknown    uint16
}

type Profile struct {
	Name       string
	nameOffset uint16
	Version    uint16
	Operands   []uint16
}

func (p Profile) String() string {
	return fmt.Sprintf("[+] %s, version: %d", p.Name, p.Version)
}

type Config struct {
	Kernel         *macho.File
	ProfileBinPath string

	sbHeader            any
	profileType         any
	profileInitPanic    string
	profileInitArgs     []string
	collectionInitPanic string
	collectionInitArgs  []string
}

func NewSandbox(c *Config) (*Sandbox, error) {
	sb := Sandbox{
		Profiles: make([]Profile, 0),
		config:   *c,
	}

	if _, err := sb.GetOperations(); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox operations: %w", err)
	}

	if kv, err := kernelcache.GetVersion(sb.config.Kernel); err != nil {
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
		sb.config.sbHeader = &header14{}
		sb.config.profileType = &profile14{}
		sb.config.collectionInitPanic = collectionInitPanic14
		sb.config.collectionInitArgs = []string{"x1", "w2"}
	} else if iOS15x.Check(sb.darwin) {
		sb.config.sbHeader = &header15{}
		sb.config.profileType = &profile15{}
		sb.config.collectionInitPanic = collectionInitPanic15
		sb.config.collectionInitArgs = []string{"x2", "w3"}
	} else {
		return nil, fmt.Errorf("unsupported darwin version: %s (only supports iOS14.x and iOS15.x)", sb.darwin)
	}

	sb.db, err = GetLibSandBoxDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get libsandbox db: %w", err)
	}

	return &sb, nil
}

func (sb *Sandbox) GetOperations() ([]string, error) {
	if len(sb.Operations) > 0 {
		return sb.Operations, nil
	}

	if dconst := sb.config.Kernel.Section("__DATA_CONST", "__const"); dconst != nil {
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

			str, err := sb.config.Kernel.GetCString(ptr | tagPtrMask)
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
				sb.Operations = append(sb.Operations, str)
				if getTag(ptr) != 0x17 { // always directly followed by another pointer
					break
				}
			}
		}
	}

	return sb.Operations, nil
}

func (sb *Sandbox) GetCollectionData() ([]byte, error) {
	if len(sb.sbData) > 0 {
		return sb.sbData, nil
	}

	if len(sb.config.ProfileBinPath) > 0 {
		var err error
		sb.sbData, err = ioutil.ReadFile(sb.config.ProfileBinPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read sandbox collection profile data file: %w", err)
		}
		return sb.sbData, nil
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

	collectionOffset, err := sb.config.Kernel.GetOffset(collection_data_addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset for _collection_data: %w", err)
	}

	sb.sbData = make([]byte, collection_data_size)
	if _, err = sb.config.Kernel.ReadAt(sb.sbData, int64(collectionOffset)); err != nil {
		return nil, fmt.Errorf("failed to read _collection_data: %w", err)
	}

	return sb.sbData, nil
}

func (sb *Sandbox) GetPlatformProfileData() ([]byte, error) {
	if len(sb.sbData) > 0 {
		return sb.sbData, nil
	}

	if len(sb.config.ProfileBinPath) > 0 {
		var err error
		sb.sbData, err = ioutil.ReadFile(sb.config.ProfileBinPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read platform profile data file: %w", err)
		}
		return sb.sbData, nil
	}

	log.Info("Searching for sandbox platform profile data")
	regs, err := sb.emulateBlock(sb.config.profileInitPanic)
	if err != nil {
		return nil, fmt.Errorf("failed to emulate block containing call to _profile_init(): %v", err)
	}

	platform_profile_data_addr := regs[sb.config.profileInitArgs[0]]
	platform_profile_data_size := regs[sb.config.profileInitArgs[1]]

	utils.Indent(log.Debug, 2)(fmt.Sprintf("emulated args:: _profile_init(%#x, %#x, %#x);", regs["x0"], platform_profile_data_addr, platform_profile_data_size))

	profileOffset, err := sb.config.Kernel.GetOffset(platform_profile_data_addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset for _platform_profile_data: %w", err)
	}

	sb.sbData = make([]byte, platform_profile_data_size)
	if _, err = sb.config.Kernel.ReadAt(sb.sbData, int64(profileOffset)); err != nil {
		return nil, fmt.Errorf("failed to read _platform_profile_data: %w", err)
	}

	return sb.sbData, nil
}

func (sb *Sandbox) ParseSandboxProfile() error {

	if _, err := sb.GetPlatformProfileData(); err != nil {
		return err
	}

	log.Info("Parsing sandbox profile data")

	r := bytes.NewReader(sb.sbData)

	if err := binary.Read(r, binary.LittleEndian, sb.config.sbHeader); err != nil {
		return fmt.Errorf("failed to read sandbox profile structure: %v", err)
	}
	if err := sb.parseHdr(sb.config.sbHeader); err != nil {
		return fmt.Errorf("failed to parse sandbox profile header structure: %v", err)
	}

	if sb.Hdr.Type != typeProfile {
		return fmt.Errorf("expected profile type, got %#x", sb.Hdr.Type)
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

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing profile operands (%d)", sb.Hdr.OpCount))
	var sbp Profile
	sbp.Operands = make([]uint16, sb.Hdr.OpCount)
	if err := binary.Read(r, binary.LittleEndian, sbp.Operands); err != nil {
		return fmt.Errorf("failed to read sandbox profile operands: %v", err)
	}
	sb.Profiles = append(sb.Profiles, sbp)

	operandEnd, _ := r.Seek(0, io.SeekCurrent)
	r.Seek(int64(roundUp(uint64(operandEnd), 8)), io.SeekStart) // alignment

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing operation nodes (%d)", sb.Hdr.OpNodeCount))
	opNodeStart, _ := r.Seek(0, io.SeekCurrent)
	sb.OpNodes = make([]OperationNode, sb.Hdr.OpNodeCount)
	if err := binary.Read(r, binary.LittleEndian, sb.OpNodes); err != nil {
		return fmt.Errorf("failed to read sandbox collection operation nodes: %v", err)
	}

	sb.baseOffset, _ = r.Seek(0, io.SeekCurrent)
	utils.Indent(log.WithFields(log.Fields{
		"start": fmt.Sprintf("%#x", opNodeStart),
		"end":   fmt.Sprintf("%#x", sb.baseOffset),
		"size":  fmt.Sprintf("%#x", sb.baseOffset-opNodeStart),
	}).Debug, 3)("operation nodes")

	if sb.Hdr.RegexItemCount > 0 {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing regex (%d)", sb.Hdr.RegexItemCount))
		for idx, roff := range regexOffsets {
			loc, _ := r.Seek(sb.baseOffset+int64(roff)*8, io.SeekStart)
			var size uint16
			if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
				return fmt.Errorf("failed to read sandbox collection regex size: %v", err)
			}
			rdat := make([]byte, size)
			if err := binary.Read(r, binary.LittleEndian, &rdat); err != nil {
				return fmt.Errorf("failed to read sandbox collection regex data: %v", err)
			}
			re, err := NewRegex(rdat)
			if err != nil {
				return fmt.Errorf("failed to parse sandbox collection regex: %v", err)
			}
			utils.Indent(log.Debug, 3)(fmt.Sprintf("[regex] idx: %d, offset: %#x, version: %d, length: %#x\n\n%s", idx+1, loc, re.Version, re.Length, hex.Dump(re.Data)))
			sb.Regexes = append(sb.Regexes, re)
		}
	}

	if sb.Hdr.GlobalVarCount > 0 {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing variables (%d)", sb.Hdr.GlobalVarCount))
		for idx, goff := range globalOffsets {
			r.Seek(sb.baseOffset+int64(goff)*8, io.SeekStart)
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
	}

	return nil
}

func (sb *Sandbox) ParseSandboxCollection() error {

	if _, err := sb.GetCollectionData(); err != nil {
		return err
	}

	log.Info("Parsing sandbox collection data")

	r := bytes.NewReader(sb.sbData)

	if err := binary.Read(r, binary.LittleEndian, sb.config.sbHeader); err != nil {
		return fmt.Errorf("failed to read sandbox profile collection structure: %v", err)
	}
	if err := sb.parseHdr(sb.config.sbHeader); err != nil {
		return fmt.Errorf("failed to parse sandbox profile collection header structure: %v", err)
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
		var sbp Profile
		if err := binary.Read(r, binary.LittleEndian, sb.config.profileType); err != nil {
			return fmt.Errorf("failed to read sandbox profile structure: %v", err)
		}
		sbp.nameOffset, sbp.Version, err = sb.parseProfile(sb.config.profileType)
		if err != nil {
			return fmt.Errorf("failed to parse sandbox profile structure: %v", err)
		}
		sbp.Operands = make([]uint16, sb.Hdr.OpCount)
		if err := binary.Read(r, binary.LittleEndian, sbp.Operands); err != nil {
			return fmt.Errorf("failed to read sandbox profile operands: %v", err)
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
	sb.OpNodes = make([]OperationNode, sb.Hdr.OpNodeCount)
	if err := binary.Read(r, binary.LittleEndian, sb.OpNodes); err != nil {
		return fmt.Errorf("failed to read sandbox collection operation nodes: %v", err)
	}
	sb.baseOffset, _ = r.Seek(0, io.SeekCurrent)
	utils.Indent(log.WithFields(log.Fields{
		"start": fmt.Sprintf("%#x", opNodeStart),
		"end":   fmt.Sprintf("%#x", sb.baseOffset),
		"size":  fmt.Sprintf("%#x", sb.baseOffset-opNodeStart),
	}).Debug, 3)("operation nodes")

	for idx, prof := range sb.Profiles {
		r.Seek(sb.baseOffset+int64(prof.nameOffset)*8, io.SeekStart)
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
		loc, _ := r.Seek(sb.baseOffset+int64(roff)*8, io.SeekStart)
		var size uint16
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return fmt.Errorf("failed to read sandbox collection regex size: %v", err)
		}
		rdat := make([]byte, size)
		if err := binary.Read(r, binary.LittleEndian, &rdat); err != nil {
			return fmt.Errorf("failed to read sandbox collection regex data: %v", err)
		}
		re, err := NewRegex(rdat)
		if err != nil {
			return fmt.Errorf("failed to parse sandbox collection regex: %v", err)
		}
		utils.Indent(log.Debug, 3)(fmt.Sprintf("[regex] idx: %d, offset: %#x, version: %d, length: %#x\n\n%s", idx+1, loc, re.Version, re.Length, hex.Dump(re.Data)))
		sb.Regexes = append(sb.Regexes, re)
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Parsing variables (%d)", sb.Hdr.GlobalVarCount))
	for idx, goff := range globalOffsets {
		r.Seek(sb.baseOffset+int64(goff)*8, io.SeekStart)
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
	// 	// loc, _ := r.Seek(sb.baseOffset+int64(moff)*8, io.SeekStart)
	// 	loc, _ := r.Seek(sb.baseOffset+int64(moff), io.SeekStart)
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

func (sb *Sandbox) GetProfile(name string) (Profile, error) {
	for _, p := range sb.Profiles {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("profile %s not found", name)
}

func (sb *Sandbox) GetStringAtOffset(offset uint32) (string, error) {
	if len(sb.sbData) == 0 {
		return "", fmt.Errorf("sandbox data not loaded")
	}

	r := bytes.NewReader(sb.sbData)

	r.Seek(sb.baseOffset+int64(offset)*8, io.SeekStart)

	var size uint16
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return "", fmt.Errorf("failed to read sandbox collection string size: %v", err)
	}

	name := make([]byte, size)
	if err := binary.Read(r, binary.LittleEndian, &name); err != nil {
		return "", fmt.Errorf("failed to read sandbox collection string data: %v", err)
	}

	return strings.Trim(string(name[:]), "\x00"), nil
}

// FIXME: not sure how this works yet (look at func 'generate_syscallmask' in libsandbox.1.dylib)
func (sb *Sandbox) GetBitMaskAtOffset(offset uint32) ([]byte, error) {
	if len(sb.sbData) == 0 {
		return nil, fmt.Errorf("sandbox data not loaded")
	}
	r := bytes.NewReader(sb.sbData)

	r.Seek(sb.baseOffset+int64(offset)*8, io.SeekStart)

	var version uint16
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("failed to read sandbox collection bitmask data version: %v", err)
	}

	if version != 1 {
		return nil, fmt.Errorf("unsupported bitmask version: %d, expected 1", version)
	}

	var byteCount uint16
	if err := binary.Read(r, binary.LittleEndian, &byteCount); err != nil {
		return nil, fmt.Errorf("failed to read sandbox collection bitmask data byte count: %v", err)
	}

	if byteCount >= 8191 { // TODO: remove this?
		return nil, fmt.Errorf("bitmask byte count too large: %d >= UINT16_MAX / NBBY", byteCount)
	}

	data := make([]byte, byteCount)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return nil, fmt.Errorf("failed to read sandbox collection bitmask data: %v", err)
	}
	// TODO: I do notice that the bytes in the array seem to decrease cyclically (pattern?)
	return data, nil
}

func (sb *Sandbox) GetRSStringAtOffset(offset uint32) ([]string, error) {
	if len(sb.sbData) == 0 {
		return nil, fmt.Errorf("sandbox data not loaded")
	}
	r := bytes.NewReader(sb.sbData)

	r.Seek(sb.baseOffset+int64(offset)*8, io.SeekStart)

	var size uint16
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return nil, fmt.Errorf("failed to read sandbox string pattern size: %v", err)
	}

	byteString := make([]byte, size)
	if err := binary.Read(r, binary.LittleEndian, &byteString); err != nil {
		return nil, fmt.Errorf("failed to read sandbox string pattern data: %v", err)
	}

	return ParseRSS(byteString, sb.Globals)
}

func (sb *Sandbox) GetHostPortAtOffset(offset uint32) (uint16, uint16, error) {
	if len(sb.sbData) == 0 {
		return 0, 0, fmt.Errorf("sandbox data not loaded")
	}

	r := bytes.NewReader(sb.sbData)

	r.Seek(sb.baseOffset+int64(offset)*8, io.SeekStart)

	var host uint16
	if err := binary.Read(r, binary.LittleEndian, &host); err != nil {
		return 0, 0, fmt.Errorf("failed to read sandbox network host: %v", err)
	}
	var port uint16
	if err := binary.Read(r, binary.LittleEndian, &port); err != nil {
		return 0, 0, fmt.Errorf("failed to read sandbox network port: %v", err)
	}

	return host, port, nil
}

func (sb *Sandbox) parseXrefs() error {
	if len(sb.xrefs) > 0 {
		return nil
	}

	var kextStartOffset uint64

	startAdders, err := kernelcache.GetKextStartVMAddrs(sb.config.Kernel)
	if err != nil {
		return fmt.Errorf("failed to get kext start addresses: %w", err)
	}

	infos, err := kernelcache.GetKextInfos(sb.config.Kernel)
	if err != nil {
		return fmt.Errorf("failed to get kext infos: %w", err)
	}

	for idx, info := range infos {
		if strings.Contains(string(info.Name[:]), "sandbox") {
			sb.kextStartAddr = startAdders[idx] | tagPtrMask
			sb.kextEndAddr = startAdders[idx+1] | tagPtrMask
			kextStartOffset, err = sb.config.Kernel.GetOffset(sb.kextStartAddr)
			if err != nil {
				return fmt.Errorf("failed to get sandbox kext start offset: %w", err)
			}
			break
		}
	}

	// TODO: only get function data (avoid parsing macho header etc)
	data := make([]byte, sb.kextEndAddr-sb.kextStartAddr)
	if _, err = sb.config.Kernel.ReadAt(data, int64(kextStartOffset)); err != nil {
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

	panicStrVMAddr, err := findCStringVMaddr(sb.config.Kernel, errmsg)
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

	hook_policy_init, err := sb.config.Kernel.GetFunctionForVMAddr(panicXrefVMAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to find _hook_policy_init function: %w", err)
	}

	data, err := sb.config.Kernel.GetFunctionData(hook_policy_init)
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
	case *header14:
		sb.Hdr.Type = v.Type
		sb.Hdr.OpNodeCount = v.OpNodeCount
		sb.Hdr.OpCount = v.OpCount
		sb.Hdr.GlobalVarCount = v.GlobalVarCount
		sb.Hdr.ProfileCount = v.ProfileCount
		sb.Hdr.RegexItemCount = v.RegexItemCount
		sb.Hdr.MsgItemCount = v.MsgItemCount
	case *header15:
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

/* UTILS */

func findCStringVMaddr(m *macho.File, cstr string) (uint64, error) {
	for _, sec := range m.Sections {

		if sec.Flags.IsCstringLiterals() || strings.Contains(sec.Name, "cstring") {
			dat, err := sec.Data()
			if err != nil {
				return 0, fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
			}

			csr := bytes.NewBuffer(dat[:])

			for {
				pos := sec.Addr + uint64(csr.Cap()-csr.Len())

				s, err := csr.ReadString('\x00')

				if err == io.EOF {
					break
				}

				if err != nil {
					return 0, fmt.Errorf("failed to read string: %v", err)
				}

				if len(s) > 0 && strings.Contains(strings.Trim(s, "\x00"), cstr) {
					return pos, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("string not found in MachO")
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
