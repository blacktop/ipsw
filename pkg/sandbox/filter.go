package sandbox

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/pkg/dyld"
)

const (
	SB_VALUE_TYPE_NONE            = 0
	SB_VALUE_TYPE_BOOL            = 1
	SB_VALUE_TYPE_BITFIELD        = 2
	SB_VALUE_TYPE_INTEGER         = 3
	SB_VALUE_TYPE_STRING          = 4
	SB_VALUE_TYPE_PATTERN_LITERAL = 5
	SB_VALUE_TYPE_PATTERN_PREFIX  = 6
	SB_VALUE_TYPE_PATTERN_SUBPATH = 7
	SB_VALUE_TYPE_PATTERN_REGEX   = 8
	SB_VALUE_TYPE_REGEX           = 9
	SB_VALUE_TYPE_NETWORK         = 10
	// SB_VALUE_TYPE_BITMASK         = 11
)

type lsversion uint8

const (
	IOS15 lsversion = iota
	IOS16
)

//go:embed data/libsandbox_12.5.0.gz
var libsandbox1250Data []byte

//go:embed data/libsandbox_13.0.0.gz
var libsandbox1300Data []byte

type LibSandbox struct {
	Operations []OperationInfo `json:"operations,omitempty"`
	Filters    []FilterInfo    `json:"filters,omitempty"`
	Modifiers  []ModifierInfo  `json:"modifiers,omitempty"`
}

func GetLibSandBoxDB(ver lsversion) (*LibSandbox, error) {
	var err error
	var lb *LibSandbox
	var zr *gzip.Reader

	switch ver {
	case IOS15:
		zr, err = gzip.NewReader(bytes.NewReader(libsandbox1250Data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
	case IOS16:
		zr, err = gzip.NewReader(bytes.NewReader(libsandbox1300Data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
	}

	if err := json.NewDecoder(zr).Decode(&lb); err != nil {
		return nil, fmt.Errorf("failed to decode libsandbox data: %w", err)
	}

	return lb, nil
}

// NOTE: bool __fastcall sb_filter_accepts_type(unsigned int a1, unsigned int a2) in libsandbox.1.dylib
func (db *LibSandbox) FilterAcceptsType(filter *FilterInfo, filterArgType int) bool {
	return false
}

func (db *LibSandbox) GetFilter(id uint8) (*FilterInfo, error) {
	if int(id) >= len(db.Filters) {
		return nil, fmt.Errorf("invalid filter id: %d", id)
	}
	return &db.Filters[id], nil
}

func (f *FilterInfo) GetArgument(sb *Sandbox, id uint16, alt bool) (any, error) {
	if alt {
		log.Debugf("💁 %s: type: %#x, arg: %#x, alt: %t\n", f.Name, f.DataType, id, alt)
	}
	switch f.DataType {
	case SB_VALUE_TYPE_BOOL:
		if id == 1 {
			return "#t", nil
		}
		return "#f", nil
	case SB_VALUE_TYPE_BITFIELD:
		return fmt.Sprintf("#o%04o", id), nil
	case SB_VALUE_TYPE_STRING:
		if alt { // bitmask variant
			mask, err := sb.GetBitMaskAtOffset(uint32(id))
			if err != nil {
				return nil, err
			}
			var aliases []string
			for idx, add := range mask {
				if add {
					alias, err := f.Aliases.Get(uint16(idx))
					if err != nil {
						return nil, err
					}
					aliases = append(aliases, alias.Name)
				}
			}
			return aliases, nil
		} else {
			alias, err := f.Aliases.Get(id) // TODO: why do these have aliases?
			if err != nil {
				// Convert integer value to IO control string
				return fmt.Sprintf("_IO \"%c\" %d", rune(id>>8), int(id&0xff)), nil
			}
			return alias.Name, nil
		}
	case SB_VALUE_TYPE_INTEGER:
		alias, err := f.Aliases.Get(id)
		if err != nil {
			return fmt.Sprintf("%d", id), nil
		}
		return alias.Name, nil
	case SB_VALUE_TYPE_PATTERN_LITERAL:
		s, err := sb.GetStringAtOffset(uint32(id))
		if err != nil {
			return nil, err
		}
		return s, nil
	case SB_VALUE_TYPE_PATTERN_PREFIX, SB_VALUE_TYPE_PATTERN_SUBPATH:
		if alt { // regex variant
			// n, err := sb.Regexes[id].NFA() // FIXME: finish NFA implimentation
			// if err != nil {
			// 	return nil, err
			// }
			// fmt.Println(n)
			return "regex #\"\"", nil
			// return nil, fmt.Errorf("not sure how to parse alt for data type %d yet", f.DataType)
		} else {
			ss, err := sb.GetRSStringAtOffset(uint32(id))
			if err != nil {
				return nil, err
			}
			if len(ss) == 1 {
				return ss[0], nil
			}
			return ss, nil
			// return fmt.Sprintf("\"%s\"", strings.Join(ss, " ")), nil
		}
	case SB_VALUE_TYPE_PATTERN_REGEX:
		if alt { // regex variant
			// n, err := sb.Regexes[id].NFA() // FIXME: finish NFA implimentation
			// if err != nil {
			// 	return nil, err
			// }
			// fmt.Println(n)
			return "regex #\"\"", nil
			// return nil, fmt.Errorf("not sure how to parse alt for data type %d yet", f.DataType)
		} else {
			ss, err := sb.GetRSStringAtOffset(uint32(id))
			if err != nil {
				return nil, err
			}
			// return []string{"literal", fmt.Sprintf("\"%s\"", strings.Join(ss, " "))}, nil
			return ss, nil
		}
	case SB_VALUE_TYPE_NETWORK:
		// NOTE: ___define_network_filter_block_invoke(void* arg1, int64_t* arg2, int32_t* arg3) in libsandbox.1.dylib
		host, port, err := sb.GetHostPortAtOffset(uint32(id))
		if err != nil {
			return nil, err
		}
		hostStr := "*"
		if host > 0x100 {
			hostStr = "localhost"
			host &= 0xff
		}
		alias, err := f.Aliases.Get(host)
		if err != nil {
			return nil, err
		}
		portStr := "*"
		if port != 0 {
			portStr = fmt.Sprintf("%d", port)
		}
		return fmt.Sprintf("%s \"%s:%s\"", alias.Name, hostStr, portStr), nil
	default:
		return nil, fmt.Errorf("unsupported filter argument type: %d", f.DataType)
	}
}

/**********************
 * LibSandbox Builder *
 **********************/

type FilterInfo struct {
	ID       int     `json:"id"`
	Name     string  `json:"name,omitempty"`
	Category string  `json:"category,omitempty"`
	Aliases  Aliases `json:"aliases,omitempty"`
	filterInfo
}

type filterInfo struct {
	NameAddr     uint64 `json:"-"`
	CategoryAddr uint64 `json:"-"`
	DataType     uint8  `json:"data_type,omitempty"`
	IsContrary   uint8  `json:"is_contrary,omitempty"`
	CostFactor   uint16 `json:"cost_factor,omitempty"`
	Dependency   uint32 `json:"dependency,omitempty"`
	AliasesAddr  uint64 `json:"-"`
}

type Aliases []Alias

func (a Aliases) Get(id uint16) (*Alias, error) {
	for _, alias := range a {
		if alias.ID == id {
			return &alias, nil
		}
	}
	return nil, fmt.Errorf("alias id not found: %d", id)
}

type Alias struct {
	Name string `json:"name,omitempty"`
	alias
}

type alias struct {
	NameAddr uint64 `json:"-"`
	ID       uint16 `json:"id"`
	Unknown  uint16 `json:"unknown,omitempty"`
	Padding  uint32 `json:"-"`
}

func getNumInfoEntries(d *dyld.File) (int, error) {
	libsand, err := d.Image("libsandbox.1.dylib")
	if err != nil {
		return -1, fmt.Errorf("failed to get libsandbox.1.dylib image: %w", err)
	}

	m, err := libsand.GetMacho()
	if err != nil {
		return -1, fmt.Errorf("failed to get libsandbox.1.dylib macho: %w", err)
	}

	lookup_filter_info, err := m.FindSymbolAddress("_lookup_filter_info")
	if err != nil {
		return -1, fmt.Errorf("failed to find _lookup_filter_info symbol: %w", err)
	}

	lookup_filter_info_fn, err := m.GetFunctionForVMAddr(lookup_filter_info)
	if err != nil {
		return -1, fmt.Errorf("failed to get _lookup_filter_info function info: %v", err)
	}

	data, err := m.GetFunctionData(lookup_filter_info_fn)
	if err != nil {
		return -1, fmt.Errorf("failed to get _lookup_filter_info function data: %v", err)
	}

	instrs, err := disassemble.GetInstructions(lookup_filter_info_fn.StartAddr, data)
	if err != nil {
		return -1, fmt.Errorf("failed to disassemble _lookup_filter_info function: %w", err)
	}

	/****************
	 * EMULATE FUNC *
	 ****************/
	var filterInfoSize int
	startAddr := lookup_filter_info_fn.StartAddr
	for _, instr := range instrs {
		if instr.Operation == disassemble.ARM64_CMP {
			if len(instr.Operands) > 1 {
				filterInfoSize = int(instr.Operands[1].Immediate)
				break
			} else {
				log.Errorf("failed to emulate _lookup_filter_info function: code might have changed")
				log.Errorf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instr.Raw), instr)
			}
		}
		// fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instr.Raw), instr)
		startAddr += uint64(binary.Size(uint32(0)))
	}

	return filterInfoSize, nil
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

	NUM_INFO_ENTRIES, err := getNumInfoEntries(d)
	if err != nil {
		return nil, fmt.Errorf("failed to get NUM_INFO_ENTRIES: %v", err)
	}

	dat, err := d.ReadBytesForUUID(uuid, int64(filterInfoOff), uint64((NUM_INFO_ENTRIES)*binary.Size(filterInfo{})))
	if err != nil {
		return nil, fmt.Errorf("failed to read _filter_info data: %w", err)
	}

	r := bytes.NewReader(dat)

	for i := 0; i < NUM_INFO_ENTRIES; i++ {
		fi := FilterInfo{ID: i}
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
		sort.Slice(fi.Aliases[:], func(i, j int) bool {
			return fi.Aliases[i].ID < fi.Aliases[j].ID
		})
		finfos = append(finfos, fi)
	}

	return finfos, nil
}

type ModifierInfo struct {
	ID      int     `json:"id"`
	Name    string  `json:"name,omitempty"`
	Aliases []Alias `json:"aliases,omitempty"`
	modifierInfo
}

type modifierInfo struct {
	NameAddr    uint64 `json:"-"`
	Action      uint32 `json:"action"`
	Type        uint32 `json:"type"` // NOTE: sb_modifier_requires_argument in libsandbox.1.dylib
	ActionMask  uint32 `json:"action_mask"`
	ActionFlag  uint32 `json:"action_flag"`
	AliasesAddr uint64 `json:"-"`
}

func getModifierCount(d *dyld.File) (int, error) {
	libsand, err := d.Image("libsandbox.1.dylib")
	if err != nil {
		return -1, fmt.Errorf("failed to get libsandbox.1.dylib image: %w", err)
	}

	m, err := libsand.GetMacho()
	if err != nil {
		return -1, fmt.Errorf("failed to get libsandbox.1.dylib macho: %w", err)
	}

	sb_modifier_requires_argument, err := m.FindSymbolAddress("_sb_modifier_requires_argument")
	if err != nil {
		return -1, fmt.Errorf("failed to find _sb_modifier_requires_argument symbol: %w", err)
	}

	sb_modifier_requires_argument_fn, err := m.GetFunctionForVMAddr(sb_modifier_requires_argument)
	if err != nil {
		return -1, fmt.Errorf("failed to get _sb_modifier_requires_argument function info: %v", err)
	}

	data, err := m.GetFunctionData(sb_modifier_requires_argument_fn)
	if err != nil {
		return -1, fmt.Errorf("failed to get _sb_modifier_requires_argument function data: %v", err)
	}

	instrs, err := disassemble.GetInstructions(sb_modifier_requires_argument_fn.StartAddr, data)
	if err != nil {
		return -1, fmt.Errorf("failed to disassemble _sb_modifier_requires_argument function: %w", err)
	}

	/****************
	 * EMULATE FUNC *
	 ****************/
	var filterInfoSize int
	startAddr := sb_modifier_requires_argument_fn.StartAddr
	for _, instr := range instrs {
		if instr.Operation == disassemble.ARM64_CMP {
			if len(instr.Operands) > 1 {
				filterInfoSize = int(instr.Operands[1].Immediate)
				break
			} else {
				log.Errorf("failed to emulate _sb_modifier_requires_argument function: code might have changed")
				log.Errorf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instr.Raw), instr)
			}
		}
		// fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instr.Raw), instr)
		startAddr += uint64(binary.Size(uint32(0)))
	}

	return filterInfoSize, nil
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

	SB_MODIFIER_COUNT, err := getModifierCount(d)
	if err != nil {
		return nil, fmt.Errorf("failed to get SB_MODIFIER_COUNT: %v", err)
	}

	dat, err := d.ReadBytesForUUID(uuid, int64(modifierInfoOff), uint64(SB_MODIFIER_COUNT*binary.Size(modifierInfo{})))
	if err != nil {
		return nil, fmt.Errorf("failed to read _modifier_info data: %w", err)
	}

	r := bytes.NewReader(dat)

	for i := 0; i < SB_MODIFIER_COUNT; i++ {
		mi := ModifierInfo{ID: i}
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
		sort.Slice(mi.Aliases[:], func(i, j int) bool {
			return mi.Aliases[i].ID < mi.Aliases[j].ID
		})
		minfos = append(minfos, mi)
	}

	return minfos, nil
}

type OperationInfo struct {
	ID            int      `json:"id"`
	Name          string   `json:"name,omitempty"`
	Modifiers     []string `json:"modifiers,omitempty"`
	Categories    []string `json:"categories,omitempty"`
	MsgFilterOp   uint32   `json:"msg_filter_op,omitempty"`
	operationInfo `json:"operation_info,omitempty"`
}

type operationInfo struct {
	NodeType            uint32 `json:"node_type,omitempty"`
	JumpTargetOperation uint32 `json:"jump_target_operation,omitempty"`
	Action              uint64 `json:"action,omitempty"`
	CategoriesAddr      uint64 `json:"-"`
	ModifiersAddr       uint64 `json:"-"`
	UnknownAddr         uint64 `json:"-"`
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
			ID:            idx,
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
			uuid, off, err := d.GetOffset(d.SlideInfo.SlidePointer(oi.UnknownAddr))
			if err != nil {
				return nil, fmt.Errorf("failed to get _operation_info MsgFilterOp uint32 offset: %w", err)
			}
			dat, err = d.ReadBytesForUUID(uuid, int64(off), uint64(len(opNames)*binary.Size(uint32(0))))
			if err != nil {
				return nil, fmt.Errorf("failed to read _operation_info MsgFilterOp uint32 data: %w", err)
			}
			if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &oinfo.MsgFilterOp); err != nil {
				return nil, fmt.Errorf("failed to read _operation_info MsgFilterOp uint32 data: %w", err)
			}
		}
		opInfos = append(opInfos, oinfo)
	}

	return opInfos, nil
}
