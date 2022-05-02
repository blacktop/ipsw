package sandbox

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/blacktop/ipsw/pkg/dyld"
)

//go:embed data/libsandbox_12.3.0.gz
var libsandboxData []byte

type LibSandbox struct {
	Operations []OperationInfo `json:"operations,omitempty"`
	Filters    []FilterInfo    `json:"filters,omitempty"`
	Modifiers  []ModifierInfo  `json:"modifiers,omitempty"`
}

func GetLibSandBoxDB() (*LibSandbox, error) {
	var lb *LibSandbox

	zr, err := gzip.NewReader(bytes.NewReader(libsandboxData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&lb); err != nil {
		return nil, fmt.Errorf("failed to decode libsandbox data: %w", err)
	}

	return lb, nil
}

func (db *LibSandbox) GetFilter(id int) (*FilterInfo, error) {
	if id < 0 || id >= len(db.Filters) {
		return nil, fmt.Errorf("invalid filter id: %d", id)
	}
	return &db.Filters[id], nil
}

/**********************
 * LibSandbox Builder *
 **********************/

type FilterInfo struct {
	ID         int     `json:"id"`
	Name       string  `json:"name,omitempty"`
	Category   string  `json:"category,omitempty"`
	Aliases    Aliases `json:"aliases,omitempty"`
	filterInfo `json:"-"`
}

type filterInfo struct {
	NameAddr     uint64
	CategoryAddr uint64
	Unknown1     uint16
	Unknown2     uint16
	Unknown3     uint32
	AliasesAddr  uint64
}

type Aliases []Alias

func (a Aliases) Get(id int) (*Alias, error) {
	if id < 0 || id >= len(a) {
		return nil, fmt.Errorf("invalid alias id: %d", id)
	}
	for _, alias := range a {
		if int(alias.ID) == id {
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
	NameAddr uint64 `json:"-,omitempty"`
	ID       uint16 `json:"id"`
	Unknown1 uint16 `json:"-,omitempty"`
	Unknown2 uint16 `json:"-,omitempty"`
	Unknown3 uint16 `json:"-,omitempty"`
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
		finfos = append(finfos, fi)
	}

	return finfos, nil
}

type ModifierInfo struct {
	ID           int     `json:"id"`
	Name         string  `json:"name,omitempty"`
	Aliases      []Alias `json:"aliases,omitempty"`
	modifierInfo `json:"-"`
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
		minfos = append(minfos, mi)
	}

	return minfos, nil
}

type OperationInfo struct {
	ID            int      `json:"id"`
	Name          string   `json:"name,omitempty"`
	Modifiers     []string `json:"modifiers,omitempty"`
	Categories    []string `json:"categories,omitempty"`
	operationInfo `json:"-"`
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
			// TODO: read unknown struct
		}
		opInfos = append(opInfos, oinfo)
	}

	return opInfos, nil
}
