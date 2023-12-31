package devicetree

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"

	"github.com/blacktop/go-macho/types"
)

// CREDIT: https://github.com/Siguza/dt/blob/master/src/pmgr.c

type pmgr_reg struct {
	Addr uint64 `json:"addr,omitempty"`
	Size uint64 `json:"size,omitempty"`
}

type pmgr_map struct {
	Reg uint32 `json:"reg,omitempty"`
	Off uint32 `json:"off,omitempty"`
	Unk uint32 `json:"unk,omitempty"`
}

func parsePmgrMap(value []byte) any {
	var maps []pmgr_map
	r := bytes.NewReader(value)
	for {
		var m pmgr_map
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			if err == io.EOF {
				break
			}
			return parseValue(value)
		}
		maps = append(maps, m)
	}
	return maps
}

type pmgr_dev struct {
	FlagAndID1  uint32
	Alias       uint32
	IndexAndMap uint32
	Unk1        uint32
	Unk2        uint32
	Unk3        uint32
	UnkAndID2   uint32
	Unk4        uint32
	Name        [0x10]byte
}

func (p pmgr_dev) Flag() uint8 {
	return uint8(types.ExtractBits(uint64(p.FlagAndID1), 0, 8))
}
func (p pmgr_dev) ID1() uint8 {
	return uint8(types.ExtractBits(uint64(p.FlagAndID1), 24, 8))
}
func (p pmgr_dev) Index() uint8 {
	return uint8(types.ExtractBits(uint64(p.IndexAndMap), 16, 8))
}
func (p pmgr_dev) Map() uint8 {
	return uint8(types.ExtractBits(uint64(p.IndexAndMap), 24, 8))
}
func (p pmgr_dev) ID2() uint16 {
	return uint16(types.ExtractBits(uint64(p.UnkAndID2), 16, 16))
}

func (p *pmgr_dev) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Flag  uint8  `json:"flag,omitempty"`
		ID1   uint8  `json:"id1,omitempty"`
		Alias uint32 `json:"alias,omitempty"`
		Index uint8  `json:"index"`
		Map   uint8  `json:"map,omitempty"`
		Unk1  uint32 `json:"unk1,omitempty"`
		Unk2  uint32 `json:"unk2,omitempty"`
		Unk3  uint32 `json:"unk3,omitempty"`
		ID2   uint16 `json:"id2,omitempty"`
		Unk4  uint32 `json:"unk4,omitempty"`
		Name  string `json:"name,omitempty"`
	}{
		Flag:  p.Flag(),
		ID1:   p.ID1(),
		Alias: p.Alias,
		Index: p.Index(),
		Map:   p.Map(),
		Unk1:  p.Unk1,
		Unk2:  p.Unk2,
		Unk3:  p.Unk3,
		ID2:   p.ID2(),
		Unk4:  p.Unk4,
		Name:  string(bytes.TrimRight(p.Name[:], "\x00")),
	})
}

func parsePmgrDevices(value []byte) any {
	var devs []pmgr_dev
	r := bytes.NewReader(value)
	for {
		var d pmgr_dev
		err := binary.Read(r, binary.LittleEndian, &d)
		if err != nil {
			if err == io.EOF {
				break
			}
			return parseValue(value)
		}
		devs = append(devs, d)
	}
	return devs
}
