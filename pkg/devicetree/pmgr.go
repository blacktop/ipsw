package devicetree

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho/types"
)

// CREDIT: https://github.com/Siguza/dt/blob/master/src/pmgr.c

type pmgr_reg struct {
	Addr uint64 `json:"addr"`
	Size uint64 `json:"size"`
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
func (p pmgr_dev) String(padding int) string {
	return fmt.Sprintf(
		"%sname: \"%s\"\n"+
			"%sindex: %d\n"+
			"%sflag: %d\n"+
			"%sid1: %d\n"+
			"%sid2: %d\n"+
			"%salias: %d\n"+
			"%smap: %d\n"+
			"%sunk1: %d\n"+
			"%sunk2: %d\n"+
			"%sunk3: %d\n"+
			"%sunk4: %d",
		strings.Repeat(" ", padding), string(bytes.TrimRight(p.Name[:], "\x00")),
		strings.Repeat(" ", padding), p.Index(),
		strings.Repeat(" ", padding), p.Flag(),
		strings.Repeat(" ", padding), p.ID1(),
		strings.Repeat(" ", padding), p.ID2(),
		strings.Repeat(" ", padding), p.Alias,
		strings.Repeat(" ", padding), p.Map(),
		strings.Repeat(" ", padding), p.Unk1,
		strings.Repeat(" ", padding), p.Unk2,
		strings.Repeat(" ", padding), p.Unk3,
		strings.Repeat(" ", padding), p.Unk4,
	)
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

// pmgr_clock layout credit: PMGRClocks in https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/m1n1/adt.py
type pmgr_clock struct {
	PerfIdx   uint8  `json:"perf_idx"`
	PerfBlock uint8  `json:"perf_block"`
	Unk       uint8  `json:"unk"`
	ID        uint8  `json:"id"`
	Name      string `json:"name"`
}

func (c pmgr_clock) String() string {
	return fmt.Sprintf("id=%d name=%q perf_idx=%d perf_block=%d unk=%d", c.ID, c.Name, c.PerfIdx, c.PerfBlock, c.Unk)
}

// parsePmgrClocks decodes 24-byte records: perf_idx, perf_block, unk, id (u8 each), u32 zero, name[16].
func parsePmgrClocks(value []byte) any {
	const recordSize = 24
	if len(value) == 0 || len(value)%recordSize != 0 {
		return undecoded(value)
	}
	clocks := make([]pmgr_clock, 0, len(value)/recordSize)
	for off := 0; off < len(value); off += recordSize {
		rec := value[off : off+recordSize]
		name := bytes.TrimRight(rec[8:], "\x00")
		if !isZero(rec[4:8]) || !isPrintable(name) {
			return Data(value)
		}
		clocks = append(clocks, pmgr_clock{PerfIdx: rec[0], PerfBlock: rec[1], Unk: rec[2], ID: rec[3], Name: string(name)})
	}
	return clocks
}
