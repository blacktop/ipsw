package ridiff

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/pkg/errors"
)

const (
	RIDIFF10Magic = 0x3031464649444952
)

type ridiff10 struct {
	Magic          uint64
	Variants       uint16
	Flags          uint64
	ControlCount   uint64
	ExcessSpace    uint32
	MetaDataOffset uint64
	ControlsOffset uint64
}

type RIDIFF10 struct {
	ridiff10
	PatchDataOffset []uint64 // len(Variants)
	PatchSize       uint64
	MetaData        []byte
	Controls        []Control
	PatchData       [][]byte
}

type Control struct {
	Offset uint64
	Size   uint64
}

type metadata struct {
	Digest       [32]byte
	TotalBytes   uint64
	UnknownCount uint64
	ExtentCount  uint64
	ForkCount    uint64
}

type MetaData struct {
	metadata
	Extents []Extent
	Forks   []Fork
}

type Extent struct {
	Offset uint64
	Size   uint64
}

type Fork struct {
	Size        uint64
	Compressed  uint64
	Variant     uint64
	ExtentIndex uint64 // I think
	ExtentCount uint64
	Algorithm   uint8
	ForkHeader  uint64 // all zeros
	// ForkChunks []ForkChunk
	// ForkFooter uint32
}

type ForkChunk struct {
	Size  uint32
	Total uint64
}

func ParseRawImageDiff10(r *bytes.Reader) (*RIDIFF10, error) {
	var rid RIDIFF10
	if err := binary.Read(r, binary.LittleEndian, &rid.ridiff10); err != nil {
		return nil, err
	}

	if rid.Magic != RIDIFF10Magic {
		return nil, errors.New("invalid magic")
	}

	rid.PatchDataOffset = make([]uint64, rid.Variants)
	if err := binary.Read(r, binary.LittleEndian, &rid.PatchDataOffset); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.LittleEndian, &rid.PatchSize); err != nil {
		return nil, err
	}

	r.Seek(int64(rid.MetaDataOffset), io.SeekStart)
	rid.MetaData = make([]byte, rid.ControlsOffset-rid.MetaDataOffset)
	if _, err := io.ReadFull(r, rid.MetaData); err != nil {
		return nil, err
	}

	r.Seek(int64(rid.ControlsOffset), io.SeekStart)
	ctrldata := make([]byte, rid.PatchDataOffset[0]-rid.ControlsOffset)
	if _, err := io.ReadFull(r, ctrldata); err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if err := pbzx.Extract(context.Background(), bytes.NewReader(rid.MetaData), &b, runtime.NumCPU()); err != nil {
		return nil, err
	}
	rid.MetaData = b.Bytes()

	os.WriteFile("metadata.RIDIFF10", rid.MetaData, 0644)

	mr := bytes.NewReader(rid.MetaData)

	var md MetaData
	if err := binary.Read(mr, binary.LittleEndian, &md.metadata); err != nil {
		return nil, err
	}
	md.Extents = make([]Extent, md.ExtentCount)
	if err := binary.Read(mr, binary.LittleEndian, &md.Extents); err != nil {
		return nil, err
	}
	// FIXME: figure out how many chunks there are in a Fork
	// md.Forks = make([]Fork, md.ForkCount)
	// if err := binary.Read(mr, binary.LittleEndian, &md.Forks); err != nil {
	// 	return nil, err
	// }

	b = bytes.Buffer{}
	if err := pbzx.Extract(context.Background(), bytes.NewReader(ctrldata), &b, runtime.NumCPU()); err != nil {
		return nil, err
	}
	ctrldata = b.Bytes()
	rid.Controls = make([]Control, rid.ControlCount)
	if err := binary.Read(bytes.NewReader(ctrldata), binary.LittleEndian, &rid.Controls); err != nil {
		return nil, err
	}

	for idx, offset := range rid.PatchDataOffset {
		r.Seek(int64(offset), io.SeekStart)
		rid.PatchData = append(rid.PatchData, make([]byte, rid.PatchSize-offset))
		if _, err := io.ReadFull(r, rid.PatchData[idx]); err != nil {
			return nil, err
		}
		b = bytes.Buffer{}
		if err := pbzx.Extract(context.Background(), bytes.NewReader(rid.PatchData[idx]), &b, runtime.NumCPU()); err != nil {
			return nil, err
		}
		rid.PatchData[idx] = b.Bytes()
		os.WriteFile(fmt.Sprintf("patchdata_%d.RIDIFF10", idx), rid.PatchData[idx], 0644)
	}

	return &rid, nil
}
