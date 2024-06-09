//go:build cgo

package sep

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/lzfse-cgo"
)

// NOTE: https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf
// NOTE: http://mista.nu/research/sep-paper.pdf
// NOTE: https://gist.github.com/xerub/0161aacd7258d31c6a27584f90fa2e8c
// NOTE: https://github.com/matteyeux/sepsplit/blob/master/sepsplit.c
// NOTE: https://gist.github.com/bazad/fe4e76a0a3b761d9fde7e74654ac14e4

const (
	legionStr                   = "Built by legion2"
	appListOffsetFromSEPOS32bit = 0xec8
	hdr32Offset                 = 0x408
	hdr64v1Offset               = 0x1004
	hdr64v2Offset               = 0x103c
)

type LegionHeader32 struct {
	Subversion uint32 //0x1
	Offset     uint32 //0x800
	Legion     [16]byte
}

type LegionHeader64v1 struct {
	Subversion uint32 //0x3
	Legion     [16]byte
	Offset     uint16
	Reserved   [2]uint8
}

type LegionHeader64v2 struct {
	Magic         uint64
	UUIDLabel     [4]byte
	UnknownOffset uint64
	_             uint32
	UUID          types.UUID
	_             [4]uint32
	Subversion    uint32 //0x4
	Legion        [16]byte
	Offset        uint32
}

type Header64 struct {
	KernelUUID       types.UUID
	Unknown0         uint64
	KernelTextOffset uint64
	KernelDataOffset uint64
	StartOfText      uint64
	StartOfData      uint64
	SepFwSize        uint64 // size of SEP firmware image
	Unknown1         uint64
	Unknown2         uint64
	Unknown3         uint64
	Unknown4         uint64
	_                uint64
	_                uint64
}

type RootHeader struct {
	TextOffset    uint64
	TextVaddr     uint64
	VMSize        uint64
	Entry         uint64
	IsZero3       uint64
	IsZero4       uint64
	Unknown5      uint64
	Unknown6      uint64
	_             uint64
	_             uint64
	_             uint64
	_             uint64
	Unknown7      uint64
	Unknown8      uint64
	Name          [16]byte // SEPOS
	UUID          types.UUID
	SourceVersion types.SrcVersion
	CRC32         uint32
	Unknown9      uint32
	Pad           [256]byte
	AppCount      uint32
	LibCount      uint32
	// AppInfoOffset uint64
}

func (h Header64) String() string {
	return fmt.Sprintf(
		"KernelUUID:       %s\n",
		h.KernelUUID,
	)
}

type MonitorBootArgs struct {
	//monitor related
	Version  uint32
	VirtBase uint32
	PhysBase uint32
	MemSize  uint32
	//kernel related
	KernBootArgsOffset uint32
	Entry              uint32
	UUID               types.UUID
}

type KernBootArgs struct {
	Revision         uint16
	Version          uint16
	VirtBase         uint32
	PhysBase         uint32
	MemSize          uint32
	TopOfKernelData  uint32
	ShmBase          uint64
	SmhSize          uint32
	Reserved         [3]uint32
	SeposCRC32       uint32
	SepromArgsOffset uint32
	SepromPhysOffset uint32
	Entropy          [2]uint64
	NumApps          uint32
	NumShlibs        uint32
	_                [232]byte
}

type Application struct {
	Offset     uint64
	VMAddress  uint32
	Size       uint32
	EntryPoint uint32
	PageSize   uint32
	VMBase     uint32
	Unknown1   uint32

	Unknown2      uint32
	Magic         uint64
	Name          [12]byte
	UUID          types.UUID
	SourceVersion types.SrcVersion
}

type application64 struct {
	TextOffset           uint64
	TextSize             uint64
	DataOffset           uint64
	DataSize             uint64
	VMBase               uint64
	Entry                uint64
	PageSize             uint64
	MemSize              uint64
	NonAntireplayMemSize uint64
	IsZero               uint64
	Magic                uint64
	Name                 [16]byte
	UUID                 types.UUID
	SourceVersion        types.SrcVersion
}

func (a application64) String() string {
	return fmt.Sprintf(
		"Name:          %s\n"+
			"UUID:          %s\n"+
			"Version:       %s\n"+
			"TextOff:       %#x -> %#x\n"+
			"DataOff:       %#x -> %#x\n"+
			"TextAddr:      %#x -> %#x\n"+
			"Entry:         %#x\n"+
			"PageSize:      %#x\n"+
			"MemSize:       %#x",
		strings.TrimSpace(string(a.Name[:])),
		a.UUID,
		a.SourceVersion,
		a.TextOffset, a.TextOffset+a.TextSize,
		a.DataOffset, a.DataOffset+a.DataSize,
		a.VMBase, a.VMBase+a.TextSize,
		a.Entry,
		a.PageSize,
		a.MemSize,
	)
}

type application64v2 struct {
	TextOffset           uint64
	TextSize             uint64
	DataOffset           uint64
	DataSize             uint64
	VMBase               uint64
	Entry                uint64
	PageSize             uint64
	MemSize              uint64
	NonAntireplayMemSize uint64
	HeapMemSize          uint64
	Unknown1             uint64
	Unknown2             uint64
	Unknown3             uint64
	Unknown4             uint64
	Magic                uint64
	Name                 [16]byte
	UUID                 types.UUID
	SourceVersion        types.SrcVersion
	_                    uint32
}

func (a application64v2) String() string {
	return fmt.Sprintf(
		"Name:          %s\n"+
			"UUID:          %s\n"+
			"Version:       %s\n"+
			"TextOff:       %#x -> %#x\n"+
			"DataOff:       %#x -> %#x\n"+
			"TextAddr:      %#x -> %#x\n"+
			"Entry:         %#x\n"+
			"PageSize:      %#x\n"+
			"MemSize:       %#x\n"+
			"Unknown1:      %#x\n"+
			"Unknown2:      %#x\n"+
			"Unknown3:      %#x\n"+
			"Unknown4:      %#x\n",
		strings.TrimSpace(string(a.Name[:])),
		a.UUID,
		a.SourceVersion,
		a.TextOffset, a.TextOffset+a.TextSize,
		a.DataOffset, a.DataOffset+a.DataSize,
		a.VMBase, a.VMBase+a.TextSize,
		a.Entry,
		a.PageSize,
		a.MemSize,
		a.Unknown1,
		a.Unknown2,
		a.Unknown3,
		a.Unknown4,
	)
}
func (a application64v2) GetOffset(addr uint64) (uint64, error) {
	if addr >= a.VMBase && addr < a.VMBase+a.MemSize {
		return addr - a.VMBase, nil
	}
	return 0, fmt.Errorf("invalid address %#x", addr)
}
func (a application64v2) GetVMAddress(off uint64) (uint64, error) {
	if off < a.MemSize {
		return off + a.VMBase, nil
	}
	return 0, fmt.Errorf("invalid offset %#x", off)
}

type Sep struct {
	Legion LegionHeader64v2
	Hdr    Header64
	SepOS  RootHeader
	Apps   []application64v2
	Libs   []application64v2

	data []byte
}

func (s Sep) String() string {
	var out string
	out += fmt.Sprintf(
		"Legion: %s uuid=%s\n"+
			"Kernel:    start=%#x end=%#x\n"+
			"%s:        uuid=%s\n",
		s.Legion.Legion[:], s.Legion.UUID,
		s.Hdr.KernelTextOffset, s.Hdr.KernelTextOffset+s.Hdr.KernelDataOffset,
		s.SepOS.Name[:], s.SepOS.UUID,
	)
	if len(s.Apps) > 0 {
		out += "\n\nAPPS"
		for _, app := range s.Apps {
			out += fmt.Sprintf("\n\n%s\n", app)
			if m, err := macho.NewFile(bytes.NewReader(s.data[app.TextOffset:])); err == nil {
				out += fmt.Sprintf("\n%s\n", m.FileTOC.String())
			}
		}
	}
	if len(s.Libs) > 0 {
		out += "\n\nLIBS"
		for _, lib := range s.Libs {
			out += fmt.Sprintf("\n\n%s\n", lib)
			if m, err := macho.NewFile(bytes.NewReader(s.data[lib.TextOffset:])); err == nil {
				out += fmt.Sprintf("\n%s\n", m.FileTOC.String())
			}
		}
	}
	return out
}

// Parse parses a SEP firmware image
func Parse(in string) (*Sep, error) {
	var s Sep
	var err error

	s.data, err = os.ReadFile(in)
	if err != nil {
		return nil, err
	}

	if string(s.data[8:16]) == "eGirBwRD" {
		out := make([]byte, len(s.data)*4)
		if n := lzfse.DecodeLZVNBuffer(s.data[0x10000:], out); n == 0 {
			return nil, fmt.Errorf("failed to decompress")
		} else {
			s.data = out[:n]
			os.WriteFile("decompressed", s.data, 0644)
		}
	}

	legion := bytes.Index(s.data, []byte(legionStr))
	if legion < 0 {
		return nil, fmt.Errorf("failed to find sep firmware magic: " + legionStr)
	}

	r := bytes.NewReader(s.data)

	switch legion {
	case hdr32Offset:
		r.Seek(0x400, io.SeekStart)
		var hdr LegionHeader32
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return nil, err
		}
		r.Seek(int64(hdr.Offset), io.SeekStart)
		var monitorArgs MonitorBootArgs
		if err := binary.Read(r, binary.LittleEndian, &monitorArgs); err != nil {
			return nil, err
		}
		r.Seek(int64(monitorArgs.KernBootArgsOffset), io.SeekStart)
		var kernArgs KernBootArgs
		if err := binary.Read(r, binary.LittleEndian, &kernArgs); err != nil {
			return nil, err
		}
		appList := make([]application64v2, kernArgs.NumApps)
		if err := binary.Read(r, binary.LittleEndian, &appList); err != nil {
			return nil, fmt.Errorf("failed to read app list: %w", err)
		}
		for _, app := range appList {
			log.Debugf("App:\n\n%s\n", app)
		}
		log.Infof("DUMPING: kernel, SEPOS and %d Apps", kernArgs.NumApps)

		// KERNEL
		// r.Seek(int64(0xe000), io.SeekStart)
		// m, err := macho.NewFile(r)
		// if err != nil {
		// 	return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
		// }
		// fname := fmt.Sprintf("%s_%s", "kernel", m.SourceVersion())
		// utils.Indent(log.WithFields(log.Fields{
		// 	"uuid":   monitorArgs.UUID,
		// 	"offset": fmt.Sprintf("%#x", monitorArgs.Entry),
		// }).Info, 2)("Dumping kernel")
		// if err := m.Export(fname, nil, 0, nil); err != nil {
		// 	return fmt.Errorf("failed to write %s to disk: %v", fname, err)
		// }

		// fmt.Println(m.FileTOC.LoadsString())

		// SEPOS
		// m, err = macho.NewFile(bytes.NewReader(dat[hdr.InitTextOffset:]))
		// if err != nil {
		// 	return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
		// }
		// fname = fmt.Sprintf("%s_%s", strings.TrimSpace(string(hdr.InitName[:])), m.SourceVersion())
		// utils.Indent(log.WithFields(log.Fields{
		// 	"uuid":   hdr.InitUUID,
		// 	"offset": fmt.Sprintf("%#x", hdr.InitTextOffset),
		// }).Info, 2)(fmt.Sprintf("Dumping %s", strings.TrimSpace(string(hdr.InitName[:]))))
		// if err := m.Export(fname, nil, 0, nil); err != nil {
		// 	return fmt.Errorf("failed to write %s to disk: %v", fname, err)
		// }
		// fmt.Println(m.FileTOC.LoadsString())

		// APPS
		for idx, app := range appList {
			if idx == 0 {
				app.TextOffset += 0x1000
				app.TextSize -= 0x1000
			}
			m, err := macho.NewFile(bytes.NewReader(append(s.data[app.TextOffset:app.TextOffset+app.TextSize], s.data[app.DataOffset:]...)))
			if err != nil {
				return nil, fmt.Errorf("failed to create MachO from embedded app file data: %w", err)
			}
			fmt.Println(m.FileTOC.String())

			// vma := types.VMAddrConverter{
			// 	Converter: func(addr uint64) uint64 {
			// 		return addr
			// 	},
			// 	VMAddr2Offet: func(address uint64) (uint64, error) {
			// 		return app.GetOffset(address)
			// 	},
			// 	Offet2VMAddr: func(offset uint64) (uint64, error) {
			// 		return app.GetVMAddress(offset)
			// 	},
			// }
			// partial, err := macho.NewFile(io.NewSectionReader(r, int64(app.TextOffset), int64(app.TextSize)), macho.FileConfig{
			// 	LoadFilter: []types.LoadCmd{
			// 		types.LC_SEGMENT,
			// 		types.LC_SEGMENT_64},
			// 	Offset:          int64(app.TextOffset),
			// 	SectionReader:   types.NewCustomSectionReader(r, &vma, 0, 1<<63-1),
			// 	VMAddrConverter: vma,
			// })
			// if err != nil {
			// 	return fmt.Errorf("failed to create MachO from embedded sep file data: %v", err)
			// }
			// fmt.Println(string(app.Name[:]))
			// fmt.Println(partial.FileTOC.LoadsString())
			// partial.Close()
			fname := fmt.Sprintf("%s_%s", strings.TrimSpace(string(app.Name[:])), m.SourceVersion())
			utils.Indent(log.WithFields(log.Fields{
				"uuid":   app.UUID,
				"offset": fmt.Sprintf("%#x-%#x", app.TextOffset, app.TextOffset+app.TextSize),
			}).Info, 2)(fmt.Sprintf("Dumping %s", strings.TrimSpace(string(app.Name[:]))))
			if err := m.Export(fname, nil, app.Entry, nil); err != nil {
				return nil, fmt.Errorf("failed to write %s to disk: %v", fname, err)
			}
			// fmt.Println(m.FileTOC)
			// for _, sym := range m.Symtab.Syms {
			// 	fmt.Println(sym)
			// }
			// m.Close()
		}
	case hdr64v1Offset:
		r.Seek(0x1000, io.SeekStart)
		var hdr LegionHeader64v1
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return nil, err
		}
		fmt.Println(hdr)
	case hdr64v2Offset:
		r.Seek(0x1000, io.SeekStart)
		if err := binary.Read(r, binary.LittleEndian, &s.Legion); err != nil {
			return nil, err
		}
		r.Seek(int64(s.Legion.Offset), io.SeekStart)
		if err := binary.Read(r, binary.LittleEndian, &s.Hdr); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &s.SepOS); err != nil {
			return nil, err
		}
		s.Apps = make([]application64v2, s.SepOS.AppCount)
		if err := binary.Read(r, binary.LittleEndian, &s.Apps); err != nil {
			return nil, fmt.Errorf("failed to read app list: %w", err)
		}
		s.Libs = make([]application64v2, s.SepOS.LibCount)
		if err := binary.Read(r, binary.LittleEndian, &s.Libs); err != nil {
			return nil, fmt.Errorf("failed to read app list: %w", err)
		}
	}

	return &s, nil
}
