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
	legionStrLen                = 16
	appListOffsetFromSEPOS32bit = 0xec8
	hdr32Offset                 = 0x408
	hdr64v1Offset               = 0x1004
	hdr64v2Offset               = 0x103c
)

type Header32 struct {
	Subversion uint32 //0x1
	Offset     uint32 //0x800
	Legion     [16]byte
}

type Header64v1 struct {
	Subversion uint32 //0x3
	Legion     [16]byte
	Offset     uint16
	Reserved   [2]uint8
}

type Header64v2 struct {
	Unknown    uint64
	TextUUID   types.UUID
	Unknown1   uint64
	Unknown2   uint32
	UUID       types.UUID
	Unknown3   uint64
	Unknown4   uint64
	Subversion uint32 //0x4
	Legion     [16]byte
	Offset     uint16
	Reserved   [2]uint8
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
	IsZero1          uint64
	IsZero2          uint64
	InitTextOffset   uint64
	InitTextVaddr    uint64
	InitVMSize       uint64
	InitEntry        uint64
	IsZero3          uint64
	IsZero4          uint64
	Unknown5         uint64
	Unknown6         uint64
	IsZero5          uint64
	IsZero6          uint64
	InitName         [16]byte
	InitUUID         types.UUID
	SourceVersion    types.SrcVersion
	Unknown7         uint64
	NumApps          uint64
}

func (h Header64) String() string {
	return fmt.Sprintf(
		"KernelUUID       : %s\n"+
			"Unknown0         : %#x\n"+
			"KernelTextOffset : %#x\n"+
			"KernelDataOffset   : %#x\n"+
			"StartOfText      : %#x\n"+
			"StartOfData      : %#x\n"+
			"SepFwSize        : %#x\n"+
			"Unknown1         : %#x\n"+
			"Unknown2         : %#x\n"+
			"Unknown3         : %#x\n"+
			"Unknown4         : %#x\n"+
			"IsZero1          : %#x\n"+
			"IsZero2          : %#x\n"+
			"InitTextOffset   : %#x\n"+
			"InitTextVaddr    : %#x\n"+
			"InitVMSize       : %#x\n"+
			"InitEntry        : %#x\n"+
			"IsZero3          : %#x\n"+
			"IsZero4          : %#x\n"+
			"Unknown5         : %#x\n"+
			"Unknown6         : %#x\n"+
			"IsZero5          : %#x\n"+
			"IsZero6          : %#x\n"+
			"InitName         : %s\n"+
			"InitUUID         : %s\n"+
			"SourceVersion    : %s\n"+
			"Unknown7         : %#x\n"+
			"NumApps          : %d",
		h.KernelUUID,
		h.Unknown0,
		h.KernelTextOffset,
		h.KernelDataOffset,
		h.StartOfText,
		h.StartOfData,
		h.SepFwSize,
		h.Unknown1,
		h.Unknown2,
		h.Unknown3,
		h.Unknown4,
		h.IsZero1,
		h.IsZero2,
		h.InitTextOffset,
		h.InitTextVaddr,
		h.InitVMSize,
		h.InitEntry,
		h.IsZero3,
		h.IsZero4,
		h.Unknown5,
		h.Unknown6,
		h.IsZero5,
		h.IsZero6,
		strings.TrimSpace(string(h.InitName[:])),
		h.InitUUID,
		h.SourceVersion,
		h.Unknown7,
		h.NumApps,
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
	// Unknown1             uint64
	// Unknown2             uint64
	// Unknown3             uint64
	// Unknown4             uint64
	Magic         uint64
	Name          [16]byte
	UUID          types.UUID
	SourceVersion types.SrcVersion
	_             uint32
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

// TODO: finish this
func Parse(data []byte) error {

	if string(data[8:16]) == "eGirBwRD" {
		out := make([]byte, len(data)*4)
		if n := lzfse.DecodeLZVNBuffer(data[0x10000:], out); n == 0 {
			return fmt.Errorf("failed to decompress")
		} else {
			data = out[:n]
			os.WriteFile("decompressed", data, 0644)
		}
	}

	legion := bytes.Index(data, []byte(legionStr))
	if legion < 0 {
		return fmt.Errorf("failed to find " + legionStr)
	}

	r := bytes.NewReader(data)

	switch legion {
	case hdr32Offset:
		r.Seek(0x400, io.SeekStart)
		var hdr Header32
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return err
		}
		r.Seek(int64(hdr.Offset), io.SeekStart)
		var monitorArgs MonitorBootArgs
		if err := binary.Read(r, binary.LittleEndian, &monitorArgs); err != nil {
			return err
		}
		r.Seek(int64(monitorArgs.KernBootArgsOffset), io.SeekStart)
		var kernArgs KernBootArgs
		if err := binary.Read(r, binary.LittleEndian, &kernArgs); err != nil {
			return err
		}
		appList := make([]application64v2, kernArgs.NumApps)
		if err := binary.Read(r, binary.LittleEndian, &appList); err != nil {
			return fmt.Errorf("failed to read app list: %w", err)
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
			m, err := macho.NewFile(bytes.NewReader(append(data[app.TextOffset:app.TextOffset+app.TextSize], data[app.DataOffset:]...)))
			if err != nil {
				return fmt.Errorf("failed to create MachO from embedded app file data: %w", err)
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
				return fmt.Errorf("failed to write %s to disk: %v", fname, err)
			}
			// fmt.Println(m.FileTOC)
			// for _, sym := range m.Symtab.Syms {
			// 	fmt.Println(sym)
			// }
			// m.Close()
		}
	case hdr64v1Offset:
		r.Seek(0x1000, io.SeekStart)
		var hdr Header64v1
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return err
		}
		fmt.Println(hdr)
	case hdr64v2Offset:
		r.Seek(0x1000, io.SeekStart)
		var hdr Header64
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return err
		}
		fmt.Println(hdr)
	}

	return nil
}
