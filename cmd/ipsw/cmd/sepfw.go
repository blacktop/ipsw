/*
Copyright © 2018-2024 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// NOTE: https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf
// NOTE: http://mista.nu/research/sep-paper.pdf
// NOTE: https://gist.github.com/xerub/0161aacd7258d31c6a27584f90fa2e8c
// NOTE: https://github.com/matteyeux/sepsplit/blob/master/sepsplit.c
// NOTE: https://gist.github.com/bazad/fe4e76a0a3b761d9fde7e74654ac14e4

const legionStr = "Built by legion2"
const appListOffsetFromSEPOS32bit = 0xec8

type sepHeader64 struct {
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

func (h sepHeader64) String() string {
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

type application struct {
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
	TextOffset    uint64
	TextSize      uint64
	DataOffset    uint64
	DataSize      uint64
	VMBase        uint64
	Entry         uint64
	PageSize      uint64
	Unknown       uint64
	IsZero1       uint64
	IsZero2       uint64
	Magic         uint64
	Name          [16]byte
	UUID          types.UUID
	SourceVersion types.SrcVersion
}

func (a application64) String() string {
	return fmt.Sprintf(
		"Name:          %s\n"+
			"UUID:          %s\n"+
			"Version:       %s\n"+
			"Text:          %#x -> %#x\n"+
			"Data:          %#x -> %#x\n"+
			"VMBase:        %#x\n"+
			"Entry:         %#x\n"+
			"PageSize:      %#x\n"+
			"Unknown:       %#x",
		strings.TrimSpace(string(a.Name[:])),
		a.UUID,
		a.SourceVersion,
		a.TextOffset, a.TextOffset+a.TextSize,
		a.DataOffset, a.DataOffset+a.DataSize,
		a.VMBase,
		a.Entry,
		a.PageSize,
		a.Unknown,
	)
}

func init() {
	rootCmd.AddCommand(sepCmd)
}

// sepCmd represents the sep command
var sepCmd = &cobra.Command{
	Use:     "sepfw <SEP_FIRMWARE>",
	Aliases: []string{"sep"},
	Short:   "Dump MachOs",
	Args:    cobra.MinimumNArgs(1),
	// Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		f, err := os.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "unabled to open file: %s", args[0])
		}
		defer f.Close()

		dat, err := io.ReadAll(f)
		if err != nil {
			return errors.Wrapf(err, "unabled to read file: %s", args[0])
		}

		r := bytes.NewReader(dat)

		legion := bytes.Index(dat, []byte(legionStr))
		if legion < 0 {
			return fmt.Errorf("failed to find " + legionStr)
		}

		r.Seek(int64(legion+len(legionStr)), io.SeekStart)

		var hdrPtr uint64
		err = binary.Read(r, binary.LittleEndian, &hdrPtr)
		if err != nil {
			return errors.Wrapf(err, "failed to read sep 64bit header")
		}

		// 64-bit SEP
		if hdrPtr > 0 {

			r.Seek(int64(hdrPtr), io.SeekStart)

			var hdr sepHeader64
			err = binary.Read(r, binary.LittleEndian, &hdr)
			if err != nil {
				return errors.Wrapf(err, "failed to read sep-firmware 64bit header")
			}

			log.Debugf("Header:\n\n%s\n", hdr)

			appList := make([]application64, hdr.NumApps)
			err = binary.Read(r, binary.LittleEndian, &appList)
			if err != nil {
				return errors.Wrapf(err, "failed to read app-list")
			}

			for _, app := range appList {
				log.Debugf("App:\n\n%s\n", app)
			}

			log.Infof("DUMPING: kernel, SEPOS and %d Apps", hdr.NumApps)

			// KERNEL
			m, err := macho.NewFile(bytes.NewReader(dat[hdr.KernelTextOffset:]))
			if err != nil {
				return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
			}
			fname := fmt.Sprintf("%s_%s", "kernel", m.SourceVersion())
			utils.Indent(log.WithFields(log.Fields{
				"uuid":   hdr.KernelUUID,
				"offset": fmt.Sprintf("%#x", hdr.KernelTextOffset),
			}).Info, 2)("Dumping kernel")
			if err := m.Export(fname, nil, 0, nil); err != nil {
				return fmt.Errorf("failed to write %s to disk: %v", fname, err)
			}
			if Verbose {
				fmt.Println(m.FileTOC.String())
			}

			// SEPOS
			m, err = macho.NewFile(bytes.NewReader(dat[hdr.InitTextOffset:]))
			if err != nil {
				return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
			}
			fname = fmt.Sprintf("%s_%s", strings.TrimSpace(string(hdr.InitName[:])), m.SourceVersion())
			utils.Indent(log.WithFields(log.Fields{
				"uuid":   hdr.InitUUID,
				"offset": fmt.Sprintf("%#x", hdr.InitTextOffset),
			}).Info, 2)(fmt.Sprintf("Dumping %s", strings.TrimSpace(string(hdr.InitName[:]))))
			if err := m.Export(fname, nil, 0, nil); err != nil {
				return fmt.Errorf("failed to write %s to disk: %v", fname, err)
			}
			if Verbose {
				fmt.Println(m.FileTOC.String())
			}

			// APPS
			for _, app := range appList {
				m, err := macho.NewFile(bytes.NewReader(dat[app.TextOffset:]))
				if err != nil {
					return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
				}

				fname := fmt.Sprintf("%s_%s", strings.TrimSpace(string(app.Name[:])), m.SourceVersion())
				utils.Indent(log.WithFields(log.Fields{
					"uuid":   app.UUID,
					"offset": fmt.Sprintf("%#x-%#x", app.TextOffset, app.TextOffset+app.TextSize),
				}).Info, 2)(fmt.Sprintf("Dumping %s", strings.TrimSpace(string(app.Name[:]))))
				if err := m.Export(fname, nil, 0, nil); err != nil {
					return fmt.Errorf("failed to write %s to disk: %v", fname, err)
				}
				if Verbose {
					fmt.Println(m.FileTOC.String())
				}
			}

			return nil
		}

		log.Error("32-bit SEP Firmware not yet supported")

		// 32-bit SEP

		// var appList []application
		// for {
		// 	var app application
		// 	err := binary.Read(r, binary.LittleEndian, &app)
		// 	if err == io.EOF {
		// 		break
		// 	}
		// 	if err != nil {
		// 		return errors.Wrapf(err, "failed to read string")
		// 	}
		// 	if app.Magic != 0xFFFFFFFF {
		// 		break
		// 	}

		// 	names = append(names, strings.TrimSpace(string(app.Name[:])))
		// 	appList = append(appList, app)
		// }

		// index := 0
		// machoDat := dat[end:]
		// for x, d := bytes.Index(machoDat, macho32Magic), 0; x > -1; x, d = bytes.Index(machoDat, macho32Magic), d+x+1 {
		// 	offset := end + x + d
		// 	if offset&0xFFF == 0 {
		// 		if len(machos) > 0 {
		// 			machos[index-1].End = offset
		// 		}
		// 		machos = append(machos, machoInfo{
		// 			Name:  names[index],
		// 			Start: offset,
		// 		})
		// 		index++
		// 	}
		// 	machoDat = machoDat[x+1 : len(machoDat)]
		// }

		// fmt.Println()
		// for _, macho := range machos {
		// 	fmt.Printf("name: %s\tstart: 0x%x(%d)\tend: 0x%x(%d)\tsize: 0x%x(%d)\n", macho.Name, macho.Start, macho.Start, macho.End, macho.End, macho.End-macho.Start, macho.End-macho.Start)
		// }

		// for _, macho := range machos {
		// 	var outDat []byte
		// 	if macho.End == 0 {
		// 		outDat = dat[macho.Start:]
		// 	} else {
		// 		outDat = dat[macho.Start:macho.End]
		// 	}

		// 	m, err := mo.NewFile(bytes.NewReader(outDat))
		// 	if err != nil {
		// 		return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
		// 	}

		// 	fname := fmt.Sprintf("sepdump_%s_%s", macho.Name, m.SourceVersion())
		// 	utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", fname))
		// 	os.WriteFile(fname, outDat, 0660)
		// 	if err != nil {
		// 		return errors.Wrapf(err, "unabled to write file: %s", fname)
		// 	}
		// }

		return nil
	},
}
