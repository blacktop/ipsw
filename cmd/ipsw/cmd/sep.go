/*
Copyright © 2021 blacktop

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
	"io/ioutil"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// NOTE: https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf
// NOTE: http://mista.nu/research/sep-paper.pdf
// NOTE: https://gist.github.com/xerub/0161aacd7258d31c6a27584f90fa2e8c
// NOTE: https://github.com/matteyeux/sepsplit/blob/master/sepsplit.c

const legionStr = "Built by legion2"
const appListOffsetFromSEPOS32bit = 0xec8

type sepHeader64 struct {
	KernelUUID         types.UUID
	Unknown0           uint64
	KernelBasePaddr    uint64
	KernelMaxPaddr     uint64
	AppImagesBasePaddr uint64
	AppImagesMaxPaddr  uint64
	PaddrMax           uint64 // size of SEP firmware image
	Unknown1           uint64
	Unknown2           uint64
	Unknown3           uint64
	InitBasePaddr      uint64
	InitVaddr          uint64
	InitSize           uint64
	InitEntry          uint64
	Unknown7           uint64
	Unknown8           uint64
	Unknown9           uint64
	InitName           [16]byte
	InitUUID           types.UUID
	Unknown10          uint64
	Unknown11          uint64
	NumApps            uint64
}

type application struct {
	Offset     uint64
	VMAddress  uint32
	Size       uint32
	EntryPoint uint32
	PageSize   uint32
	VMBase     uint32
	Unknown1   uint32

	Unknown2 uint32
	Magic    uint64
	Name     [12]byte
	UUID     types.UUID

	Version  uint32
	Unknown3 uint32
}

type application64 struct {
	PhysText uint64
	SizeText uint64
	PhysData uint64
	SizeData uint64
	Virt     uint64
	Entry    uint64
	Unknown1 uint64
	Unknown2 uint64
	Unknown3 uint64
	MinusOne uint32
	Unknown4 uint32
	Name     [16]byte
	UUID     types.UUID
	Unknown5 uint64
}

func init() {
	rootCmd.AddCommand(sepCmd)
}

// sepCmd represents the sep command
var sepCmd = &cobra.Command{
	Use:    "sep <SEP_BIN>",
	Short:  "🚧 [WIP] Dump MachOs 🚧",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		f, err := os.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "unabled to open file: %s", args[0])
		}
		defer f.Close()

		dat, err := ioutil.ReadAll(f)
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

			appList := make([]application64, hdr.NumApps)
			err = binary.Read(r, binary.LittleEndian, &appList)
			if err != nil {
				return errors.Wrapf(err, "failed to read app-list")
			}
			log.WithFields(log.Fields{
				"uuid":  hdr.KernelUUID,
				"start": fmt.Sprintf("0x%x", hdr.KernelBasePaddr),
				"size":  fmt.Sprintf("0x%x", hdr.KernelMaxPaddr),
			}).Info("kernel")
			if Verbose {
				m, err := macho.NewFile(bytes.NewReader(dat[hdr.KernelBasePaddr:]))
				if err != nil {
					return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
				}
				fmt.Println(m.FileTOC.LoadsString())
			}
			log.WithFields(log.Fields{
				"uuid":  hdr.InitUUID,
				"start": fmt.Sprintf("0x%x", hdr.InitBasePaddr),
				"size":  fmt.Sprintf("0x%x", hdr.PaddrMax),
			}).Info(strings.TrimSpace(string(hdr.InitName[:])))
			if Verbose {
				m, err := macho.NewFile(bytes.NewReader(dat[hdr.InitBasePaddr:]))
				if err != nil {
					return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
				}
				fmt.Println(m.FileTOC.LoadsString())
			}

			for _, app := range appList {
				log.WithFields(log.Fields{
					"uuid":  app.UUID,
					"start": fmt.Sprintf("0x%x", app.PhysText),
					"size":  fmt.Sprintf("0x%x", app.SizeText),
				}).Info(strings.TrimSpace(string(app.Name[:])))
				// fmt.Printf("name: %sUUID: %s, start: 0x%x(%d)\tsize: 0x%x(%d)\n", app.Name, app.UUID, app.PhysText, app.PhysText, app.SizeText, app.SizeText)
				// m, err := macho.NewFile(bytes.NewReader(dat[app.PhysText:app.PhysText+app.SizeText]), types.LC_SEGMENT_64, types.LC_UUID, types.LC_SOURCE_VERSION)
				if Verbose {
					m, err := macho.NewFile(bytes.NewReader(dat[app.PhysText:]))
					if err != nil {
						return errors.Wrapf(err, "failed to create MachO from embedded sep file data")
					}
					fmt.Println(m.FileTOC.LoadsString())
				}
			}

			// 	fname := fmt.Sprintf("sepdump_%s_%s", macho.Name, m.SourceVersion())
			// 	utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", fname))
			// 	ioutil.WriteFile(fname, outDat, 0644)
			// 	if err != nil {
			// 		return errors.Wrapf(err, "unabled to write file: %s", fname)
			// 	}
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
		// 	ioutil.WriteFile(fname, outDat, 0644)
		// 	if err != nil {
		// 		return errors.Wrapf(err, "unabled to write file: %s", fname)
		// 	}
		// }

		return nil
	},
}
