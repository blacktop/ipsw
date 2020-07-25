/*
Copyright © 2020 blacktop

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
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(sepCmd)
}

type sepMachoItem struct {
	Magic    uint64
	Name     [12]byte
	Hash     [16]byte
	Unknown1 uint32
	Unknown2 uint32
	Unknown3 uint64
	Unknown4 uint32
	Unknown5 uint32
	Unknown6 uint32
	Unknown7 uint32
	Unknown8 uint64
	Unknown9 uint32
}

type machoInfo struct {
	Name  string
	Start int
	End   int
}

// sepCmd represents the sep command
var sepCmd = &cobra.Command{
	Use:   "sep",
	Short: "Dump MachOs",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		var names []string
		var machos []machoInfo

		macho32Magic := []byte{0xCE, 0xFA, 0xED, 0xFE}
		// macho64Magic := []byte{0xCF, 0xFA, 0xED, 0xFE}
		divider := []byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}

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

		start := bytes.Index(dat, divider)
		end := bytes.Index(dat, macho32Magic)
		if start < 0 || end < 0 {
			return fmt.Errorf("failed to find MachO names list range")
		}

		r := bytes.NewReader(dat[start:end])

		var sepItem sepMachoItem

		for {
			err := binary.Read(r, binary.LittleEndian, &sepItem)
			if err == io.EOF {
				break
			}
			if err != nil {
				return errors.Wrapf(err, "failed to read string")
			}
			if sepItem.Magic != 0xFFFFFFFF {
				break
			}

			names = append(names, strings.TrimSpace(string(sepItem.Name[:])))
		}

		index := 0
		machoDat := dat[end:]
		for x, d := bytes.Index(machoDat, macho32Magic), 0; x > -1; x, d = bytes.Index(machoDat, macho32Magic), d+x+1 {
			offset := end + x + d
			if offset&0xFFF == 0 {
				if len(machos) > 0 {
					machos[index-1].End = offset
				}
				machos = append(machos, machoInfo{
					Name:  names[index],
					Start: offset,
				})
				index++
			}
			machoDat = machoDat[x+1 : len(machoDat)]
		}

		for _, macho := range machos {
			var outDat []byte
			if macho.End == 0 {
				outDat = dat[macho.Start:]
			} else {
				outDat = dat[macho.Start:macho.End]
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", macho.Name))
			ioutil.WriteFile(macho.Name, outDat, 0644)
			if err != nil {
				return errors.Wrapf(err, "unabled to write file: %s", macho.Name)
			}
		}

		return nil
	},
}
