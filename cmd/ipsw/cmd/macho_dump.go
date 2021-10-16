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
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	machoCmd.AddCommand(machoDumpCmd)

	machoDumpCmd.Flags().StringP("arch", "a", viper.GetString("IPSW_ARCH"), "Which architecture to use for fat/universal MachO")
	machoDumpCmd.Flags().Uint64P("size", "s", 0, "Size of data in bytes")
	machoDumpCmd.Flags().Uint64P("count", "c", 0, "The number of total items to display")

	machoDumpCmd.Flags().BoolP("addr", "v", false, "Output as addresses/uint64s")
	machoDumpCmd.Flags().BoolP("hex", "x", false, "Output as hexdump")
	machoDumpCmd.Flags().StringP("output", "o", "", "Output to a file")
	machoDumpCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoDumpCmd represents the mdump command
var machoDumpCmd = &cobra.Command{
	Use:   "dump <macho> <address>",
	Short: "Dump MachO data at given virtual address",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		selectedArch, _ := cmd.Flags().GetString("arch")

		size, _ := cmd.Flags().GetUint64("size")
		count, _ := cmd.Flags().GetUint64("count")

		asAddrs, _ := cmd.Flags().GetBool("addr")
		asHex, _ := cmd.Flags().GetBool("hex")
		outFile, _ := cmd.Flags().GetString("output")

		if size > 0 && count > 0 {
			return fmt.Errorf("you can only use --size OR --count")
		}

		if asAddrs && asHex {
			return fmt.Errorf("you can only use --addr OR --hex")
		} else if !asAddrs && !asHex {
			asHex = true
			if size == 0 && count == 0 {
				log.Info("Setting --size=256")
				size = 256
			}
		} else if asAddrs && !asHex {
			if size == 0 && count == 0 {
				log.Info("Setting --count=20")
				count = 20
			}
		}

		addr, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
		}

		if asAddrs && size == 0 {
			size = count * uint64(binary.Size(uint64(0)))
		}

		machoPath := filepath.Clean(args[0])

		// first check for fat file
		fat, err := macho.OpenFat(machoPath)
		if err != nil && err != macho.ErrNotFat {
			return err
		}
		if err == macho.ErrNotFat {
			m, err = macho.Open(machoPath)
			if err != nil {
				return err
			}
		} else {
			var options []string
			var shortOptions []string
			for _, arch := range fat.Arches {
				options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
				shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
			}

			if len(selectedArch) > 0 {
				found := false
				for i, opt := range shortOptions {
					if strings.Contains(strings.ToLower(opt), strings.ToLower(selectedArch)) {
						m = fat.Arches[i].File
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("--arch '%s' not found in: %s", selectedArch, strings.Join(shortOptions, ", "))
				}
			} else {
				choice := 0
				prompt := &survey.Select{
					Message: "Detected a universal MachO file, please select an architecture to analyze:",
					Options: options,
				}
				survey.AskOne(prompt, &choice)
				m = fat.Arches[choice].File
			}
		}

		off, err := m.GetOffset(addr)
		if err != nil {
			log.Error(err.Error())
		} else {
			dat := make([]byte, size)
			if _, err := m.ReadAt(dat, int64(off)); err != nil {
				return err
			}

			if asHex {
				if len(outFile) > 0 {
					ioutil.WriteFile(outFile, dat, 0755)
					log.Infof("Wrote data to file %s", outFile)
				} else {
					fmt.Println(hex.Dump(dat))
				}
			} else if asAddrs {
				addrs := make([]uint64, count)
				if err := binary.Read(bytes.NewReader(dat), m.ByteOrder, addrs); err != nil {
					return err
				}
				if len(outFile) > 0 {
					o, err := os.Create(outFile)
					if err != nil {
						return err
					}
					w := bufio.NewWriter(o)
					for _, a := range addrs {
						w.WriteString(fmt.Sprintf("%#x\n", a))
					}
				} else {
					for _, a := range addrs {
						fmt.Printf("%#x\n", a)
					}
				}
			}
		}

		return nil
	},
}
