/*
Copyright © 2018-2025 blacktop

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
package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoDumpCmd)

	machoDumpCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	machoDumpCmd.Flags().Uint64P("size", "s", 0, "Size of data in bytes")
	machoDumpCmd.Flags().Uint64P("count", "c", 0, "The number of total items to display")
	machoDumpCmd.Flags().BoolP("addr", "v", false, "Output as addresses/uint64s")
	machoDumpCmd.Flags().BoolP("bytes", "b", false, "Output as bytes")
	machoDumpCmd.Flags().StringP("output", "o", "", "Output to a file")
	machoDumpCmd.Flags().StringP("entry", "e", "", "Dump from fileset entry (requires --section)")
	machoDumpCmd.Flags().StringP("segment", "g", "", "Dump a specific segment (i.e. __TEXT)")
	machoDumpCmd.Flags().StringP("section", "x", "", "Dump a specific segment/section (i.e. __TEXT.__text)")

	viper.BindPFlag("macho.dump.arch", machoDumpCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.dump.size", machoDumpCmd.Flags().Lookup("size"))
	viper.BindPFlag("macho.dump.count", machoDumpCmd.Flags().Lookup("count"))
	viper.BindPFlag("macho.dump.addr", machoDumpCmd.Flags().Lookup("addr"))
	viper.BindPFlag("macho.dump.bytes", machoDumpCmd.Flags().Lookup("bytes"))
	viper.BindPFlag("macho.dump.output", machoDumpCmd.Flags().Lookup("output"))
	viper.BindPFlag("macho.dump.entry", machoDumpCmd.Flags().Lookup("entry"))
	viper.BindPFlag("macho.dump.segment", machoDumpCmd.Flags().Lookup("segment"))
	viper.BindPFlag("macho.dump.section", machoDumpCmd.Flags().Lookup("section"))

	machoDumpCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoDumpCmd represents the mdump command
var machoDumpCmd = &cobra.Command{
	Use:   "dump <macho> <address>",
	Short: "Dump MachO data at given virtual address",
	Args:  cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		selectedArch := viper.GetString("macho.dump.arch")
		size := viper.GetUint64("macho.dump.size")
		count := viper.GetUint64("macho.dump.count")
		asAddrs := viper.GetBool("macho.dump.addr")
		asBytes := viper.GetBool("macho.dump.bytes")
		outFile := viper.GetString("macho.dump.output")
		filesetEntry := viper.GetString("macho.dump.entry")
		segment := viper.GetString("macho.dump.segment")
		section := viper.GetString("macho.dump.section")
		// validate flags
		if size > 0 && count > 0 {
			return fmt.Errorf("you can only use --size OR --count")
		} else if asAddrs && asBytes {
			return fmt.Errorf("you can only use --addr OR --bytes")
		} else if asAddrs && size > 0 {
			return fmt.Errorf("you can only use --addr with --count")
		} else if asBytes && count > 0 {
			return fmt.Errorf("you can only use --bytes with --size")
		} else if viper.IsSet("macho.dump.section") && len(args) != 1 {
			return fmt.Errorf("you can only use <address> OR --section")
		} else if len(filesetEntry) > 0 && !viper.IsSet("macho.dump.section") {
			return fmt.Errorf("you must specify a --section when using --entry")
		} else if viper.IsSet("macho.dump.segment") && viper.IsSet("macho.dump.section") {
			return fmt.Errorf("you can only use --segment OR --section")
		}

		machoPath := filepath.Clean(args[0])

		var m *macho.File

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

		if len(filesetEntry) > 0 && m.FileTOC.FileHeader.Type != types.MH_FILESET {
			return fmt.Errorf("macho is not a MH_FILESET")
		}

		var addr uint64
		if viper.IsSet("macho.dump.segment") || viper.IsSet("macho.dump.section") {
			switch {
			case viper.IsSet("macho.dump.segment"):
				if seg := m.Segment(segment); seg != nil {
					addr = seg.Addr
					if size == 0 && count == 0 {
						size = seg.Filesz
					}
				} else {
					if m.FileTOC.FileHeader.Type == types.MH_FILESET {
						m, err = m.GetFileSetFileByName(filesetEntry)
						if err != nil {
							return fmt.Errorf("failed to get fileset entry '%s': %v", filesetEntry, err)
						}
						if seg := m.Segment(segment); seg != nil {
							addr = seg.Addr
							if size == 0 && count == 0 {
								size = seg.Filesz
							}
						} else {
							return fmt.Errorf("failed to find segment '%s' in '%s'", segment, filesetEntry)
						}
					} else {
						return fmt.Errorf("failed to find segment '%s'", segment)
					}
				}
			case viper.IsSet("macho.dump.section"):
				segName, secName, ok := strings.Cut(section, ".")
				if !ok {
					return fmt.Errorf("invalid __SEGMENT.__section input format '%s'", section)
				}
				if sec := m.Section(segName, secName); sec != nil {
					addr = sec.Addr
					if size == 0 && count == 0 {
						size = sec.Size
					}
				} else {
					if m.FileTOC.FileHeader.Type == types.MH_FILESET {
						m, err = m.GetFileSetFileByName(filesetEntry)
						if err != nil {
							return fmt.Errorf("failed to get fileset entry '%s': %v", filesetEntry, err)
						}
						if sec := m.Section(segName, secName); sec != nil {
							addr = sec.Addr
							if size == 0 && count == 0 {
								size = sec.Size
							}
						} else {
							return fmt.Errorf("failed to find section '%s' in '%s'", section, filesetEntry)
						}
					} else {
						return fmt.Errorf("failed to find section '%s'", section)
					}
				}
			}
		} else {
			addr, err = utils.ConvertStrToInt(args[1])
			if err != nil {
				return err
			}
		}

		if asAddrs {
			if count == 0 {
				log.Info("Setting --count=20")
				count = 20
			}
			size = count * uint64(binary.Size(uint64(0)))
		} else {
			if size == 0 {
				log.Info("Setting --size=256")
				size = 256
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

			if asAddrs {
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
						w.WriteString(fmt.Sprintf("%#x\n", m.SlidePointer(a)))
					}
				} else {
					for _, a := range addrs {
						fmt.Printf("%#x\n", m.SlidePointer(a))
					}
				}
			} else if asBytes {
				if _, err := os.Stdout.Write(dat); err != nil {
					return fmt.Errorf("failed to write bytes to stdout: %s", err)
				}
			} else {
				if len(outFile) > 0 {
					os.WriteFile(outFile, dat, 0660)
					log.Infof("Wrote data to file %s", outFile)
				} else {
					if viper.IsSet("macho.dump.segment") || viper.IsSet("macho.dump.section") {
						switch {
						case viper.IsSet("macho.dump.segment"):
							if s := m.FindSegmentForVMAddr(addr); s != nil {
								log.WithFields(log.Fields{"segment": s.Name, "size": len(dat)}).Info("Address location")
							}
						case viper.IsSet("macho.dump.section"):
							if s := m.FindSegmentForVMAddr(addr); s != nil {
								if s.Nsect > 0 {
									if c := m.FindSectionForVMAddr(addr); c != nil {
										log.WithFields(log.Fields{"section": fmt.Sprintf("%s.%s", c.Seg, c.Name), "size": len(dat)}).Info("Address location")
									}
								} else {
									log.WithFields(log.Fields{"segment": s.Name, "size": len(dat)}).Info("Address location")
								}
							}
						}
					}
					fmt.Println(utils.HexDump(dat, addr))
				}
			}
		}

		return nil
	},
}
