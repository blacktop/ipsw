/*
Copyright © 2018-2023 blacktop

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
package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(DumpCmd)
	DumpCmd.Flags().Uint64P("size", "s", 0, "Size of data in bytes")
	DumpCmd.Flags().Uint64P("count", "c", 0, "The number of total items to display")
	DumpCmd.Flags().BoolP("addr", "a", false, "Output as addresses/uint64s")
	DumpCmd.Flags().BoolP("bytes", "b", false, "Output as bytes")
	DumpCmd.Flags().StringP("image", "i", "", "Dump from image (requires --section)")
	DumpCmd.Flags().StringP("section", "x", "", "Dump a specific segment/section (i.e. __TEXT.__text)")
	DumpCmd.Flags().StringP("output", "o", "", "Output to a file")

	viper.BindPFlag("dyld.dump.arch", DumpCmd.Flags().Lookup("arch"))
	viper.BindPFlag("dyld.dump.size", DumpCmd.Flags().Lookup("size"))
	viper.BindPFlag("dyld.dump.count", DumpCmd.Flags().Lookup("count"))
	viper.BindPFlag("dyld.dump.addr", DumpCmd.Flags().Lookup("addr"))
	viper.BindPFlag("dyld.dump.bytes", DumpCmd.Flags().Lookup("bytes"))
	viper.BindPFlag("dyld.dump.image", DumpCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.dump.section", DumpCmd.Flags().Lookup("section"))
	viper.BindPFlag("dyld.dump.output", DumpCmd.Flags().Lookup("output"))
	viper.BindPFlag("dyld.dump.color", DumpCmd.Flags().Lookup("color"))
}

// DumpCmd represents the dump command
var DumpCmd = &cobra.Command{
	Use:   "dump <DSC> <ADDR>",
	Short: "Dump data at given virtual address",
	Args:  cobra.MaximumNArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = !viper.GetBool("color")

		// flags
		size := viper.GetUint64("dyld.dump.size")
		count := viper.GetUint64("dyld.dump.count")
		asAddrs := viper.GetBool("dyld.dump.addr")
		asBytes := viper.GetBool("dyld.dump.bytes")
		fromImage := viper.GetString("dyld.dump.image")
		segmentSection := viper.GetString("dyld.dump.section")
		outFile := viper.GetString("dyld.dump.output")

		if size > 0 && count > 0 {
			return fmt.Errorf("you can only use --size OR --count")
		} else if asAddrs && asBytes {
			return fmt.Errorf("you can only use --addr OR --bytes")
		} else if asAddrs && size > 0 {
			return fmt.Errorf("you can only use --addr with --count")
		} else if asBytes && count > 0 {
			return fmt.Errorf("you can only use --bytes with --size")
		} else if fromImage != "" && segmentSection == "" {
			return fmt.Errorf("you must specify a --section when using --image")
		} else if fromImage == "" && segmentSection != "" {
			return fmt.Errorf("you must specify an --image when using --section")
		} else if len(segmentSection) > 0 && len(args) != 1 {
			return fmt.Errorf("you can only use <address> OR (--image AND --section)")
		}

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		var addr uint64
		if len(segmentSection) != 0 {
			parts := strings.Split(segmentSection, ".")
			if len(parts) != 2 {
				return fmt.Errorf("invalid section")
			}
			image, err := f.Image(fromImage)
			if err != nil {
				return err
			}
			m, err := image.GetPartialMacho()
			if err != nil {
				return err
			}
			if sec := m.Section(parts[0], parts[1]); sec != nil {
				addr = sec.Addr
				if size == 0 && count == 0 {
					size = sec.Size
				}
			} else {
				return fmt.Errorf("failed to find section %s", segmentSection)
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

		uuid, off, err := f.GetOffset(addr)
		if err != nil {
			log.Error(err.Error())
		} else {
			dat, err := f.ReadBytesForUUID(uuid, int64(off), size)
			if err != nil {
				return err
			}

			if asAddrs {
				addrs := make([]uint64, count)
				if err := binary.Read(bytes.NewReader(dat), f.ByteOrder, addrs); err != nil {
					return err
				}
				if len(outFile) > 0 {
					o, err := os.Create(outFile)
					if err != nil {
						return err
					}
					w := bufio.NewWriter(o)
					for _, a := range addrs {
						w.WriteString(fmt.Sprintf("%#x\n", f.SlideInfo.SlidePointer(a)))
					}
				} else {
					for _, a := range addrs {
						fmt.Printf("%#x\n", f.SlideInfo.SlidePointer(a))
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
					if image, err := f.GetImageContainingVMAddr(addr); err == nil {
						if m, err := image.GetMacho(); err == nil {
							defer m.Close()
							if s := m.FindSegmentForVMAddr(addr); s != nil {
								if s.Nsect > 0 {
									if c := m.FindSectionForVMAddr(addr); c != nil {
										log.WithFields(log.Fields{"dylib": image.Name, "section": fmt.Sprintf("%s.%s", c.Seg, c.Name)}).Info("Address location")
									}
								} else {
									log.WithFields(log.Fields{"dylib": image.Name, "segment": s.Name}).Info("Address location")
								}
							}
						}
					} else {
						if _, mapping, err := f.GetMappingForVMAddress(addr); err == nil {
							log.WithFields(log.Fields{
								"name": mapping.Name,
								"off":  fmt.Sprintf("%#x", mapping.FileOffset),
								"addr": fmt.Sprintf("%#x", mapping.Address),
								"size": fmt.Sprintf("%#x", mapping.Size),
							}).Info("Mapping")
						}
					}
					fmt.Println(utils.HexDump(dat, addr))
				}
			}
		}

		return nil
	},
}
