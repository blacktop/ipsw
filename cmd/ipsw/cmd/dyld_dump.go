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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDumpCmd)

	// dyldDumpCmd.Flags().Uint64P("offset", "f", 0, "File offset")
	// dyldDumpCmd.Flags().Uint64P("vaddr", "v", 0, "Virtual Address")
	dyldDumpCmd.Flags().Uint64P("size", "s", 0, "Size of data in bytes")
	dyldDumpCmd.Flags().Uint64P("count", "c", 0, "The number of total items to display")

	dyldDumpCmd.Flags().BoolP("addr", "a", false, "Output as addresses/uint64s")
	dyldDumpCmd.Flags().BoolP("hex", "x", false, "Output as hexdump")
	dyldDumpCmd.Flags().StringP("output", "o", "", "Output to a file")
	dyldDumpCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// dyldDumpCmd represents the dump command
var dyldDumpCmd = &cobra.Command{
	Use:   "dump <dyld_shared_cache> <address>",
	Short: "Dump dyld_shared_cache data at given virtual address",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

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

		uuid, off, err := f.GetOffset(addr)
		if err != nil {
			log.Error(err.Error())
		} else {
			dat, err := f.ReadBytesForUUID(uuid, int64(off), size)
			if err != nil {
				return err
			}

			if asHex {
				if len(outFile) > 0 {
					ioutil.WriteFile(outFile, dat, 0755)
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
						if mapping, err := f.GetMappingForVMAddress(addr); err == nil {
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
			} else if asAddrs {
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
			}
		}

		return nil
	},
}
