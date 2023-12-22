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
package dyld

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(AddrToFuncCmd)
	AddrToFuncCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply")
	AddrToFuncCmd.Flags().StringP("in", "i", "", "Path to file containing list of addresses to lookup")
	AddrToFuncCmd.Flags().StringP("out", "o", "", "Path to output JSON file")
	AddrToFuncCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	AddrToFuncCmd.Flags().StringP("cache", "c", "", "Path to .a2s addr to sym cache file (speeds up analysis)")

	viper.BindPFlag("dyld.a2f.slide", AddrToFuncCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.a2f.in", AddrToFuncCmd.Flags().Lookup("in"))
	viper.BindPFlag("dyld.a2f.out", AddrToFuncCmd.Flags().Lookup("out"))
	viper.BindPFlag("dyld.a2f.json", AddrToFuncCmd.Flags().Lookup("json"))
	viper.BindPFlag("dyld.a2f.cache", AddrToFuncCmd.Flags().Lookup("cache"))
}

// AddrToFuncCmd represents the a2f command
var AddrToFuncCmd = &cobra.Command{
	Use:   "a2f <DSC> <ADDR>",
	Short: "Lookup function containing unslid address",
	Args:  cobra.ExactArgs(2),
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
		color.NoColor = viper.GetBool("no-color")

		slide := viper.GetUint64("dyld.a2f.slide")
		ptrFile := viper.GetString("dyld.a2f.in")
		jsonFile := viper.GetString("dyld.a2f.out")
		asJSON := viper.GetBool("dyld.a2f.json")
		cacheFile := viper.GetString("dyld.a2f.cache")

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

		if len(ptrFile) > 0 {
			var fs []dscFunc
			var enc *json.Encoder

			imap := make(map[*dyld.CacheImage][]uint64)

			pfile, err := os.Open(ptrFile)
			if err != nil {
				return err
			}
			defer pfile.Close()

			scanner := bufio.NewScanner(pfile)

			log.Infof("Parsing functions for pointers in %s", ptrFile)
			for scanner.Scan() {
				addr, err := utils.ConvertStrToInt(scanner.Text())
				if err != nil {
					return err
				}

				var unslidAddr uint64 = addr
				if slide > 0 {
					unslidAddr = addr - slide
				}

				image, err := f.GetImageContainingVMAddr(unslidAddr)
				if err != nil {
					return err
				}

				imap[image] = append(imap[image], unslidAddr)
			}

			if err := scanner.Err(); err != nil {
				return err
			}

			if len(jsonFile) > 0 {
				jFile, err := os.Create(jsonFile)
				if err != nil {
					return err
				}
				defer jFile.Close()
				enc = json.NewEncoder(jFile)
			} else {
				enc = json.NewEncoder(os.Stdout)
			}

			if len(cacheFile) == 0 {
				cacheFile = dscPath + ".a2s"
			}
			if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
				return err
			}

			for img, ptrs := range imap {
				m, err := img.GetMacho()
				if err != nil {
					return err
				}
				defer m.Close()

				for _, ptr := range ptrs {
					if fn, err := m.GetFunctionForVMAddr(ptr); err == nil {
						if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
							fn.Name = symName
						}
						fs = append(fs, dscFunc{
							Addr:  ptr,
							Start: fn.StartAddr,
							End:   fn.EndAddr,
							Size:  fn.EndAddr - fn.StartAddr,
							Name:  fn.Name,
							Image: filepath.Base(img.Name),
						})
					}
				}
			}

			if err := enc.Encode(fs); err != nil {
				return err
			}
		} else {
			if len(args) < 2 {
				return fmt.Errorf("you must supply an virtual address")
			}
			addr, err := utils.ConvertStrToInt(args[1])
			if err != nil {
				return err
			}

			var unslidAddr uint64 = addr
			if slide > 0 {
				unslidAddr = addr - slide
			}

			image, err := f.GetImageContainingVMAddr(unslidAddr)
			if err != nil {
				return err
			}

			m, err := image.GetMacho()
			if err != nil {
				return err
			}
			defer m.Close()

			// Load all symbols
			if err := image.Analyze(); err != nil {
				return err
			}

			if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
				if asJSON {
					if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
						fn.Name = symName
					}
					if err := json.NewEncoder(os.Stdout).Encode(dscFunc{
						Addr:  addr,
						Start: fn.StartAddr,
						End:   fn.EndAddr,
						Size:  fn.EndAddr - fn.StartAddr,
						Name:  fn.Name,
						Image: filepath.Base(image.Name),
					}); err != nil {
						return err
					}
				} else {
					if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
						if unslidAddr-fn.StartAddr == 0 {
							fmt.Printf("\n%#x: %s (start: %#x, end: %#x)\n", addr, symName, fn.StartAddr, fn.EndAddr)
						} else {
							fmt.Printf("\n%#x: %s + %d (start: %#x, end: %#x)\n", addr, symName, unslidAddr-fn.StartAddr, fn.StartAddr, fn.EndAddr)
						}
						return nil
					}
					fmt.Printf("\n%#x: func_%x (start: %#x, end: %#x)\n", addr, addr, fn.StartAddr, fn.EndAddr)
				}
			} else {
				log.Errorf("%#x is not in any known function", unslidAddr)
			}
		}

		return nil
	},
}
