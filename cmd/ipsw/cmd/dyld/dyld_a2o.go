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
package dyld

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(AddrToOffsetCmd)
	AddrToOffsetCmd.Flags().BoolP("dec", "d", false, "Return address in decimal")
	AddrToOffsetCmd.Flags().BoolP("hex", "x", false, "Return address in hexadecimal")
}

// AddrToOffsetCmd represents the a2o command
var AddrToOffsetCmd = &cobra.Command{
	Use:   "a2o <DSC> <ADDR>",
	Short: "Convert address to offset",
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

		inDec, _ := cmd.Flags().GetBool("dec")
		inHex, _ := cmd.Flags().GetBool("hex")

		if inDec && inHex {
			return fmt.Errorf("you can only use --dec OR --hex")
		}

		addr, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
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

		if f.Headers[f.UUID].CacheType == dyld.CacheTypeUniversal {
			utils.Indent(log.Warn, 2)("dyld4 cache with stub islands detected (will search within dyld_subcache_entry's cacheVMOffsets)")
		} else if f.IsDyld4 {
			utils.Indent(log.Warn, 2)("dyld4 cache detected (will search for offset in each subcache)")
		}

		off, err := dsc.ConvertAddressToOffset(f, addr)
		if err != nil {
			return err
		}

		if inDec {
			fmt.Printf("%d\n", off.File.Offset)
		} else if inHex {
			fmt.Printf("%#x\n", off.File.Offset)
		} else {
			if f.IsDyld4 {
				var stubs string
				if off.File.SubCache.InStubs {
					stubs = "STUB Island "
				}
				log.WithFields(log.Fields{
					"hex": fmt.Sprintf("%#x", off.File.Offset),
					"dec": fmt.Sprintf("%d", off.File.Offset),
					"sub_cache": fmt.Sprintf("%sdsc%s, mapping: %s, UUID: %s",
						stubs,
						off.File.SubCache.Extension,
						off.File.SubCache.Mapping,
						off.File.SubCache.UUID,
					),
				}).Info("Offset")
			} else {
				log.WithFields(log.Fields{
					"hex":     fmt.Sprintf("%#x", off.File.Offset),
					"dec":     fmt.Sprintf("%d", off.File.Offset),
					"mapping": off.File.SubCache.Mapping,
				}).Info("Offset")
			}
		}

		if off.Cache != nil {
			var stubs string
			if off.Cache.SubCache.InStubs {
				stubs = "STUB Island "
			}
			log.WithFields(log.Fields{
				"hex": fmt.Sprintf("%#x", off.Cache.Offset),
				"dec": fmt.Sprintf("%d", off.Cache.Offset),
				"sub_cache": fmt.Sprintf("%sdsc%s, mapping: %s, UUID: %s",
					stubs,
					off.Cache.SubCache.Extension,
					off.Cache.SubCache.Mapping,
					off.Cache.SubCache.UUID,
				),
			}).Info("CACHE offset")
		}

		return nil
	},
}
