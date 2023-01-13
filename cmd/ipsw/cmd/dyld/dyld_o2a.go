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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(OffsetToAddrCmd)
	OffsetToAddrCmd.Flags().BoolP("dec", "d", false, "Return address in decimal")
	OffsetToAddrCmd.Flags().BoolP("hex", "x", false, "Return address in hexadecimal")

	OffsetToAddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// OffsetToAddrCmd represents the o2a command
var OffsetToAddrCmd = &cobra.Command{
	Use:           "o2a <dyld_shared_cache> <offset>",
	Short:         "Convert dyld_shared_cache offset to address",
	Args:          cobra.MinimumNArgs(2),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		inDec, _ := cmd.Flags().GetBool("dec")
		inHex, _ := cmd.Flags().GetBool("hex")

		if inDec && inHex {
			return fmt.Errorf("you can only use --dec OR --hex")
		}

		offset, err := utils.ConvertStrToInt(args[1])
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
			log.Warn("dyld4 cache with stub islands detected (will search within dyld_subcache_entry's cacheVMOffsets)")
			uuid, address, err := f.GetCacheVMAddress(offset)
			if err != nil {
				return err
			}
			if f.IsDyld4 {
				ext, err := f.GetSubCacheExtensionFromUUID(uuid)
				if err != nil {
					return err
				}
				_, m, err := f.GetMappingForVMAddress(address)
				if err != nil {
					return err
				}
				var stubs bool
				if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
					stubs = true
				}
				log.WithFields(log.Fields{
					"uuid":    uuid.String(),
					"hex":     fmt.Sprintf("%#x", address),
					"dec":     fmt.Sprintf("%d", address),
					"ext":     fmt.Sprintf("\"%s\"", ext),
					"stubs":   stubs,
					"mapping": m.Name,
				}).Info("Address")
				return nil
			}
		}

		if f.IsDyld4 {
			log.Warn("dyld4 cache detected (will search for offset in each subcache)")
		}

		for uuid := range f.MappingsWithSlideInfo {
			address, err := f.GetVMAddressForUUID(uuid, offset)
			if err != nil {
				continue
			} else {
				if inDec {
					fmt.Printf("%d\n", address)
				} else if inHex {
					fmt.Printf("%#x\n", address)
				} else {
					uuid, m, err := f.GetMappingForVMAddress(address)
					if err != nil {
						return err
					}
					if f.IsDyld4 {
						ext, _ := f.GetSubCacheExtensionFromUUID(uuid)
						var stubs bool
						if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
							stubs = true
						}
						log.WithFields(log.Fields{
							"uuid":    uuid.String(),
							"hex":     fmt.Sprintf("%#x", address),
							"dec":     fmt.Sprintf("%d", address),
							"ext":     fmt.Sprintf("\"%s\"", ext),
							"stubs":   stubs,
							"mapping": m.Name,
						}).Info("Address")
					} else {
						log.WithFields(log.Fields{
							"hex":     fmt.Sprintf("%#x", address),
							"dec":     fmt.Sprintf("%d", address),
							"mapping": m.Name,
						}).Info("Address")
					}
				}
			}
		}

		return nil
	},
}
