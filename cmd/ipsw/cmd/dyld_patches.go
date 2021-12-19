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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(patchesCmd)

	patchesCmd.Flags().StringP("image", "i", "", "dylib image to search")
	patchesCmd.Flags().StringP("sym", "s", "", "dylib image symbol to dump patches for")
	patchesCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// patchesCmd represents the patches command
var patchesCmd = &cobra.Command{
	Use:   "patches <dyld_shared_cache>",
	Short: "Dump dyld patch info",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		symbolName, _ := cmd.Flags().GetString("sym")

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

		if f.IsDyld4 {
			return fmt.Errorf("this command does NOT support the NEW iOS15+ dyld_shared_caches yet")
		}

		if err := f.ParsePatchInfo(); err != nil {
			return err
		}

		if len(imageName) > 0 {
			image, err := f.Image(imageName)
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath, err)
			}
			if image.PatchableExports != nil {
				if len(symbolName) > 0 {
					for _, patch := range image.PatchableExports {
						if strings.EqualFold(strings.ToLower(patch.Name), strings.ToLower(symbolName)) {
							log.Infof("%s patch locations", patch.Name)
							for _, loc := range patch.PatchLocations {
								fmt.Println(loc.String(f.Headers[f.UUID].SharedRegionStart))
							}
						}
					}
				} else {
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
					for _, patch := range image.PatchableExports {
						fmt.Fprintf(w, "0x%08X\t(%d patches)\t%s\n", patch.OffsetOfImpl, len(patch.PatchLocations), patch.Name)
					}
					w.Flush()
				}
			} else {
				log.Warn("Image had no patch entries")
			}
		} else {
			for _, img := range f.Images {
				if img.PatchableExports != nil {
					log.Infof("[%d entries] %s", len(img.PatchableExports), img.Name)
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
					for _, patch := range img.PatchableExports {
						fmt.Printf("0x%08X\t(%d patches)\t%s\n", patch.OffsetOfImpl, len(patch.PatchLocations), patch.Name)
					}
					w.Flush()
				}
			}
		}

		return nil
	},
}
