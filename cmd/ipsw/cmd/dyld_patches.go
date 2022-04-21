/*
Copyright © 2018-2022 blacktop

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
	"github.com/blacktop/ipsw/internal/utils"
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
					if f.PatchInfoVersion == 1 {
						for _, patch := range image.PatchableExports {
							if strings.EqualFold(strings.ToLower(patch.Name), strings.ToLower(symbolName)) {
								log.Infof("%s patch locations", patch.Name)
								for _, loc := range patch.PatchLocations {
									fmt.Println(loc.String(f.Headers[f.UUID].SharedRegionStart))
								}
							}
						}
					} else {
						exp2uses := make(map[string][]dyld.PatchableExport)
						for _, patch := range image.PatchableExports {
							exp2uses[patch.Name] = append(exp2uses[patch.Name], patch)
						}
						if patches, ok := exp2uses[symbolName]; ok {
							fmt.Printf("%#x: %s\n", image.LoadAddress+uint64(patches[0].OffsetOfImpl), symbolName)
							for _, patch := range patches {
								for _, loc := range patch.PatchLocationsV2 {
									fmt.Printf("    %s\t%s\n",
										loc.String(f.Images[patch.ClientIndex].LoadAddress),
										f.Images[patch.ClientIndex].Name)
								}
							}
						} else {
							log.Infof("%s patch locations", symbolName)
							utils.Indent(log.Error, 2)("no patches found")
						}
					}
				} else {
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
					if f.PatchInfoVersion == 1 {
						for _, patch := range image.PatchableExports {
							fmt.Fprintf(w, "%#x\t(%d patches)\t%s\n", patch.OffsetOfImpl, len(patch.PatchLocations), patch.Name)
						}
						w.Flush()
					} else {
						exp2uses := make(map[string][]dyld.PatchableExport)
						for _, patch := range image.PatchableExports {
							exp2uses[patch.Name] = append(exp2uses[patch.Name], patch)
						}
						for name, patches := range exp2uses {
							fmt.Printf("%#x: %s\n", image.LoadAddress+uint64(patches[0].OffsetOfImpl), name)
							for _, patch := range patches {
								for _, loc := range patch.PatchLocationsV2 {
									fmt.Fprintf(w, "    %s\t%s\n",
										loc.String(f.Images[patch.ClientIndex].LoadAddress),
										f.Images[patch.ClientIndex].Name)
								}
							}
							w.Flush()
						}
					}
				}
			} else {
				log.Warnf("image %s had no patch entries", filepath.Base(image.Name))
			}
		} else {
			for _, image := range f.Images {
				if image.PatchableExports != nil {
					fmt.Printf("[%d entries] %s\n", len(image.PatchableExports), image.Name)
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
					if f.PatchInfoVersion == 1 {
						for _, patch := range image.PatchableExports {
							fmt.Fprintf(w, "%#x\t(%d patches)\t%s\n", patch.OffsetOfImpl, len(patch.PatchLocations), patch.Name)
						}
						w.Flush()
					} else {
						exp2uses := make(map[string][]dyld.PatchableExport)
						for _, patch := range image.PatchableExports {
							exp2uses[patch.Name] = append(exp2uses[patch.Name], patch)
						}
						for name, patches := range exp2uses {
							fmt.Printf("%#x: %s\n", image.LoadAddress+uint64(patches[0].OffsetOfImpl), name)
							for _, patch := range patches {
								for _, loc := range patch.PatchLocationsV2 {
									fmt.Fprintf(w, "    %s\t%s\n", loc.String(f.Images[patch.ClientIndex].LoadAddress), f.Images[patch.ClientIndex].Name)
								}
								w.Flush()
							}
						}
					}

				}
			}
		}

		return nil
	},
}
