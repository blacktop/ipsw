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
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(PatchesCmd)
	PatchesCmd.Flags().StringP("image", "i", "", "dylib image to search")
	PatchesCmd.Flags().StringP("sym", "s", "", "dylib image symbol to dump patches for")
}

// PatchesCmd represents the patches command
var PatchesCmd = &cobra.Command{
	Use:     "patches <DSC>",
	Aliases: []string{"p"},
	Short:   "Dump dyld patch info",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

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
			return fmt.Errorf("failed to parse patch info: %s", err)
		}

		var images []*dyld.CacheImage

		if len(imageName) > 0 {
			image, err := f.Image(imageName)
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath, err)
			}
			images = append(images, image)
		} else {
			images = f.Images
		}

		for idx, image := range images {
			if image.PatchableExports == nil && image.PatchableGOTs == nil {
				continue
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)

			if len(symbolName) > 0 {
				switch f.PatchInfoVersion {
				case 1:
					for _, patch := range image.PatchableExports {
						if strings.EqualFold(strings.ToLower(patch.GetName()), strings.ToLower(symbolName)) {
							log.Infof("%s patch locations", patch.GetName())
							for _, loc := range patch.GetPatchLocations().([]dyld.CachePatchableLocationV1) {
								fmt.Println(loc.String(f.Headers[f.UUID].SharedRegionStart))
							}
						}
					}
				case 2, 3:
					exp2uses := make(map[string][]dyld.Patch)
					for _, patch := range image.PatchableExports {
						exp2uses[patch.GetName()] = append(exp2uses[patch.GetName()], patch)
					}
					if patches, ok := exp2uses[symbolName]; ok {
						fmt.Printf("%#x: %s%s\n", image.LoadAddress+uint64(patches[0].GetImplOffset()), patches[0].GetKind(), symbolName)
						for _, patch := range patches {
							for _, loc := range patch.GetPatchLocations().([]dyld.CachePatchableLocationV2) {
								fmt.Fprintf(w, "    %s\t%s\n",
									loc.String(f.Images[patch.GetClientIndex()].LoadAddress),
									f.Images[patch.GetClientIndex()].Name)
							}
						}
					}
					if f.PatchInfoVersion == 3 {
						// GOT patch locations
						got2uses := make(map[string][]dyld.Patch)
						for _, got := range image.PatchableGOTs {
							got2uses[got.GetName()] = append(got2uses[got.GetName()], got)
						}
						if patches, ok := got2uses[symbolName]; ok {
							for _, patch := range patches {
								for _, got := range patch.GetGotLocations().([]dyld.CachePatchableLocationV3) {
									fmt.Fprintf(w, "    %s\tGOT\n",
										got.String(func(u uint64) uint64 {
											if _, addr, err := f.GetCacheVMAddress(u); err == nil {
												return addr
											}
											return 0
										}))
								}
							}
						}
					}
					w.Flush()
				case 4:
					// Patch locations
					exp2uses := make(map[string][]dyld.Patch)
					for _, patch := range image.PatchableExports {
						exp2uses[patch.GetName()] = append(exp2uses[patch.GetName()], patch)
					}
					if patches, ok := exp2uses[symbolName]; ok {
						fmt.Printf("%#x: %s%s\n", image.LoadAddress+uint64(patches[0].GetImplOffset()), patches[0].GetKind(), symbolName)
						for _, patch := range patches {
							for _, loc := range patch.GetPatchLocations().([]dyld.CachePatchableLocationV4) {
								fmt.Fprintf(w, "    %s\t%s\n",
									loc.String(f.Images[patch.GetClientIndex()].LoadAddress),
									colorImage(path.Base(f.Images[patch.GetClientIndex()].Name)))
							}
						}
					}
					// GOT patch locations
					got2uses := make(map[string][]dyld.Patch)
					for _, got := range image.PatchableGOTs {
						got2uses[got.GetName()] = append(got2uses[got.GetName()], got)
					}
					if patches, ok := got2uses[symbolName]; ok {
						for _, patch := range patches {
							for _, got := range patch.GetGotLocations().([]dyld.CachePatchableLocationV4Got) {
								fmt.Fprintf(w, "    %s\n",
									got.String(func(u uint64) uint64 {
										if _, addr, err := f.GetCacheVMAddress(u); err == nil {
											return addr
										}
										return 0
									}))
							}
						}
					}
					w.Flush()
				default:
					return fmt.Errorf("unsupported patch info version %d", f.PatchInfoVersion)
				}
			} else {
				if idx == 0 {
					fmt.Printf("[PATCHES] %s", image.Name)
				} else {
					fmt.Printf("\n[PATCHES] %s", image.Name)
				}
				switch f.PatchInfoVersion {
				case 1:
					fmt.Println()
					for _, patch := range image.PatchableExports {
						fmt.Fprintf(w, "%#x\t(%d patches)\t%s\n", patch.GetImplOffset(), len(patch.GetPatchLocations().([]dyld.CachePatchableLocationV1)), patch.GetName())
					}
					w.Flush()
				case 2, 3:
					exp2uses := make(map[string][]dyld.Patch)
					for _, patch := range image.PatchableExports {
						exp2uses[patch.GetName()] = append(exp2uses[patch.GetName()], patch)
					}
					if f.PatchInfoVersion == 3 {
						for _, got := range image.PatchableGOTs {
							exp2uses[got.GetName()] = append(exp2uses[got.GetName()], got)
						}
					}
					fmt.Printf("\t(%d symbols)\n", len(exp2uses))
					for name, patches := range exp2uses {
						fmt.Printf("%#x: %s\n", image.LoadAddress+uint64(patches[0].GetImplOffset()), name)
						for _, patch := range patches {
							switch patch := patch.(type) {
							case dyld.PatchableExport:
								for _, loc := range patch.PatchLocationsV2 {
									fmt.Fprintf(w, "    %s\t%s\n",
										loc.String(f.Images[patch.ClientIndex].LoadAddress),
										f.Images[patch.ClientIndex].Name)
								}
							case dyld.PatchableGotExport:
								for _, got := range patch.GotLocationsV3 {
									fmt.Fprintf(w, "    %s\tGOT\n",
										got.String(func(u uint64) uint64 {
											if _, addr, err := f.GetCacheVMAddress(u); err == nil {
												return addr
											}
											return 0
										}))
								}
							}
						}
						w.Flush()
					}
				case 4:
					exp2uses := make(map[string][]dyld.Patch)
					for _, patch := range image.PatchableExports {
						exp2uses[patch.GetName()] = append(exp2uses[patch.GetName()], patch)
					}
					for _, got := range image.PatchableGOTs {
						exp2uses[got.GetName()] = append(exp2uses[got.GetName()], got)
					}
					fmt.Printf("\t(%d symbols)\n", len(exp2uses))
					for name, patches := range exp2uses {
						fmt.Printf("%#x: %s\n", image.LoadAddress+uint64(patches[0].GetImplOffset()), name)
						for _, patch := range patches {
							switch patch := patch.(type) {
							case dyld.PatchableExport:
								for _, loc := range patch.PatchLocationsV4 {
									fmt.Fprintf(w, "    %s\t%s\n",
										loc.String(f.Images[patch.ClientIndex].LoadAddress),
										colorImage(path.Base(f.Images[patch.ClientIndex].Name)))
								}
							case dyld.PatchableGotExport:
								for _, got := range patch.GotLocationsV4 {
									fmt.Fprintf(w, "    %s\n",
										got.String(func(u uint64) uint64 {
											if _, addr, err := f.GetCacheVMAddress(u); err == nil {
												return addr
											}
											return 0
										}))
								}
							}
						}
						w.Flush()
					}
				default:
					return fmt.Errorf("unsupported patch info version %d", f.PatchInfoVersion)
				}
			}
		}

		return nil
	},
}
