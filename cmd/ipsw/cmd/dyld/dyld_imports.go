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
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getDSCs(path string) []string {
	matches, err := filepath.Glob(filepath.Join(path, "dyld_shared_cache*"))
	if err != nil {
		return nil
	}
	return matches
}

func init() {
	DyldCmd.AddCommand(dyldImportsCmd)
	dyldImportsCmd.Flags().StringP("ipsw", "i", "", "Path to IPSW to scan for MachO files that import dylib")
	dyldImportsCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
	dyldImportsCmd.RegisterFlagCompletionFunc("ipsw", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	})
}

// dyldImportsCmd represents the imports command
var dyldImportsCmd = &cobra.Command{
	Use:     "imports",
	Aliases: []string{"imp"},
	Short:   "List all dylibs that load a given dylib",
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		ipswPath, _ := cmd.Flags().GetString("ipsw")

		if ipswPath != "" {
			if err := search.ForEachMachoInIPSW(filepath.Clean(ipswPath), func(path string, m *macho.File) error {
				for _, imp := range m.ImportedLibraries() {
					if strings.Contains(strings.ToLower(imp), strings.ToLower(args[1])) {
						fmt.Printf("%s\n", path)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to scan files in IPSW: %v", err)
			}
		} else {
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

			image, err := f.Image(args[1])
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath, err)
			}

			title := fmt.Sprintf("\n%s Imported By:\n", filepath.Base(image.Name))
			fmt.Print(title)
			fmt.Println(strings.Repeat("=", len(title)-2))

			if f.SupportsDylibPrebuiltLoader() {
				fmt.Println("\nIn DSC (Dylibs)")
				fmt.Println("---------------")
				for _, img := range f.Images {
					pbl, err := f.GetDylibPrebuiltLoader(img.Name)
					if err != nil {
						return err
					}
					for _, dep := range pbl.Dependents {
						if strings.EqualFold(dep.Name, image.Name) {
							fmt.Println(img.Name)
						}
					}
				}
			} else {
				for _, img := range f.Images {
					m, err := img.GetPartialMacho()
					if err != nil {
						return err
					}
					for _, imp := range m.ImportedLibraries() {
						if strings.EqualFold(imp, image.Name) {
							fmt.Println(img.Name)
						}
					}
					m.Close()
				}
			}

			if f.SupportsPrebuiltLoaderSet() {
				fmt.Println("\nIn FileSystem DMG (Apps)")
				fmt.Println("------------------------")
				if err := f.ForEachLaunchLoaderSet(func(execPath string, pset *dyld.PrebuiltLoaderSet) {
					for _, loader := range pset.Loaders {
						for _, dep := range loader.Dependents {
							if strings.EqualFold(dep.Name, image.Name) {
								if execPath != loader.Path {
									fmt.Printf("%s (%s)\n", execPath, loader.Path)
								} else {
									fmt.Println(execPath)
								}
							}
						}
					}
				}); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
