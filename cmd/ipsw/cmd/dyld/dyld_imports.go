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

func init() {
	DyldCmd.AddCommand(ImportsCmd)
	ImportsCmd.Flags().BoolP("file-system", "f", false, "Scan File System in IPSW for MachO files that import dylib")
	ImportsCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// ImportsCmd represents the imports command
var ImportsCmd = &cobra.Command{
	Use:     "imports",
	Aliases: []string{"imp"},
	Short:   "List all dylibs that load a given dylib",
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		scanFS, _ := cmd.Flags().GetBool("file-system")

		if scanFS {
			ipswPath := filepath.Clean(args[0])
			if err := search.ForEachMachoInIPSW(ipswPath, func(path string, m *macho.File) error {
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
