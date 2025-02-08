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
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	dscCmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldImportsCmd)
	dyldImportsCmd.Flags().StringP("ipsw", "i", "", "Path to IPSW to scan for MachO files that import dylib")
	dyldImportsCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	dyldImportsCmd.RegisterFlagCompletionFunc("ipsw", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	})
}

// dyldImportsCmd represents the imports command
var dyldImportsCmd = &cobra.Command{
	Use:     "imports <DSC> <DYLIB>",
	Aliases: []string{"imp"},
	Short:   "List all dylibs that load a given dylib",
	Args:    cobra.MaximumNArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveDefault
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")
		// flags
		ipswPath, _ := cmd.Flags().GetString("ipsw")
		pemDB, _ := cmd.Flags().GetString("pem-db")
		// validate args
		if ipswPath != "" && len(args) != 1 {
			return errors.New("you must specify a DYLIB to search for")
		} else if ipswPath == "" && len(args) != 2 {
			return errors.New("you must specify a DSC and a DYLIB to search for")
		}

		if ipswPath != "" {
			found := false
			if err := search.ForEachMachoInIPSW(filepath.Clean(ipswPath), pemDB, func(path string, m *macho.File) error {
				for _, imp := range m.ImportedLibraries() {
					if strings.EqualFold(imp, args[0]) {
						fmt.Printf("%s\n", path)
						found = true
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to scan files in IPSW: %v", err)
			}
			if !found {
				log.Warn("No MachOs found containing import; NOTE: '--ipsw' imports searching requires the exact FULL path to the dylib (example:  /usr/lib/libobjc.A.dylib)")
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

			importedBy, err := dscCmd.GetDylibsThatImport(f, image.Name)
			if err != nil {
				return fmt.Errorf("failed to get dylibs that import %s: %v", image.Name, err)
			}

			if len(importedBy.DSC) > 0 {
				fmt.Println("\nIn DSC (Dylibs)")
				fmt.Println("---------------")
				for _, img := range importedBy.DSC {
					fmt.Println(img)
				}
			}

			if len(importedBy.Apps) > 0 {
				fmt.Println("\nIn FileSystem DMG (Apps)")
				fmt.Println("------------------------")
				for _, img := range importedBy.Apps {
					fmt.Println(img)
				}
			}
		}

		return nil
	},
}
