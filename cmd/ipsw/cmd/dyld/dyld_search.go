/*
Copyright © 2024 blacktop

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
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldSearchCmd)

	dyldSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command regex")
	dyldSearchCmd.Flags().StringP("import", "i", "", "Search for specific import regex")
	dyldSearchCmd.Flags().StringP("section", "x", "", "Search for specific section regex")
	dyldSearchCmd.Flags().StringP("uuid", "u", "", "Search for dylib by UUID")
	viper.BindPFlag("dyld.search.load-command", dyldSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("dyld.search.import", dyldSearchCmd.Flags().Lookup("import"))
	viper.BindPFlag("dyld.search.section", dyldSearchCmd.Flags().Lookup("section"))
	viper.BindPFlag("dyld.search.uuid", dyldSearchCmd.Flags().Lookup("uuid"))
}

// dyldSearchCmd represents the search command
var dyldSearchCmd = &cobra.Command{
	Use:     "search <DSC>",
	Aliases: []string{"sr"},
	Short:   "Find Dylib files for given search criteria",
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

		// flags
		loadCmdReStr := viper.GetString("dyld.search.load-command")
		importReStr := viper.GetString("dyld.search.import")
		sectionReStr := viper.GetString("dyld.search.section")
		uuidStr := viper.GetString("dyld.search.uuid")
		// verify flags
		if loadCmdReStr == "" && importReStr == "" && sectionReStr == "" && uuidStr == "" {
			return fmt.Errorf("must specify a search criteria via one of the flags")
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
				return fmt.Errorf("failed to read symlink %s: %v", dscPath, err)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return fmt.Errorf("failed to open dyld shared cache %s: %w", dscPath, err)
		}

		var m *macho.File

		for _, img := range f.Images {
			if loadCmdReStr != "" {
				m, err = img.GetMacho()
				if err != nil {
					return err
				}
			} else { // use partial macho for speed
				m, err = img.GetPartialMacho()
				if err != nil {
					return err
				}
			}

			if uuidStr != "" {
				if strings.EqualFold(img.UUID.String(), uuidStr) {
					fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("uuid"), img.UUID)
				}
			}
			if loadCmdReStr != "" {
				re, err := regexp.Compile(loadCmdReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", loadCmdReStr, err)
				}
				for _, lc := range m.Loads {
					if re.MatchString(lc.Command().String()) {
						fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("load"), lc.Command())
						fmt.Printf("\t%s\n", lc)
					}
				}
			}
			if importReStr != "" {
				re, err := regexp.Compile(importReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", importReStr, err)
				}
				for _, imp := range m.ImportedLibraries() {
					if re.MatchString(imp) {
						fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("import"), imp)
						break
					}
				}
			}
			if sectionReStr != "" {
				re, err := regexp.Compile(sectionReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", sectionReStr, err)
				}
				for _, sec := range m.Sections {
					if re.MatchString(fmt.Sprintf("%s.%s", sec.Seg, sec.Name)) {
						fmt.Printf("%-55s%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("load"), fmt.Sprintf("%s.%s", sec.Seg, sec.Name))
					}
				}
			}
		}

		return nil
	},
}
