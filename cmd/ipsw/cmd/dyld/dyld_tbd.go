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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/tbd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(TbdCmd)
	TbdCmd.Flags().BoolP("private", "p", false, "Add private symbols")
	TbdCmd.Flags().StringP("output", "o", "", "Directory to extract the dylibs (default: CWD)")
	TbdCmd.MarkFlagDirname("output")
	viper.BindPFlag("dyld.tbd.private", TbdCmd.Flags().Lookup("private"))
	viper.BindPFlag("dyld.tbd.output", TbdCmd.Flags().Lookup("output"))
}

// TbdCmd represents the tbd command
var TbdCmd = &cobra.Command{
	Use:     "tbd <DSC> <DYLIB>",
	Aliases: []string{"t"},
	Short:   "Generate a text-based stub library '.tbd' file for a dylib",
	Args:    cobra.ExactArgs(2),
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
		private := viper.GetBool("dyld.tbd.private")
		output := viper.GetString("dyld.tbd.output")

		dscPath := filepath.Clean(args[0])

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		image, err := f.Image(args[1])
		if err != nil {
			return fmt.Errorf("image not in %s: %v", dscPath, err)
		}

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		var reexports []string
		if rexps := m.GetLoadsByName("LC_REEXPORT_DYLIB"); len(rexps) > 0 {
			for _, rexp := range rexps {
				reexports = append(reexports, rexp.(*macho.ReExportDylib).Name)
			}
		}

		t, err := tbd.NewTBD(image, reexports, private)
		if err != nil {
			return fmt.Errorf("failed to create tbd file for %s: %v", args[1], err)
		}

		outTBD, err := t.Generate()
		if err != nil {
			return fmt.Errorf("failed to create tbd file for %s: %v", args[1], err)
		}

		if rexps := m.GetLoadsByName("LC_REEXPORT_DYLIB"); len(rexps) > 0 {
			for _, rexp := range rexps {
				image, err := f.Image(rexp.(*macho.ReExportDylib).Name)
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}
				t, err := tbd.NewTBD(image, nil, private)
				if err != nil {
					return fmt.Errorf("failed to create tbd file for %s: %v", args[1], err)
				}

				rexpOut, err := t.Generate()
				if err != nil {
					return fmt.Errorf("failed to create tbd file for %s: %v", args[1], err)
				}
				outTBD += "\n" + rexpOut
			}
		}

		outTBD += "...\n"

		tbdFile := filepath.Base(t.Path) + ".tbd"
		if len(output) > 0 {
			if err := os.MkdirAll(output, 0750); err != nil {
				return fmt.Errorf("failed to create output directory %s: %v", output, err)
			}
			tbdFile = filepath.Join(output, tbdFile)
		}

		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %v", err)
		}

		log.Info("Created " + strings.TrimPrefix(tbdFile, cwd))
		if err = os.WriteFile(tbdFile, []byte(outTBD), 0660); err != nil {
			return fmt.Errorf("failed to write tbd file %s: %v", tbdFile, err)
		}

		return nil
	},
}
