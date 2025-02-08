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
package macho

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoA2oCmd)

	machoA2oCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	machoA2oCmd.Flags().BoolP("dec", "d", false, "Return address in decimal")
	machoA2oCmd.Flags().BoolP("hex", "x", false, "Return address in hexadecimal")
	viper.BindPFlag("macho.a2o.arch", machoA2oCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.a2o.dec", machoA2oCmd.Flags().Lookup("dec"))
	viper.BindPFlag("macho.a2o.hex", machoA2oCmd.Flags().Lookup("hex"))
	machoA2oCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoA2oCmd represents the ma2o command
var machoA2oCmd = &cobra.Command{
	Use:     "a2o <macho> <vaddr>",
	Aliases: []string{"a"},
	Short:   "Convert MachO address to offset",
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		selectedArch := viper.GetString("macho.a2o.arch")
		inDec := viper.GetBool("macho.a2o.dec")
		inHex := viper.GetBool("macho.a2o.hex")

		if inDec && inHex {
			return fmt.Errorf("you can only use --dec OR --hex")
		}

		addr, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
		}

		machoPath := filepath.Clean(args[0])

		// first check for fat file
		fat, err := macho.OpenFat(machoPath)
		if err != nil && err != macho.ErrNotFat {
			return err
		}
		if err == macho.ErrNotFat {
			m, err = macho.Open(machoPath)
			if err != nil {
				return err
			}
		} else {
			var options []string
			var shortOptions []string
			for _, arch := range fat.Arches {
				options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
				shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
			}

			if len(selectedArch) > 0 {
				found := false
				for i, opt := range shortOptions {
					if strings.Contains(strings.ToLower(opt), strings.ToLower(selectedArch)) {
						m = fat.Arches[i].File
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("--arch '%s' not found in: %s", selectedArch, strings.Join(shortOptions, ", "))
				}
			} else {
				choice := 0
				prompt := &survey.Select{
					Message: "Detected a universal MachO file, please select an architecture to analyze:",
					Options: options,
				}
				survey.AskOne(prompt, &choice)
				m = fat.Arches[choice].File
			}
		}

		off, err := m.GetOffset(addr)
		if err != nil {
			log.Error(err.Error())
		} else {
			if inDec {
				fmt.Printf("%d\n", off)
			} else if inHex {
				fmt.Printf("%#x\n", off)
			} else {
				sec := m.FindSectionForVMAddr(addr)
				if sec == nil {
					seg := m.FindSegmentForVMAddr(addr)
					if seg == nil {
						return fmt.Errorf("failed to find a segment or section containing address %#x", addr)
					}
					log.WithFields(log.Fields{
						"hex":     fmt.Sprintf("%#x", off),
						"dec":     fmt.Sprintf("%d", off),
						"segment": seg.Name,
					}).Info("Offset")
				} else {
					log.WithFields(log.Fields{
						"hex":     fmt.Sprintf("%#x", off),
						"dec":     fmt.Sprintf("%d", off),
						"segment": sec.Seg,
						"section": sec.Name,
					}).Info("Offset")
				}
			}
		}

		return nil
	},
}
