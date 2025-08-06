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

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoO2aCmd)

	machoO2aCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	machoO2aCmd.Flags().BoolP("dec", "d", false, "Return address in decimal")
	machoO2aCmd.Flags().BoolP("hex", "x", false, "Return address in hexadecimal")
	viper.BindPFlag("macho.o2a.arch", machoO2aCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.o2a.dec", machoO2aCmd.Flags().Lookup("dec"))
	viper.BindPFlag("macho.o2a.hex", machoO2aCmd.Flags().Lookup("hex"))
	machoO2aCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoO2aCmd represents the mo2a command
var machoO2aCmd = &cobra.Command{
	Use:     "o2a <macho> <offset>",
	Aliases: []string{"o"},
	Short:   "Convert MachO offset to address",
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		// flags
		selectedArch := viper.GetString("macho.o2a.arch")
		inDec := viper.GetBool("macho.o2a.dec")
		inHex := viper.GetBool("macho.o2a.hex")

		if inDec && inHex {
			return fmt.Errorf("you can only use --dec OR --hex")
		}

		offset, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
		}

		machoPath := filepath.Clean(args[0])

		mr, err := mcmd.OpenMachO(machoPath, selectedArch)
		if err != nil {
			return err
		}
		defer mr.Close()
		m = mr.File

		address, err := m.GetVMAddress(offset)
		if err != nil {
			log.Error(err.Error())
		} else {
			if inDec {
				fmt.Printf("%d\n", address)
			} else if inHex {
				fmt.Printf("%#x\n", address)
			} else {
				sec := m.FindSectionForVMAddr(address)
				if sec == nil {
					seg := m.FindSegmentForVMAddr(address)
					if seg == nil {
						return fmt.Errorf("failed to find a segment or section containing address %#x", address)
					} else {
						log.WithFields(log.Fields{
							"hex":     fmt.Sprintf("%#x", address),
							"dec":     fmt.Sprintf("%d", address),
							"segment": seg.Name,
						}).Info("Address")
					}
				} else {
					log.WithFields(log.Fields{
						"hex":     fmt.Sprintf("%#x", address),
						"dec":     fmt.Sprintf("%d", address),
						"segment": sec.Seg,
						"section": sec.Name,
					}).Info("Address")
				}
			}
		}

		return nil
	},
}
