/*
Copyright © 2022 blacktop

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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	ctypes "github.com/blacktop/go-macho/pkg/codesign/types"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoSignCmd)

	machoSignCmd.Flags().StringP("id", "i", "", "sign with identifier")
	machoSignCmd.Flags().BoolP("ad-hoc", "a", false, "ad-hoc codesign")
	machoSignCmd.Flags().StringP("cert", "c", "", "p12 codesign with cert")
	machoSignCmd.Flags().StringP("ent", "e", "", "entitlements.plist file")
	machoSignCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoSignCmd.Flags().StringP("output", "o", "", "Output codesigned file")
	viper.BindPFlag("macho.sign.id", machoSignCmd.Flags().Lookup("id"))
	viper.BindPFlag("macho.sign.ad-hoc", machoSignCmd.Flags().Lookup("ad-hoc"))
	viper.BindPFlag("macho.sign.cert", machoSignCmd.Flags().Lookup("cert"))
	viper.BindPFlag("macho.sign.ent", machoSignCmd.Flags().Lookup("ent"))
	viper.BindPFlag("macho.sign.overwrite", machoSignCmd.Flags().Lookup("overwrite"))
	viper.BindPFlag("macho.sign.output", machoSignCmd.Flags().Lookup("output"))
	machoSignCmd.MarkFlagRequired("id")
}

// machoSignCmd represents the macho sign command
var machoSignCmd = &cobra.Command{
	Use:           "sign <MACHO>",
	Short:         "Codesign a MachO",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		id := viper.GetString("macho.sign.id")
		adHoc := viper.GetBool("macho.sign.ad-hoc")
		// certFile := viper.GetString("macho.sign.cert")
		entitlementsPlist := viper.GetString("macho.sign.ent")
		overwrite := viper.GetBool("macho.sign.overwrite")
		output := viper.GetString("macho.sign.output")

		machoPath := filepath.Clean(args[0])

		if info, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		} else if info.IsDir() {
			machoPath, err = plist.GetBinaryInApp(machoPath)
			if err != nil {
				return err
			}
		}

		if ok, err := magic.IsMachO(machoPath); !ok {
			return fmt.Errorf(err.Error())
		}
		var entitlementData []byte
		if len(entitlementsPlist) > 0 {
			entitlementData, err = os.ReadFile(entitlementsPlist)
			if err != nil {
				return fmt.Errorf("failed to read entitlements file %s: %v", entitlementsPlist, err)
			}
		}

		if fat, err := macho.OpenFat(machoPath); err == nil { // UNIVERSAL MACHO
			defer fat.Close()
			if adHoc {
				_ = fat // TODO: sign universal machos
			}
			return fmt.Errorf("universal machos are not supported yet")
		} else {
			if errors.Is(err, macho.ErrNotFat) {
				m, err = macho.Open(machoPath)
				if err != nil {
					return err
				}
				defer m.Close()

				if adHoc {
					if err := m.CodeSign(id, ctypes.ADHOC, entitlementData); err != nil {
						return fmt.Errorf("failed to codesign MachO file: %v", err)
					}
				} else {
					panic("non ad-hoc codesigning is not supported yet")
					// if err := m.CodeSign(id, ctypes.RUNTIME, entitlementData); err != nil {
					// 	return fmt.Errorf("failed to codesign MachO file: %v", err)
					// }
				}
			} else {
				return fmt.Errorf("failed to open MachO file: %v", err)
			}
		}

		if len(output) == 0 {
			output = machoPath
		}

		if filepath.Clean(args[0]) == output {
			if !confirm(output, overwrite) { // confirm overwrite
				return nil
			}
		}

		log.Infof("Codesigning %s", output)
		if err := m.Save(output); err != nil {
			return fmt.Errorf("failed to save signed MachO file: %v", err)
		}

		return nil
	},
}
