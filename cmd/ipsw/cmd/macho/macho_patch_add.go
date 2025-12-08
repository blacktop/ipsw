/*
Copyright © 2025 blacktop

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
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var supportedAddLCs = []string{
	"LC_ID_DYLIB",
	"LC_LOAD_DYLIB",
	"LC_LOAD_WEAK_DYLIB",
	"LC_REEXPORT_DYLIB",
	"LC_LAZY_LOAD_DYLIB",
	"LC_LOAD_UPWARD_DYLIB",
	"LC_RPATH",
	"LC_BUILD_VERSION",
	"LC_ID_DYLINKER",
	"LC_LOAD_DYLINKER",
	"LC_DYLD_ENVIRONMENT",
	"LC_VERSION_MIN_MACOSX",
	"LC_VERSION_MIN_IPHONEOS",
	"LC_VERSION_MIN_TVOS",
	"LC_VERSION_MIN_WATCHOS",
}

func init() {
	machoPatchCmd.AddCommand(machoPatchAddCmd)
	machoPatchAddCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoPatchAddCmd.Flags().BoolP("re-sign", "s", false, "Ad-hoc sign file")
	machoPatchAddCmd.Flags().StringP("output", "o", "", "Output new file")
	viper.BindPFlag("macho.patch.add.overwrite", machoPatchAddCmd.Flags().Lookup("overwrite"))
	viper.BindPFlag("macho.patch.add.re-sign", machoPatchAddCmd.Flags().Lookup("re-sign"))
	viper.BindPFlag("macho.patch.add.output", machoPatchAddCmd.Flags().Lookup("output"))
}

// machoPatchAddCmd represents the add command
var machoPatchAddCmd = &cobra.Command{
	Use:   "add <MACHO> <LC> <LC_FIELDS...>",
	Short: "Add a load command to a MachO file",
	Example: heredoc.Doc(`
		# Add an LC_RPATH like install_name_tool
		❯ ipsw macho patch add MACHO LC_RPATH @executable_path/Frameworks`),
	Args:          cobra.MinimumNArgs(2),
	SilenceErrors: true,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return supportedAddLCs, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		overwrite := viper.GetBool("macho.patch.add.overwrite")
		reSign := viper.GetBool("macho.patch.add.re-sign")
		output := viper.GetString("macho.patch.add.output")

		var m *macho.File

		machoPath := filepath.Clean(args[0])
		loadCommand := args[1]

		if !utils.StrSliceHas(supportedAddLCs, strings.ToUpper(loadCommand)) {
			return fmt.Errorf("unsupported load command: %s; must be one of: %s", loadCommand, strings.Join(supportedAddLCs, ", "))
		}

		if info, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		} else if info.IsDir() {
			machoPath, err = plist.GetBinaryInApp(machoPath)
			if err != nil {
				return err
			}
		}

		if ok, err := magic.IsMachO(machoPath); !ok {
			return err
		}

		if len(output) == 0 { // modify in place
			output = machoPath
			if !confirm(output, overwrite) { // confirm overwrite
				return nil
			}
		}

		if fat, err := macho.OpenFat(machoPath); err == nil { // UNIVERSAL MACHO
			defer fat.Close()
			var slices []string
			for _, arch := range fat.Arches {
				if err := mcmd.PatchMachoAdd(arch.File, fmt.Sprintf("%s (%s slice)", machoPath, arch.File.CPU.String()), loadCommand, args); err != nil {
					return fmt.Errorf("failed to patch MachO file: %v", err)
				}
				tmp, err := os.CreateTemp("", "macho_"+arch.File.CPU.String())
				if err != nil {
					return fmt.Errorf("failed to create temp file: %v", err)
				}
				defer os.Remove(tmp.Name())
				if err := arch.File.Save(tmp.Name()); err != nil {
					return fmt.Errorf("failed to save temp file: %v", err)
				}
				if err := tmp.Close(); err != nil {
					return fmt.Errorf("failed to close temp file: %v", err)
				}
				slices = append(slices, tmp.Name())
			}
			if ff, err := macho.CreateFat(output, slices...); err != nil {
				return fmt.Errorf("failed to create fat file: %v", err)
			} else {
				defer ff.Close()
			}
		} else {
			if errors.Is(err, macho.ErrNotFat) {
				m, err = macho.Open(machoPath)
				if err != nil {
					return fmt.Errorf("failed to open MachO file: %v", err)
				}
				defer m.Close()
				if err := mcmd.PatchMachoAdd(m, machoPath, loadCommand, args); err != nil {
					return fmt.Errorf("failed to patch MachO file: %v", err)
				}
				if err := m.Save(output); err != nil {
					return fmt.Errorf("failed to save patched MachO file: %v", err)
				}
			} else {
				return fmt.Errorf("failed to open MachO file: %v", err)
			}
		}

		yes := false
		if !reSign {
			log.Warn("Code signature has been invalidated (MachO may need to be re-signed)")
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("Adhoc codesign %s?", output),
				Default: false,
			}
			survey.AskOne(prompt, &yes)
		}
		if reSign || yes {
			log.Infof("Adhoc signing MachO file: %s", output)
			return mcmd.AdhocSign(output, output)
		}

		return nil
	},
}
