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
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
 * ROADMAP:
 * - [ ] add install_name_tool features
 * - [ ] add vtool features
 * - [ ] add ability to add arbitrary LCs
 */

var supportedActions = []string{"add", "rm", "mod"}

var supportedLCs = []string{
	"LC_ID_DYLIB",
	"LC_LOAD_DYLIB",
	"LC_LOAD_WEAK_DYLIB",
	"LC_REEXPORT_DYLIB",
	"LC_LAZY_LOAD_DYLIB",
	"LC_LOAD_UPWARD_DYLIB",
	"LC_RPATH",
	"LC_BUILD_VERSION",
}

func confirm(path string, overwrite bool) bool {
	if overwrite {
		return true
	}
	yes := false
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("You are about to overwrite %s. Continue?", filepath.Base(path)),
	}
	survey.AskOne(prompt, &yes)
	return yes
}

func init() {
	MachoCmd.AddCommand(machoPatchCmd)
	machoPatchCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoPatchCmd.Flags().StringP("output", "o", "", "Directory to save codesigned files to")
	viper.BindPFlag("macho.patch.overwrite", machoPatchCmd.Flags().Lookup("overwrite"))
	viper.BindPFlag("macho.patch.output", machoPatchCmd.Flags().Lookup("output"))
}

// machoPatchCmd represents the patch command
var machoPatchCmd = &cobra.Command{
	Use:           "patch [add|rm|mod] <MACHO> <LC> [OPTIONS]",
	Short:         "Patch MachO Load Commands",
	Args:          cobra.MinimumNArgs(4),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return supportedActions, cobra.ShellCompDirectiveNoFileComp
		}
		if len(args) == 1 {
			return nil, cobra.ShellCompDirectiveDefault
		}
		if len(args) == 2 {
			return supportedLCs, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		overwrite := viper.GetBool("macho.patch.overwrite")

		var m *macho.File

		action := args[0]
		machoPath := filepath.Clean(args[1])
		loadCommand := args[2]

		if !utils.StrSliceHas(supportedLCs, strings.ToUpper(loadCommand)) {
			return fmt.Errorf("unsupported load command: %s; must be one of: %s", loadCommand, strings.Join(supportedLCs, ", "))
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
			return fmt.Errorf(err.Error())
		}

		folder := filepath.Dir(machoPath) // default to folder of macho file
		if len(viper.GetString("macho.patch.output")) > 0 {
			folder = viper.GetString("macho.patch.output")
		}
		outPath := filepath.Join(folder, filepath.Base(machoPath))

		outPath += ".patched"

		if fat, err := macho.OpenFat(machoPath); err == nil { // UNIVERSAL MACHO
			_ = fat // TODO: patch universal machos
			return fmt.Errorf("universal machos are not supported yet")
		} else {
			if errors.Is(err, macho.ErrNotFat) {
				m, err = macho.Open(machoPath)
				if err != nil {
					return fmt.Errorf("failed to open MachO file: %v", err)
				}
				defer m.Close()
			} else {
				return fmt.Errorf("failed to open MachO file: %v", err)
			}
		}

		switch action {
		case "add":
			log.Infof("adding load command %s to %s", loadCommand, machoPath)
			switch loadCommand {
			case "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB":
				if len(args) < 6 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PATH, CURRENT_VERSION and COMPAT_VERSION strings", loadCommand)
				}
				var lc types.LoadCmd
				switch loadCommand {
				case "LC_LOAD_DYLIB":
					lc = types.LC_LOAD_DYLIB
				case "LC_LOAD_WEAK_DYLIB":
					lc = types.LC_LOAD_WEAK_DYLIB
				case "LC_REEXPORT_DYLIB":
					lc = types.LC_REEXPORT_DYLIB
				case "LC_LAZY_LOAD_DYLIB":
					lc = types.LC_LAZY_LOAD_DYLIB
				case "LC_LOAD_UPWARD_DYLIB":
					lc = types.LC_LOAD_UPWARD_DYLIB
				}
				var currVer types.Version
				if err := currVer.Set(args[4]); err != nil {
					return fmt.Errorf("failed to parse current version: %v", err)
				}
				var compatVer types.Version
				if err := compatVer.Set(args[5]); err != nil {
					return fmt.Errorf("failed to parse compatibility version: %v", err)
				}
				m.AddLoad(&macho.Dylib{
					DylibCmd: types.DylibCmd{
						LoadCmd:        lc,
						Len:            uint32(binary.Size(types.DylibCmd{}) + len(args[3]) + 1),
						NameOffset:     0x18,
						Timestamp:      2,
						CurrentVersion: currVer,
						CompatVersion:  compatVer,
					},
					Name: args[3],
				})
			case "LC_RPATH":
				if len(args) < 5 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PATH string", loadCommand)
				}
				m.AddLoad(&macho.Rpath{
					Path: args[4],
				})
			case "LC_BUILD_VERSION":
				if len(args) < 5 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PLATFORM, MINOS, SDK strings and TOOLS via --tools", loadCommand)
				}
				panic("not implemented yet")
				m.AddLoad(&macho.BuildVersion{
					BuildVersionCmd: types.BuildVersionCmd{
						Platform: 1,
						// Minos:    types.Version{Major: 10, Minor: 15, Patch: 0},
						// Sdk:      types.Version{Major: 11, Minor: 0, Patch: 0},
						// Tools: []types.BuildToolVersion{
						// 	{
						// 		Tool:    1,
						// 		Version: types.Version{Major: 11, Minor: 0, Patch: 0},
						// 	},
						// },
						NumTools: 1,
					},
				})
			default:
				return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
			}
		case "rm":
			log.Infof("deleting load command %s from %s", loadCommand, machoPath)
			switch loadCommand {
			case "LC_LOAD_DYLIB",
				"LC_LOAD_WEAK_DYLIB",
				"LC_REEXPORT_DYLIB",
				"LC_LAZY_LOAD_DYLIB",
				"LC_LOAD_UPWARD_DYLIB":
				for _, lc := range m.GetLoadsByName(loadCommand) {
					if lc.(*macho.LoadDylib).Name == args[3] {
						if err := m.RemoveLoad(lc); err != nil {
							return fmt.Errorf("failed to remove load command: %v", err)
						}
					}
				}
			default:
				return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
			}

		case "mod":
			log.Infof("modifying load command %s in %s", loadCommand, machoPath)
			switch loadCommand {
			case "LC_ID_DYLIB":
				if m.FileHeader.Type != types.MH_DYLIB {
					return fmt.Errorf("you can only modify LC_ID_DYLIB in a dylib")
				}
			default:
				return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
			}
		}

		if filepath.Clean(args[1]) == outPath {
			if !confirm(outPath, overwrite) { // confirm overwrite
				return nil
			}
		}

		if err := m.Save(outPath); err != nil {
			return fmt.Errorf("failed to save MachO file: %v", err)
		}

		log.Warn("code signature has been invalidated (MachO may need to be re-signed)")

		return nil
	},
}
