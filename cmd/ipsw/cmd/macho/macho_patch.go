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
		Message: fmt.Sprintf("You are about to overwrite %s. Continue?", path),
	}
	survey.AskOne(prompt, &yes)
	return yes
}

func pointerAlign(sz uint32) uint32 {
	if (sz % 8) != 0 {
		sz += 8 - (sz % 8)
	}
	return sz
}

func init() {
	MachoCmd.AddCommand(machoPatchCmd)
	machoPatchCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoPatchCmd.Flags().StringP("output", "o", "", "Output new file")
	viper.BindPFlag("macho.patch.overwrite", machoPatchCmd.Flags().Lookup("overwrite"))
	viper.BindPFlag("macho.patch.output", machoPatchCmd.Flags().Lookup("output"))
}

// machoPatchCmd represents the patch command
var machoPatchCmd = &cobra.Command{
	Use:           "patch [add|rm|mod] <MACHO> <LC> <LC_FIELDS...>",
	Short:         "Patch MachO Load Commands",
	Args:          cobra.MinimumNArgs(3),
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

		// flags
		overwrite := viper.GetBool("macho.patch.overwrite")
		output := viper.GetString("macho.patch.output")

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
			log.Infof("Adding load command %s to %s", loadCommand, machoPath)
			switch loadCommand {
			case "LC_ID_DYLIB":
				m.FileHeader.Type = types.MH_DYLIB // set type to dylib
				fallthrough
			case "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB":
				if len(args) < 6 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PATH, CURRENT_VERSION and COMPAT_VERSION strings", loadCommand)
				}
				var lc types.LoadCmd
				switch loadCommand {
				case "LC_ID_DYLIB":
					lc = types.LC_ID_DYLIB
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
						Len:            pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[3]) + 1)),
						NameOffset:     0x18,
						Timestamp:      2,
						CurrentVersion: currVer,
						CompatVersion:  compatVer,
					},
					Name: args[3],
				})
			case "LC_RPATH":
				if len(args) < 4 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PATH string", loadCommand)
				}
				m.AddLoad(&macho.Rpath{
					RpathCmd: types.RpathCmd{
						LoadCmd:    types.LC_RPATH,
						Len:        pointerAlign(uint32(binary.Size(types.RpathCmd{}) + len(args[3]) + 1)),
						PathOffset: 0xC,
					},
					Path: args[3],
				})
			case "LC_BUILD_VERSION":
				if len(args) < 8 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PLATFORM, MINOS, SDK strings and TOOL, TOOL_VERSION strings", loadCommand)
				} else if len(args) > 8 {
					return fmt.Errorf("too many arguments for adding %s; NOTE you can only add one tool to a %s", loadCommand, loadCommand)
				}
				platform, err := types.GetPlatformByName(args[3])
				if err != nil {
					return fmt.Errorf("failed to parse tool name: %v", err)
				}
				var minos types.Version
				if err := minos.Set(args[4]); err != nil {
					return fmt.Errorf("failed to parse min OS version: %v", err)
				}
				var sdk types.Version
				if err := sdk.Set(args[5]); err != nil {
					return fmt.Errorf("failed to parse SDK version: %v", err)
				}
				tool, err := types.GetToolByName(args[6])
				if err != nil {
					return fmt.Errorf("failed to parse tool name: %v", err)
				}
				var toolVer types.Version
				if err := toolVer.Set(args[7]); err != nil {
					return fmt.Errorf("failed to parse tool version: %v", err)
				}
				m.AddLoad(&macho.BuildVersion{
					BuildVersionCmd: types.BuildVersionCmd{
						LoadCmd:  types.LC_BUILD_VERSION,
						Len:      uint32(binary.Size(types.BuildVersionCmd{}) + binary.Size(types.BuildVersionTool{})),
						Platform: platform,
						Minos:    minos,
						Sdk:      sdk,
						NumTools: 1,
					},
					Tools: []types.BuildVersionTool{
						{
							Tool:    tool,
							Version: toolVer,
						},
					},
				})
			default:
				return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
			}
		case "rm":
			log.Infof("Deleting load command %s from %s", loadCommand, machoPath)
			switch loadCommand {
			case "LC_ID_DYLIB":
				if m.FileHeader.Type == types.MH_DYLIB {
					m.FileHeader.Type = types.MH_EXECUTE // set type to executable to remove LC_ID_DYLIB
				}
				fallthrough
			case "LC_BUILD_VERSION":
				for _, lc := range m.GetLoadsByName(loadCommand) {
					if err := m.RemoveLoad(lc); err != nil {
						return fmt.Errorf("failed to remove load command: %v", err)
					}
				}
			case "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_RPATH":
				if len(args) < 4 {
					return fmt.Errorf("not enough arguments for removing %s; must supply PATH string", loadCommand)
				}
				for _, lc := range m.GetLoadsByName(loadCommand) {
					if lc.(*macho.Dylib).Name == args[3] {
						if err := m.RemoveLoad(lc); err != nil {
							return fmt.Errorf("failed to remove load command: %v", err)
						}
					}
				}
			default:
				return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
			}

		case "mod":
			log.Infof("Modifying load command %s in %s", loadCommand, machoPath)
			switch loadCommand {
			case "LC_ID_DYLIB":
				if m.FileHeader.Type != types.MH_DYLIB {
					return fmt.Errorf("you can only modify LC_ID_DYLIB in a dylib")
				}
				if len(args) < 4 {
					return fmt.Errorf("not enough arguments for setting %s; must supply ID string", loadCommand)
				}
				for _, lc := range m.GetLoadsByName(loadCommand) {
					lc.(*macho.IDDylib).Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[3]) + 1))
					lc.(*macho.IDDylib).Name = args[3]
				}
			case "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB":
				if len(args) < 5 {
					return fmt.Errorf("not enough arguments for setting %s; must supply OLD and NEW strings", loadCommand)
				}
				for _, lc := range m.GetLoadsByName(loadCommand) {
					if lc.(*macho.Dylib).Name == args[3] {
						lc.(*macho.LoadDylib).Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[4]) + 1))
						lc.(*macho.LoadDylib).Name = args[4]
					}
				}
			case "LC_BUILD_VERSION":
				if len(args) < 8 {
					return fmt.Errorf("not enough arguments for adding %s; must supply PLATFORM, MINOS, SDK strings and TOOL, TOOL_VERSION strings", loadCommand)
				} else if len(args) > 8 {
					return fmt.Errorf("too many arguments for adding %s; NOTE you can only add one tool to a %s", loadCommand, loadCommand)
				}
				platform, err := types.GetPlatformByName(args[3])
				if err != nil {
					return fmt.Errorf("failed to parse tool name: %v", err)
				}
				var minos types.Version
				if err := minos.Set(args[4]); err != nil {
					return fmt.Errorf("failed to parse min OS version: %v", err)
				}
				var sdk types.Version
				if err := sdk.Set(args[5]); err != nil {
					return fmt.Errorf("failed to parse SDK version: %v", err)
				}
				tool, err := types.GetToolByName(args[6])
				if err != nil {
					return fmt.Errorf("failed to parse tool name: %v", err)
				}
				var toolVer types.Version
				if err := toolVer.Set(args[7]); err != nil {
					return fmt.Errorf("failed to parse tool version: %v", err)
				}
				lcbvs := m.GetLoadsByName(loadCommand)
				if len(lcbvs) == 0 {
					return fmt.Errorf("failed to find load command %s in %s", loadCommand, machoPath)
				} else if len(lcbvs) == 1 {
					lcbvs[0].(*macho.BuildVersion).Len = uint32(binary.Size(types.BuildVersionCmd{}) + binary.Size(types.BuildVersionTool{}))
					lcbvs[0].(*macho.BuildVersion).NumTools = 1
					lcbvs[0].(*macho.BuildVersion).Platform = platform
					lcbvs[0].(*macho.BuildVersion).Minos = minos
					lcbvs[0].(*macho.BuildVersion).Sdk = sdk
					lcbvs[0].(*macho.BuildVersion).Tools = []types.BuildVersionTool{
						{
							Tool:    tool,
							Version: toolVer,
						},
					}
				} else {
					return fmt.Errorf("found more than one load command %s in %s", loadCommand, machoPath)
				}
			case "LC_RPATH":
				if len(args) < 5 {
					return fmt.Errorf("not enough arguments for adding %s; must supply OLD_PATH NEW_PATH string", loadCommand)
				}
				lcrps := m.GetLoadsByName(loadCommand)
				if len(lcrps) == 0 {
					return fmt.Errorf("failed to find load command %s in %s", loadCommand, machoPath)
				}
				for _, lc := range lcrps {
					if lc.(*macho.Rpath).Path == args[3] {
						lc.(*macho.Rpath).Len = pointerAlign(uint32(binary.Size(types.RpathCmd{}) + len(args[4]) + 1))
						lc.(*macho.Rpath).Path = args[4]
					}
				}
			default:
				return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
			}
		}

		if len(output) == 0 {
			output = machoPath
		}

		if filepath.Clean(args[1]) == output {
			if !confirm(output, overwrite) { // confirm overwrite
				return nil
			}
		}

		if err := m.Save(output); err != nil {
			return fmt.Errorf("failed to save MachO file: %v", err)
		}

		log.Warn("Code signature has been invalidated (MachO may need to be re-signed)")

		return nil
	},
}
