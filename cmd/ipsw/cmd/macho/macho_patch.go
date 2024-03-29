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
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
 * ROADMAP:
 * - [x] add install_name_tool features
 * - [x] add vtool features
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
	"LC_ID_DYLINKER",
	"LC_LOAD_DYLINKER",
	"LC_DYLD_ENVIRONMENT",
}

func confirm(path string, overwrite bool) bool {
	if overwrite {
		return true
	}
	yes := false
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("You are about to overwrite %s. Continue?", path),
		Default: true,
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

func patchMacho(m *macho.File, machoPath, action, loadCommand string, args []string) error {
	switch action {
	case "add":
		log.Infof("Adding load command %s to %s", loadCommand, machoPath)
		switch loadCommand {
		case "LC_ID_DYLIB":
			m.FileHeader.Type = types.MH_DYLIB // set type to dylib
			/* TODO:
			 * Patch mach header so it is identified as a dylib instead of an executable and add MH_NO_REEXPORTED_DYLIBS flag
			 * Get rid of PAGEZERO since with it we can't load the dylib
			 * Add a LC_ID_DYLIB command where PAGEZERO previously was to identify the dylib
			 * Patch opcodes: Since we got rid of PAGEZERO we have one less segment thus we need to patch whatever is referencing to SEGMENT X to SEGMENT X-1.
			 */
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
					Timestamp:      2, // TODO: I've only seen this value be 2
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
			if len(args) < 6 {
				return fmt.Errorf("not enough arguments for modding %s; must supply at least PLATFORM, MINOS and SDK strings", loadCommand)
			} else if len(args) > 6 {
				if ((len(args) - 6) % 2) != 0 {
					return fmt.Errorf("when adding tools to %s; ensure you supply both TOOL and TOOL_VERSION strings", loadCommand)
				}
			}
			platform, err := types.GetPlatformByName(args[3])
			if err != nil {
				return fmt.Errorf("failed to parse platform name %s: %v", args[3], err)
			}
			var minos types.Version
			if err := minos.Set(args[4]); err != nil {
				return fmt.Errorf("failed to parse min OS version: %v", err)
			}
			var sdk types.Version
			if err := sdk.Set(args[5]); err != nil {
				return fmt.Errorf("failed to parse SDK version: %v", err)
			}
			var tools []types.BuildVersionTool
			if len(args) > 6 {
				for i := 6; i < len(args); i += 2 {
					tool, err := types.GetToolByName(args[i])
					if err != nil {
						return fmt.Errorf("failed to parse tool name %s: %v", args[i], err)
					}
					var toolVer types.Version
					if err := toolVer.Set(args[i+1]); err != nil {
						return fmt.Errorf("failed to parse tool version %s: %v", args[i+1], err)
					}
					tools = append(tools, types.BuildVersionTool{Tool: tool, Version: toolVer})
				}
			}
			m.AddLoad(&macho.BuildVersion{
				BuildVersionCmd: types.BuildVersionCmd{
					LoadCmd:  types.LC_BUILD_VERSION,
					Len:      uint32(binary.Size(types.BuildVersionCmd{}) + len(tools)*binary.Size(types.BuildVersionTool{})),
					Platform: platform,
					Minos:    minos,
					Sdk:      sdk,
					NumTools: uint32(len(tools)),
				},
				Tools: tools,
			})
		case "LC_ID_DYLINKER", "LC_LOAD_DYLINKER", "LC_DYLD_ENVIRONMENT":
			var lc types.LoadCmd
			var name string
			switch loadCommand {
			case "LC_ID_DYLINKER":
				if len(args) < 4 {
					return fmt.Errorf("not enough arguments for setting %s; must supply ID name", loadCommand)
				}
				lc = types.LC_ID_DYLINKER
				name = args[3]
			case "LC_LOAD_DYLINKER":
				if len(args) < 4 {
					return fmt.Errorf("not enough arguments for setting %s; must supply PATH string", loadCommand)
				}
				lc = types.LC_LOAD_DYLINKER
				name = args[3]
			case "LC_DYLD_ENVIRONMENT":
				if m.FileHeader.Type != types.MH_EXECUTE {
					return fmt.Errorf("you can only modify LC_DYLD_ENVIRONMENT in a main binary")
				}
				if len(args) < 5 {
					return fmt.Errorf("not enough arguments for setting %s; must supply ENV_VAR name, and VALUE strings", loadCommand)
				}
				lc = types.LC_DYLD_ENVIRONMENT
				name = args[3] + "=" + args[4]
			}
			m.AddLoad(&macho.Dylinker{
				DylinkerCmd: types.DylinkerCmd{
					LoadCmd:    lc,
					Len:        pointerAlign(uint32(binary.Size(types.DylinkerCmd{}) + len(name) + 1)),
					NameOffset: 0xc,
				},
				Name: name,
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
		case "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_RPATH":
			if len(args) < 4 {
				return fmt.Errorf("not enough arguments for removing %s; must supply PATH string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if lc.(*macho.Dylib).Name == args[3] {
					if err := m.RemoveLoad(lc); err != nil {
						return fmt.Errorf("failed to remove load command: %v", err)
					}
				}
			}
		case "LC_BUILD_VERSION":
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			} else if len(lcs) > 1 { // FIXME: can we have multiple LC_BUILD_VERSION(s)?
				return fmt.Errorf("found multiple %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if err := m.RemoveLoad(lc); err != nil {
					return fmt.Errorf("failed to remove load command: %v", err)
				}
			}
		case "LC_ID_DYLINKER":
			if m.FileHeader.Type == types.MH_DYLINKER {
				m.FileHeader.Type = types.MH_EXECUTE
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if err := m.RemoveLoad(lc); err != nil {
					return fmt.Errorf("failed to remove load command: %v", err)
				}
			}
		case "LC_LOAD_DYLINKER":
			if len(args) < 4 {
				return fmt.Errorf("not enough arguments for removing %s; must supply PATH string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if lc.(*macho.LoadDylinker).Name == args[3] {
					if err := m.RemoveLoad(lc); err != nil {
						return fmt.Errorf("failed to remove load command: %v", err)
					}
				}
			}
		case "LC_DYLD_ENVIRONMENT":
			if len(args) < 4 {
				return fmt.Errorf("not enough arguments for removing %s; must supply ENV_VAR string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if strings.Split(lc.(*macho.DyldEnvironment).Name, "=")[0] == args[3] {
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
				return fmt.Errorf("you can only modify %s in a dylib", loadCommand)
			}
			if len(args) < 4 {
				return fmt.Errorf("not enough arguments for setting %s; must supply ID string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			} else if len(lcs) > 1 {
				return fmt.Errorf("found multiple %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				prevLen := int32(lc.(*macho.IDDylib).Len)
				lc.(*macho.IDDylib).Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[3]) + 1))
				lc.(*macho.IDDylib).Name = args[3]
				m.ModifySizeCommands(prevLen, int32(lc.(*macho.IDDylib).Len))
			}
		case "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB":
			if len(args) < 5 {
				return fmt.Errorf("not enough arguments for setting %s; must supply OLD and NEW strings", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				switch c := lc.(type) {
				case *macho.LoadDylib:
					if c.Name != args[3] {
						continue
					}
					prevLen := int32(c.Len)
					c.Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[4]) + 1))
					c.Name = args[4]
					m.ModifySizeCommands(prevLen, int32(c.Len))
				case *macho.WeakDylib:
					if c.Name != args[3] {
						continue
					}
					prevLen := int32(c.Len)
					c.Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[4]) + 1))
					c.Name = args[4]
					m.ModifySizeCommands(prevLen, int32(c.Len))
				case *macho.ReExportDylib:
					if c.Name != args[3] {
						continue
					}
					prevLen := int32(c.Len)
					c.Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[4]) + 1))
					c.Name = args[4]
					m.ModifySizeCommands(prevLen, int32(c.Len))
				case *macho.LazyLoadDylib:
					if c.Name != args[3] {
						continue
					}
					prevLen := int32(c.Len)
					c.Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[4]) + 1))
					c.Name = args[4]
					m.ModifySizeCommands(prevLen, int32(c.Len))
				case *macho.UpwardDylib:
					if c.Name != args[3] {
						continue
					}
					prevLen := int32(c.Len)
					c.Len = pointerAlign(uint32(binary.Size(types.DylibCmd{}) + len(args[4]) + 1))
					c.Name = args[4]
					m.ModifySizeCommands(prevLen, int32(c.Len))
				default:
					return fmt.Errorf("failed to modify load command %s in %s", loadCommand, machoPath)
				}
			}
		case "LC_BUILD_VERSION":
			if len(args) < 6 {
				return fmt.Errorf("not enough arguments for modding %s; must supply at least PLATFORM, MINOS and SDK strings", loadCommand)
			} else if len(args) > 6 {
				if ((len(args) - 6) % 2) != 0 {
					return fmt.Errorf("when adding tools to %s; ensure you supply both TOOL and TOOL_VERSION strings", loadCommand)
				}
			}
			platform, err := types.GetPlatformByName(args[3])
			if err != nil {
				return fmt.Errorf("failed to parse platform name %s: %v", args[3], err)
			}
			var minos types.Version
			if err := minos.Set(args[4]); err != nil {
				return fmt.Errorf("failed to parse min OS version: %v", err)
			}
			var sdk types.Version
			if err := sdk.Set(args[5]); err != nil {
				return fmt.Errorf("failed to parse SDK version: %v", err)
			}
			var tools []types.BuildVersionTool
			if len(args) > 6 {
				for i := 6; i < len(args); i += 2 {
					tool, err := types.GetToolByName(args[i])
					if err != nil {
						return fmt.Errorf("failed to parse tool name %s: %v", args[i], err)
					}
					var toolVer types.Version
					if err := toolVer.Set(args[i+1]); err != nil {
						return fmt.Errorf("failed to parse tool version %s: %v", args[i+1], err)
					}
					tools = append(tools, types.BuildVersionTool{Tool: tool, Version: toolVer})
				}
			}
			lcbvs := m.GetLoadsByName(loadCommand)
			if len(lcbvs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			} else if len(lcbvs) == 1 {
				prevLen := int32(lcbvs[0].(*macho.BuildVersion).Len)
				lcbvs[0].(*macho.BuildVersion).Len = uint32(binary.Size(types.BuildVersionCmd{}) + len(tools)*binary.Size(types.BuildVersionTool{}))
				lcbvs[0].(*macho.BuildVersion).Platform = platform
				lcbvs[0].(*macho.BuildVersion).Minos = minos
				lcbvs[0].(*macho.BuildVersion).Sdk = sdk
				lcbvs[0].(*macho.BuildVersion).NumTools = uint32(len(tools))
				lcbvs[0].(*macho.BuildVersion).Tools = tools
				m.ModifySizeCommands(prevLen, int32(lcbvs[0].(*macho.BuildVersion).Len)) // should be 0
			} else {
				return fmt.Errorf("found more than one load command %s in %s", loadCommand, machoPath)
			}
		case "LC_RPATH":
			if len(args) < 5 {
				return fmt.Errorf("not enough arguments for adding %s; must supply OLD_PATH NEW_PATH string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if lc.(*macho.Rpath).Path == args[3] {
					prevLen := int32(lc.(*macho.Rpath).Len)
					lc.(*macho.Rpath).Len = pointerAlign(uint32(binary.Size(types.RpathCmd{}) + len(args[4]) + 1))
					lc.(*macho.Rpath).Path = args[4]
					m.ModifySizeCommands(prevLen, int32(lc.(*macho.Rpath).Len))
				}
			}
		case "LC_ID_DYLINKER":
			if len(args) < 4 {
				return fmt.Errorf("not enough arguments for setting %s; must supply PATH string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			} else if len(lcs) > 1 {
				return fmt.Errorf("found more than one %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				prevLen := int32(lc.(*macho.DylinkerID).Len)
				lc.(*macho.DylinkerID).Len = pointerAlign(uint32(binary.Size(types.DylinkerCmd{}) + len(args[3]) + 1))
				lc.(*macho.DylinkerID).Name = args[3]
				m.ModifySizeCommands(prevLen, int32(lc.(*macho.DylinkerID).Len))
			}
		case "LC_LOAD_DYLINKER":
			if len(args) < 5 {
				return fmt.Errorf("not enough arguments for setting %s; must supply OLD_PATH and NEW_PATH string", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to find %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if lc.(*macho.LoadDylinker).Name == args[3] {
					prevLen := int32(lc.(*macho.LoadDylinker).Len)
					lc.(*macho.LoadDylinker).Len = pointerAlign(uint32(binary.Size(types.DylinkerCmd{}) + len(args[4]) + 1))
					lc.(*macho.LoadDylinker).Name = args[4]
					m.ModifySizeCommands(prevLen, int32(lc.(*macho.LoadDylinker).Len))
				}
			}
		case "LC_DYLD_ENVIRONMENT":
			if m.FileHeader.Type != types.MH_EXECUTE {
				return fmt.Errorf("you can only modify %s in a main binary", loadCommand)
			}
			if len(args) < 5 {
				return fmt.Errorf("not enough arguments for setting %s; must supply ENV_VAR and NEW_VALUE strings", loadCommand)
			}
			lcs := m.GetLoadsByName(loadCommand)
			if len(lcs) == 0 {
				return fmt.Errorf("failed to %s in %s", loadCommand, machoPath)
			}
			for _, lc := range lcs {
				if strings.Split(lc.(*macho.DyldEnvironment).Name, "=")[0] == args[3] {
					prevLen := int32(lc.(*macho.DyldEnvironment).Len)
					lc.(*macho.DyldEnvironment).Len = pointerAlign(uint32(binary.Size(types.DylinkerCmd{}) + len(args[4]) + 1))
					lc.(*macho.DyldEnvironment).Name = args[4]
					m.ModifySizeCommands(prevLen, int32(lc.(*macho.DyldEnvironment).Len))
				}
			}
		default:
			return fmt.Errorf("unsupported load command for action '%s': %s", action, loadCommand)
		}
	}
	return nil
}

func init() {
	MachoCmd.AddCommand(machoPatchCmd)
	machoPatchCmd.Flags().BoolP("overwrite", "f", false, "Overwrite file")
	machoPatchCmd.Flags().BoolP("re-sign", "s", false, "Adhoc sign file")
	machoPatchCmd.Flags().StringP("output", "o", "", "Output new file")
	viper.BindPFlag("macho.patch.overwrite", machoPatchCmd.Flags().Lookup("overwrite"))
	viper.BindPFlag("macho.patch.re-sign", machoPatchCmd.Flags().Lookup("re-sign"))
	viper.BindPFlag("macho.patch.output", machoPatchCmd.Flags().Lookup("output"))
}

// machoPatchCmd represents the patch command
var machoPatchCmd = &cobra.Command{
	Use:     "patch [add|rm|mod] <MACHO> <LC> <LC_FIELDS...>",
	Aliases: []string{"p"},
	Short:   "Patch MachO Load Commands",
	Example: `  # Modify LC_BUILD_VERSION like vtool
  ❯ ipsw macho patch mod MACHO LC_BUILD_VERSION iOS 16.3 16.3 ld 820.1
  # Add an LC_RPATH like install_name_tool
  ❯ ipsw macho patch add MACHO LC_RPATH @executable_path/Frameworks`,
	Args:          cobra.MinimumNArgs(3),
	SilenceUsage:  true,
	SilenceErrors: true,
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
		color.NoColor = viper.GetBool("no-color")

		// flags
		overwrite := viper.GetBool("macho.patch.overwrite")
		reSign := viper.GetBool("macho.patch.re-sign")
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
				if err := patchMacho(arch.File, fmt.Sprintf("%s (%s slice)", machoPath, arch.File.CPU.String()), action, loadCommand, args); err != nil {
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
				if err := patchMacho(m, machoPath, action, loadCommand, args); err != nil {
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
