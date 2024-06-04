package macho

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func pointerAlign(sz uint32) uint32 {
	if (sz % 8) != 0 {
		sz += 8 - (sz % 8)
	}
	return sz
}

func PatchMachoAdd(m *macho.File, machoPath, loadCommand string, args []string) error {
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
		return fmt.Errorf("unsupported load command: %s", loadCommand)
	}
	return nil
}

func PatchMachoRm(m *macho.File, machoPath, loadCommand string, args []string) error {
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
		return fmt.Errorf("unsupported load command: %s", loadCommand)
	}
	return nil
}

func PatchMachoMod(m *macho.File, machoPath, loadCommand string, args []string) error {
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
		return fmt.Errorf("unsupported load command: %s", loadCommand)
	}
	return nil
}
