package macho

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
)

// FatConfig contains configuration options for opening fat/universal MachO files
type FatConfig struct {
	Arch        string            // Architecture to select (e.g., "arm64", "x86_64")
	Interactive bool              // Whether to prompt user for architecture selection
	FatFile     **macho.FatFile   // Optional: if provided, the fat file will be stored here (caller must close it)
	FatArch     **macho.FatArch   // Optional: if provided, the selected FatArch will be stored here
}

// OpenFatMachO opens a MachO file, handling both regular and fat/universal binaries.
// If the file is a fat binary and no arch is specified, it will prompt the user to select one.
// If arch is specified (e.g., "arm64", "x86_64"), it will try to find and return that architecture.
func OpenFatMachO(machoPath string, arch string) (*macho.File, error) {
	return OpenFatMachOWithConfig(machoPath, &FatConfig{
		Arch:        arch,
		Interactive: true,
	})
}

// OpenFatMachOWithConfig opens a MachO file with custom configuration options
func OpenFatMachOWithConfig(machoPath string, config *FatConfig) (*macho.File, error) {
	if config == nil {
		config = &FatConfig{Interactive: true}
	}

	// First try to open as fat file
	fat, err := macho.OpenFat(machoPath)
	if err != nil && err != macho.ErrNotFat {
		return nil, err
	}

	// If it's not a fat file, open as regular MachO
	if err == macho.ErrNotFat {
		return macho.Open(machoPath)
	}

	// It's a fat file - need to select an architecture
	// If caller wants to keep the fat file open, store it
	if config.FatFile != nil {
		*config.FatFile = fat
	} else {
		// Otherwise ensure it gets closed when we're done
		defer fat.Close()
	}

	var arches []string
	var shortArches []string
	for _, a := range fat.Arches {
		arches = append(arches, fmt.Sprintf("%s, %s", a.CPU, a.SubCPU.String(a.CPU)))
		shortArches = append(shortArches, strings.ToLower(a.SubCPU.String(a.CPU)))
	}

	var selectedIndex int = -1
	
	// If arch is specified, try to find it
	if len(config.Arch) > 0 {
		for i, opt := range shortArches {
			if strings.Contains(strings.ToLower(opt), strings.ToLower(config.Arch)) {
				selectedIndex = i
				break
			}
		}
		if selectedIndex == -1 {
			return nil, fmt.Errorf("--arch '%s' not found in: %s", config.Arch, strings.Join(shortArches, ", "))
		}
	} else if !config.Interactive {
		// Return the first architecture if not interactive
		if len(fat.Arches) > 0 {
			selectedIndex = 0
		} else {
			return nil, fmt.Errorf("no architectures found in fat file")
		}
	} else {
		// Prompt user to select
		choice := 0
		prompt := &survey.Select{
			Message: "Detected a universal MachO file, please select an architecture to analyze:",
			Options: arches,
		}
		if err := survey.AskOne(prompt, &choice); err != nil {
			if err == terminal.InterruptErr {
				fmt.Println("Exiting...")
				return nil, nil
			}
			return nil, fmt.Errorf("failed to get user selection: %v", err)
		}
		selectedIndex = choice
	}

	// Store the selected FatArch if requested
	if config.FatArch != nil {
		*config.FatArch = &fat.Arches[selectedIndex]
	}

	return fat.Arches[selectedIndex].File, nil
}

func FindSwiftStrings(m *macho.File) (map[uint64]string, error) {
	text := m.Section("__TEXT", "__text")
	if text == nil {
		return nil, fmt.Errorf("no __TEXT.__text section found")
	}

	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get __TEXT.__text data: %v", err)
	}

	engine := disass.NewMachoDisass(m, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
		Middle:       text.Addr + text.Size,
	})

	return engine.FindSwiftStrings()
}
