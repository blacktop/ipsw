package macho

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
)

// MachO holds the result of opening a MachO file, handling both fat and regular files
type MachO struct {
	File    *macho.File    // The selected MachO file
	FatFile *macho.FatFile // The fat file (nil if not a fat file)
	FatArch *macho.FatArch // The selected architecture from fat file (nil if not a fat file)
}

// Close closes the underlying file(s). For fat files, only the fat file needs to be closed.
// For regular files, the individual file is closed.
func (mr *MachO) Close() error {
	if mr.FatFile != nil {
		return mr.FatFile.Close()
	}
	if mr.File != nil {
		return mr.File.Close()
	}
	return nil
}

// OpenMachO opens a MachO file and returns a MachOResult that handles cleanup properly.
// If the file is a fat binary and no arch is specified, it will prompt the user to select one.
// If arch is specified (e.g., "arm64", "x86_64"), it will try to find and return that architecture.
func OpenMachO(machoPath string, arch string) (*MachO, error) {
	return OpenMachONonInteractive(machoPath, arch, true)
}

// OpenMachONonInteractive opens a MachO file with the specified architecture and interactivity setting
func OpenMachONonInteractive(machoPath string, arch string, interactive bool) (*MachO, error) {
	// First try to open as fat file
	fat, err := macho.OpenFat(machoPath)
	if err != nil && err != macho.ErrNotFat {
		return nil, err
	}

	// If it's not a fat file, open as regular MachO
	if err == macho.ErrNotFat {
		file, err := macho.Open(machoPath)
		if err != nil {
			return nil, err
		}
		return &MachO{
			File:    file,
			FatFile: nil,
			FatArch: nil,
		}, nil
	}

	// It's a fat file - need to select an architecture
	var arches []string
	var shortArches []string
	for _, a := range fat.Arches {
		arches = append(arches, fmt.Sprintf("%s, %s", a.CPU, a.SubCPU.String(a.CPU)))
		shortArches = append(shortArches, strings.ToLower(a.SubCPU.String(a.CPU)))
	}

	var selectedIndex = -1

	// If arch is specified, try to find it
	if len(arch) > 0 {
		for i, opt := range shortArches {
			if strings.Contains(strings.ToLower(opt), strings.ToLower(arch)) {
				selectedIndex = i
				break
			}
		}
		if selectedIndex == -1 {
			if err := fat.Close(); err != nil {
				return nil, fmt.Errorf("failed to close fat file: %v (original error: --arch '%s' not found in: %s)", err, arch, strings.Join(shortArches, ", "))
			}
			return nil, fmt.Errorf("--arch '%s' not found in: %s", arch, strings.Join(shortArches, ", "))
		}
	} else if !interactive {
		// Return the first architecture if not interactive
		if len(fat.Arches) > 0 {
			selectedIndex = 0
		} else {
			if err := fat.Close(); err != nil {
				return nil, fmt.Errorf("failed to close fat file: %v (original error: no architectures found in fat file)", err)
			}
			return nil, fmt.Errorf("no architectures found in fat file")
		}
	} else if len(fat.Arches) == 1 {
		// If there's only one architecture, select it automatically
		selectedIndex = 0
	} else {
		// Prompt user to select
		choice := 0
		prompt := &survey.Select{
			Message: "Detected a universal MachO file, please select an architecture to analyze:",
			Options: arches,
		}
		if err := survey.AskOne(prompt, &choice); err != nil {
			if closeErr := fat.Close(); closeErr != nil {
				return nil, fmt.Errorf("failed to close fat file: %v (original error: %v)", closeErr, err)
			}
			if err == terminal.InterruptErr {
				fmt.Println("Exiting...")
				return nil, nil
			}
			return nil, fmt.Errorf("failed to get user selection: %v", err)
		}
		selectedIndex = choice
	}

	return &MachO{
		File:    fat.Arches[selectedIndex].File,
		FatFile: fat,
		FatArch: &fat.Arches[selectedIndex],
	}, nil
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
