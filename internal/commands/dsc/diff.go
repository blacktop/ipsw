package dsc

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// Diff compares two DSC files
func Diff(f1 *dyld.File, f2 *dyld.File, conf *macho.DiffConfig) (*macho.MachoDiff, error) {
	diff := &macho.MachoDiff{
		Updated: make(map[string]string),
	}

	/* PREVIOUS DSC */

	prev := make(map[string]*macho.DiffInfo)

	for _, img := range f1.Images {
		m, err := img.GetMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to create MachO for image %s: %v", img.Name, err)
		}
		prev[img.Name] = macho.GenerateDiffInfo(m, conf)
	}

	/* NEXT DSC */

	next := make(map[string]*macho.DiffInfo)

	for _, img := range f2.Images {
		m, err := img.GetMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to create MachO for image %s: %v", img.Name, err)
		}
		next[img.Name] = macho.GenerateDiffInfo(m, conf)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}
