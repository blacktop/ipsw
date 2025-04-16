package dsc

import (
	"github.com/apex/log"

	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// Diff compares two DSC files
func Diff(f1 *dyld.File, f2 *dyld.File, conf *mcmd.DiffConfig) (*mcmd.MachoDiff, error) {
	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	/* PREVIOUS DSC */

	prev := make(map[string]*mcmd.DiffInfo)

	for _, img := range f1.Images {
		m, err := img.GetMacho()
		if err != nil {
			// return nil, fmt.Errorf("failed to create MachO for image %s: %v", img.Name, err)
			log.Errorf("failed to parse MachO for image %s: %v", img.Name, err)
			continue
		}
		// add private symbols to the macho
		if err := img.ParseLocalSymbols(false); err == nil {
			for _, lsym := range img.LocalSymbols {
				m.Symtab.Syms = append(m.Symtab.Syms, macho.Symbol{
					Name:  lsym.Name,
					Value: lsym.Value,
					Type:  lsym.Type,
					Desc:  lsym.Desc,
					Sect:  lsym.Sect,
				})
			}
		}
		prev[img.Name] = mcmd.GenerateDiffInfo(m, conf)
	}

	/* NEXT DSC */

	next := make(map[string]*mcmd.DiffInfo)

	for _, img := range f2.Images {
		m, err := img.GetMacho()
		if err != nil {
			// return nil, fmt.Errorf("failed to create MachO for image %s: %v", img.Name, err)
			log.Errorf("failed to parse MachO for image %s: %v", img.Name, err)
			continue
		}
		// add private symbols to the macho
		if err := img.ParseLocalSymbols(false); err == nil {
			for _, lsym := range img.LocalSymbols {
				m.Symtab.Syms = append(m.Symtab.Syms, macho.Symbol{
					Name:  lsym.Name,
					Value: lsym.Value,
					Type:  lsym.Type,
					Desc:  lsym.Desc,
					Sect:  lsym.Sect,
				})
			}
		}
		next[img.Name] = mcmd.GenerateDiffInfo(m, conf)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}
