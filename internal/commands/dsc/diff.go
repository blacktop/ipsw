package dsc

import (
	"sort"

	"github.com/apex/log"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// Diff compares two DSC files
func Diff(f1 *dyld.File, f2 *dyld.File, conf *mcmd.DiffConfig) (*mcmd.MachoDiff, error) {
	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	// Build name->image lookup tables (cheap) so we can diff without
	// materializing DiffInfo for every image at once.
	prev := make(map[string]*dyld.CacheImage, len(f1.Images))
	var prevKeys []string
	for _, img := range f1.Images {
		prev[img.Name] = img
		prevKeys = append(prevKeys, img.Name)
	}
	next := make(map[string]*dyld.CacheImage, len(f2.Images))
	var nextKeys []string
	for _, img := range f2.Images {
		next[img.Name] = img
		nextKeys = append(nextKeys, img.Name)
	}

	sort.Strings(prevKeys)
	sort.Strings(nextKeys)

	diff.New = utils.Difference(nextKeys, prevKeys)
	diff.Removed = utils.Difference(prevKeys, nextKeys)
	// Keep output stable for callers
	sort.Strings(diff.New)
	sort.Strings(diff.Removed)

	for _, name := range nextKeys {
		img1, ok := prev[name]
		if !ok {
			continue
		}
		img2 := next[name]

		m1, err := img1.GetMacho()
		if err != nil {
			log.Errorf("failed to parse MachO for image %s: %v", img1.Name, err)
			continue
		}

		m2, err := img2.GetMacho()
		if err != nil {
			log.Errorf("failed to parse MachO for image %s: %v", img2.Name, err)
			if m1 != nil {
				m1.Close()
			}
			continue
		}

		// Parse local/private symbols for better symbol identity when available
		if err := img1.ParseLocalSymbols(false); err != nil {
			// non-fatal: continue using whatever public symbols we have
			log.Debugf("failed to parse local symbols for image %s: %v", img1.Name, err)
		} else {
			if m1 != nil && m1.Symtab != nil {
				m1.Symtab.Syms = append(m1.Symtab.Syms, img1.GetLocalSymbolsAsMachoSymbols()...)
			}
		}
		if err := img2.ParseLocalSymbols(false); err != nil {
			log.Debugf("failed to parse local symbols for image %s: %v", img2.Name, err)
		} else {
			if m2 != nil && m2.Symtab != nil {
				m2.Symtab.Syms = append(m2.Symtab.Syms, img2.GetLocalSymbolsAsMachoSymbols()...)
			}
		}

		info1 := mcmd.GenerateDiffInfo(m1, conf)
		info2 := mcmd.GenerateDiffInfo(m2, conf)
		if info2.Equal(*info1) {
			if m1 != nil {
				m1.Close()
			}
			if m2 != nil {
				m2.Close()
			}
			continue
		}

		out, err := mcmd.FormatUpdatedDiff(info1, info2, conf)
		if err != nil {
			if m1 != nil {
				m1.Close()
			}
			if m2 != nil {
				m2.Close()
			}
			return nil, err
		}
		if out != "" {
			diff.Updated[name] = out
		}

		if m1 != nil {
			m1.Close()
		}
		if m2 != nil {
			m2.Close()
		}
	}

	return diff, nil
}
