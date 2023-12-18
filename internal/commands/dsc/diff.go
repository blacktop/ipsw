package dsc

import (
	"fmt"
	"slices"

	"github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
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
		prev[img.Name] = macho.GenerateDiffInfo(m)
	}

	var prevFiles []string
	for f := range prev {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	/* NEXT DSC */

	next := make(map[string]*macho.DiffInfo)

	for _, img := range f2.Images {
		m, err := img.GetMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to create MachO for image %s: %v", img.Name, err)
		}
		next[img.Name] = macho.GenerateDiffInfo(m)
	}

	var nextFiles []string
	for f := range next {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF DSC */

	diff.New = utils.Difference(nextFiles, prevFiles)
	diff.Removed = utils.Difference(prevFiles, nextFiles)
	// gc
	prevFiles = []string{}

	var err error
	for _, f2 := range nextFiles {
		dat2 := next[f2]
		if dat1, ok := prev[f2]; ok {
			if dat2.Equal(*dat1) {
				continue
			}
			var out string
			if conf.Markdown {
				out, err = utils.GitDiff(dat1.String()+"\n", dat2.String()+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return nil, err
				}
			} else {
				out, err = utils.GitDiff(dat1.String()+"\n", dat2.String()+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return nil, err
				}
			}
			if len(out) == 0 { // no diff
				continue
			}
			if conf.Markdown {
				diff.Updated[f2] = "```diff\n" + out + "\n```\n"
			} else {
				diff.Updated[f2] = out
			}
		}
	}

	return diff, nil
}
