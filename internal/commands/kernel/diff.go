package kernel

import (
	"fmt"
	"slices"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
)

// Diff compares two MH_FILESET kernelcache files
func Diff(k1, k2 *macho.File, conf *mcmd.DiffConfig) (*mcmd.MachoDiff, error) {
	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	/* PREVIOUS KERNEL */

	prev := make(map[string]*mcmd.DiffInfo)

	if k1.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fe := range k1.FileSets() {
			mfe, err := k1.GetFileSetFileByName(fe.EntryID)
			if err != nil {
				return nil, fmt.Errorf("failed to parse entry %s: %v", fe.EntryID, err)
			}
			prev[fe.EntryID] = mcmd.GenerateDiffInfo(mfe, conf)
		}
	}

	var prevFiles []string
	for f := range prev {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	/* NEXT KERNEL */

	next := make(map[string]*mcmd.DiffInfo)

	if k2.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fe := range k2.FileSets() {
			mfe, err := k2.GetFileSetFileByName(fe.EntryID)
			if err != nil {
				return nil, fmt.Errorf("failed to parse entry %s: %v", fe.EntryID, err)
			}
			next[fe.EntryID] = mcmd.GenerateDiffInfo(mfe, conf)
		}
	}

	var nextFiles []string
	for f := range next {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF KERNEL */

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
