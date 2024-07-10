package kernel

import (
	"fmt"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
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

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}
