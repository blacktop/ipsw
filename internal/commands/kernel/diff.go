package kernel

import (
	"fmt"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/signature"
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
			var smaps []signature.SymbolMap
			if conf.SymMap != nil {
				smap, ok := conf.SymMap[k1.UUID().String()]
				if !ok {
					return nil, fmt.Errorf("failed to find symbol map for kernelcache %s", k1.UUID().String())
				}
				smaps = append(smaps, smap)
			}
			prev[fe.EntryID] = mcmd.GenerateDiffInfo(mfe, conf, smaps...)
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
			var smaps []signature.SymbolMap
			if conf.SymMap != nil {
				smap, ok := conf.SymMap[k2.UUID().String()]
				if !ok {
					return nil, fmt.Errorf("failed to find symbol map for kernelcache %s", k2.UUID().String())
				}
				smaps = append(smaps, smap)
			}
			next[fe.EntryID] = mcmd.GenerateDiffInfo(mfe, conf, smaps...)
		}
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}
