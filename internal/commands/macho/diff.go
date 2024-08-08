package macho

import (
	"fmt"
	"slices"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"golang.org/x/exp/maps"
)

type DiffConfig struct {
	Markdown  bool
	Color     bool
	DiffTool  string
	AllowList []string
	BlockList []string
	CStrings  bool
	PemDB     string
}

type MachoDiff struct {
	New     []string          `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"updated,omitempty"`
}

type section struct {
	Name string `json:"name,omitempty"`
	Size uint64 `json:"size,omitempty"`
}

type DiffInfo struct {
	Version   string
	Imports   []string
	Sections  []section
	Functions int
	Symbols   []string
	CStrings  []string
}

func GenerateDiffInfo(m *macho.File, conf *DiffConfig) *DiffInfo {
	var secs []section
	for _, s := range m.Sections {
		if len(conf.AllowList) > 0 {
			if !slices.Contains(conf.AllowList, s.Seg+"."+s.Name) {
				continue
			}
		}
		if len(conf.BlockList) > 0 {
			if slices.Contains(conf.BlockList, s.Seg+"."+s.Name) {
				continue
			}
		}
		secs = append(secs, section{
			Name: s.Seg + "." + s.Name,
			Size: s.Size,
		})
	}
	funcCount := 0
	if fns := m.GetFunctions(); fns != nil {
		funcCount = len(fns)
	}
	var sourceVersion string
	if m.SourceVersion() != nil {
		sourceVersion = m.SourceVersion().Version.String()
	}
	var syms []string
	// TODO: handle private symbols from DSC images
	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			syms = append(syms, sym.Name)
		}
		slices.Sort(syms)
	}
	var strs []string
	if conf.CStrings {
		if cs, err := m.GetCStrings(); err == nil {
			for _, val := range cs {
				str2addr := maps.Keys(val)
				strs = append(strs, str2addr...)
			}
			slices.Sort(strs)
		}
	}
	return &DiffInfo{
		Version:   sourceVersion,
		Imports:   m.ImportedLibraries(),
		Sections:  secs,
		Functions: funcCount,
		Symbols:   syms,
		CStrings:  strs,
	}
}

// Equal checks if two Info structs are equal
func (i DiffInfo) Equal(x DiffInfo) bool {
	if len(i.Imports) != len(x.Imports) {
		return false
	}
	for i, imp := range i.Imports {
		if imp != x.Imports[i] {
			return false
		}
	}
	if len(i.Sections) != len(x.Sections) {
		return false
	}
	for i, sec := range i.Sections {
		if sec != x.Sections[i] {
			return false
		}
	}
	if i.Functions != x.Functions {
		return false
	}
	if len(i.Symbols) != len(x.Symbols) {
		return false
	}
	// if i.Version != x.Version { (this could be a lie)
	// 	return false
	// }
	return true
}

func (i *DiffInfo) String() string {
	out := i.Version + "\n"
	for _, sec := range i.Sections {
		out += fmt.Sprintf("  %s: %#x\n", sec.Name, sec.Size)
	}
	slices.Sort(i.Imports)
	for _, i := range i.Imports {
		out += fmt.Sprintf("  - %s\n", i)
	}
	out += fmt.Sprintf("  Functions: %d\n", i.Functions)
	out += fmt.Sprintf("  Symbols:   %d\n", len(i.Symbols))
	out += fmt.Sprintf("  CStrings:  %d\n", len(i.CStrings))
	return out
}

func (diff *MachoDiff) Generate(prev, next map[string]*DiffInfo, conf *DiffConfig) error {

	var prevFiles []string
	for f := range prev {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	var nextFiles []string
	for f := range next {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF IPSW */
	diff.New = utils.Difference(nextFiles, prevFiles)
	diff.Removed = utils.Difference(prevFiles, nextFiles)

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
					return err
				}
			} else {
				out, err = utils.GitDiff(dat1.String()+"\n", dat2.String()+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return err
				}
			}
			if len(out) == 0 { // no diff
				continue
			}
			if conf.Markdown {
				diff.Updated[f2] = "```diff\n" + out
			} else {
				diff.Updated[f2] = out
			}

			/* DIFF Symbols */
			newSyms := utils.Difference(dat2.Symbols, dat1.Symbols)
			rmSyms := utils.Difference(dat1.Symbols, dat2.Symbols)
			if len(newSyms) > 0 || len(rmSyms) > 0 {
				diff.Updated[f2] += "Symbols:\n"
				for _, s := range newSyms {
					diff.Updated[f2] += fmt.Sprintf("+ %s\n", s)
				}
				for _, s := range rmSyms {
					diff.Updated[f2] += fmt.Sprintf("- %s\n", s)
				}
			}

			/* DIFF CStrings */
			if conf.CStrings {
				newStrs := utils.Difference(dat2.CStrings, dat1.CStrings)
				rmStrs := utils.Difference(dat1.CStrings, dat2.CStrings)
				if len(newStrs) > 0 || len(rmStrs) > 0 {
					diff.Updated[f2] += "CStrings:\n"
					for _, s := range newStrs {
						diff.Updated[f2] += fmt.Sprintf("+ %#v\n", s)
					}
					for _, s := range rmStrs {
						diff.Updated[f2] += fmt.Sprintf("- %#v\n", s)
					}
				}
			}

			if conf.Markdown {
				diff.Updated[f2] += "\n```\n"
			}
		}
	}

	return nil
}

// DiffIPSW diffs two IPSW's MachOs
func DiffIPSW(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}

	/* PREVIOUS IPSW */

	prev := make(map[string]*DiffInfo)

	if err := search.ForEachMachoInIPSW(oldIPSW, conf.PemDB, func(path string, m *macho.File) error {
		prev[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	/* NEXT IPSW */

	next := make(map[string]*DiffInfo)

	if err := search.ForEachMachoInIPSW(newIPSW, conf.PemDB, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}

// DiffFirmwares diffs two IPSW's im4p firmware MachOs
func DiffFirmwares(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}

	/* PREVIOUS IPSW */

	prev := make(map[string]*DiffInfo)

	if err := search.ForEachIm4pInIPSW(oldIPSW, func(path string, m *macho.File) error {
		prev[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	/* NEXT IPSW */

	next := make(map[string]*DiffInfo)

	if err := search.ForEachIm4pInIPSW(newIPSW, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}
