package macho

import (
	"fmt"
	"slices"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
)

type DiffConfig struct {
	Markdown bool
	Color    bool
	DiffTool string
	Filter   []string
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
	Symbols   int
	Functions int
}

func GenerateDiffInfo(m *macho.File, conf *DiffConfig) *DiffInfo {
	var secs []section
	for _, s := range m.Sections {
		if len(conf.Filter) > 0 {
			if !slices.Contains(conf.Filter, s.Seg+"."+s.Name) {
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
	var symCount int
	if m.Symtab != nil {
		symCount = len(m.Symtab.Syms)
	}
	return &DiffInfo{
		Version:   sourceVersion,
		Imports:   m.ImportedLibraries(),
		Sections:  secs,
		Symbols:   symCount,
		Functions: funcCount,
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
	if i.Symbols != x.Symbols {
		return false
	}
	if i.Functions != x.Functions {
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
	out += fmt.Sprintf("  Symbols:   %d\n", i.Symbols)
	out += fmt.Sprintf("  Functions: %d\n", i.Functions)
	return out
}

// DiffIPSW diffs two IPSW's MachOs
func DiffIPSW(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}

	/* PREVIOUS IPSW */

	prev := make(map[string]*DiffInfo)

	if err := search.ForEachMachoInIPSW(oldIPSW, func(path string, m *macho.File) error {
		prev[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	var prevFiles []string
	for f := range prev {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	/* NEXT IPSW */

	next := make(map[string]*DiffInfo)

	if err := search.ForEachMachoInIPSW(newIPSW, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	var nextFiles []string
	for f := range next {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF IPSW */
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

	var prevFiles []string
	for f := range prev {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	/* NEXT IPSW */

	next := make(map[string]*DiffInfo)

	if err := search.ForEachIm4pInIPSW(newIPSW, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	var nextFiles []string
	for f := range next {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF IPSW */
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
