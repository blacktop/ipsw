package macho

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
)

type DiffConfig struct {
	Markdown bool
	Color    bool
	DiffTool string
}

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

type section struct {
	Name string
	Size uint64
}

type Info struct {
	Version   string
	Imports   []string
	Sections  []section
	Symbols   int
	Functions int
}

func generateInfo(m *macho.File) *Info {
	var secs []section
	for _, s := range m.Sections {
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
	return &Info{
		Version:   sourceVersion,
		Imports:   m.ImportedLibraries(),
		Sections:  secs,
		Symbols:   len(m.Symtab.Syms),
		Functions: funcCount,
	}
}

// Equal checks if two Info structs are equal
func (i Info) Equal(x Info) bool {
	if i.Version == x.Version {
		return true
	}
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
	return true
}

func (i *Info) String() string {
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
func DiffIPSW(oldIPSW, newIPSW string, conf *DiffConfig) (string, error) {
	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	/* PREVIOUS IPSW */

	prev := make(map[string]*Info)

	if err := search.ForEachMachoInIPSW(oldIPSW, func(path string, m *macho.File) error {
		prev[path] = generateInfo(m)
		return nil
	}); err != nil {
		return "", fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	var prevFiles []string
	for f := range prev {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	/* NEXT IPSW */

	next := make(map[string]*Info)

	if err := search.ForEachMachoInIPSW(newIPSW, func(path string, m *macho.File) error {
		next[path] = generateInfo(m)
		return nil
	}); err != nil {
		return "", fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	var nextFiles []string
	for f := range next {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF IPSW */
	buf.WriteString("### 🆕 NEW\n\n")
	for _, df := range difference(nextFiles, prevFiles) {
		buf.WriteString(color.New(color.Bold).Sprintf(" - %s\n", df))
	}
	buf.WriteString("\n### ❌ Removed\n\n")
	for _, df := range difference(prevFiles, nextFiles) {
		buf.WriteString(color.New(color.Bold).Sprintf(" - %s\n", df))
	}
	// gc
	prevFiles = []string{}

	var err error
	var hasDiffs bool
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
					return "", err
				}
			} else {
				out, err = utils.GitDiff(dat1.String()+"\n", dat2.String()+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return "", err
				}
			}
			if len(out) == 0 { // no diff
				continue
			}
			hasDiffs = true
			if conf.Markdown {
				buf.WriteString(fmt.Sprintf("### %s\n\n> `%s`\n\n", filepath.Base(f2), f2))
				buf.WriteString("```diff\n" + out + "\n```\n")
			} else {
				buf.WriteString(color.New(color.Bold).Sprintf("\n%s\n", f2))
				buf.WriteString(out + "\n")
			}
		}
	}

	if !hasDiffs {
		buf.WriteString("- No differences found\n")
	}

	buf.Flush()

	return dat.String(), nil
}
