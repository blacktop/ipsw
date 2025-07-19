package macho

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/signature"
)

type DiffConfig struct {
	Markdown   bool
	Color      bool
	DiffTool   string
	AllowList  []string
	BlockList  []string
	CStrings   bool
	FuncStarts bool
	PemDB      string
	SymMap     map[string]signature.SymbolMap
	Verbose    bool
	// Function matching tuning parameters
	FuncMatchNameWeight     float64 // Weight for name matching (default 0.5)
	FuncMatchSizeWeight     float64 // Weight for size matching (default 0.3)
	FuncMatchPositionWeight float64 // Weight for position proximity (default 0.2)
	FuncMatchMinConfidence  float64 // Minimum confidence to consider a match (default 0.3)
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
	UUID      string
	Imports   []string
	Sections  []section
	Functions int
	Starts    []types.Function
	Symbols   []string
	CStrings  []string
	SymbolMap map[uint64]string
	Verbose   bool
}

func GenerateDiffInfo(m *macho.File, conf *DiffConfig, smaps ...signature.SymbolMap) *DiffInfo {
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
	var starts []types.Function
	if fns := m.GetFunctions(); fns != nil {
		starts = fns
	}
	var sourceVersion string
	if m.SourceVersion() != nil {
		sourceVersion = m.SourceVersion().Version.String()
	}
	var uuidStr string
	if m.UUID() != nil {
		uuidStr = m.UUID().String()
	}
	smap := make(map[uint64]string)
	if len(smaps) > 0 {
		maps.Copy(smap, smaps[0])
	}
	var syms []string
	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			syms = append(syms, sym.Name)
			if conf.FuncStarts {
				if len(sym.Name) != 0 && sym.Name != "<redacted>" {
					smap[sym.Value] = sym.Name
				}
			}
		}
		slices.Sort(syms)
	}
	var strs []string
	if conf.CStrings {
		if cs, err := m.GetCStrings(); err == nil {
			for _, val := range cs {
				str2addr := slices.Collect(maps.Keys(val))
				strs = append(strs, str2addr...)
			}
			slices.Sort(strs)
		}
		if cfstrs, err := m.GetCFStrings(); err == nil {
			for _, val := range cfstrs {
				strs = append(strs, val.Name)
			}
			slices.Sort(strs)
		}
	}
	return &DiffInfo{
		Version:   sourceVersion,
		UUID:      uuidStr,
		Imports:   m.ImportedLibraries(),
		Sections:  secs,
		Functions: len(starts),
		Starts:    starts,
		Symbols:   syms,
		CStrings:  strs,
		SymbolMap: smap,
		Verbose:   conf.Verbose,
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
	if i.Verbose && x.Verbose {
		if i.Version != x.Version { // (this could be a lie)
			return false
		}
		if i.UUID != x.UUID {
			return false
		}
	}
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
	out += fmt.Sprintf("  UUID: %s\n", i.UUID)
	out += fmt.Sprintf("  Functions: %d\n", i.Functions)
	out += fmt.Sprintf("  Symbols:   %d\n", len(i.Symbols))
	out += fmt.Sprintf("  CStrings:  %d\n", len(i.CStrings))
	return out
}

func (diff *MachoDiff) Generate(prev, next map[string]*DiffInfo, conf *DiffConfig) error {

	/* DIFF IPSW */
	diff.New = utils.Difference(slices.Collect(maps.Keys(next)), slices.Collect(maps.Keys(prev)))
	diff.Removed = utils.Difference(slices.Collect(maps.Keys(prev)), slices.Collect(maps.Keys(next)))

	var err error
	for _, currentFileKey := range slices.Sorted(maps.Keys(next)) {
		dat2 := next[currentFileKey]
		if dat1, ok := prev[currentFileKey]; ok {
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
				diff.Updated[currentFileKey] = "```diff\n" + out
			} else {
				diff.Updated[currentFileKey] = out
			}

			/* DIFF Symbols */
			newSyms := utils.Difference(dat2.Symbols, dat1.Symbols)
			sort.Strings(newSyms)
			rmSyms := utils.Difference(dat1.Symbols, dat2.Symbols)
			sort.Strings(rmSyms)
			if len(newSyms) > 0 || len(rmSyms) > 0 {
				diff.Updated[currentFileKey] += "Symbols:\n"
				for _, s := range newSyms {
					diff.Updated[currentFileKey] += fmt.Sprintf("+ %s\n", s)
				}
				for _, s := range rmSyms {
					diff.Updated[currentFileKey] += fmt.Sprintf("- %s\n", s)
				}
			}

			/* DIFF Functions */
			if conf.FuncStarts {
				funcs1 := dat1.Starts
				funcs2 := dat2.Starts

				// Use the new function matcher
				matcher := NewFunctionMatcher(dat1.SymbolMap, dat2.SymbolMap)

				// Apply custom tuning if specified
				if conf.FuncMatchNameWeight > 0 {
					matcher.NameWeight = conf.FuncMatchNameWeight
				}
				if conf.FuncMatchSizeWeight > 0 {
					matcher.SizeWeight = conf.FuncMatchSizeWeight
				}
				if conf.FuncMatchPositionWeight > 0 {
					matcher.PositionWeight = conf.FuncMatchPositionWeight
				}
				if conf.FuncMatchMinConfidence > 0 {
					matcher.MinConfidence = conf.FuncMatchMinConfidence
				}
				_, deltas := matcher.alignFunctions(funcs1, funcs2)

				var b strings.Builder

				// Group deltas by type for cleaner output
				var additions, removals, modifications []FunctionDelta
				for _, delta := range deltas {
					switch delta.Type {
					case "add":
						additions = append(additions, delta)
					case "remove":
						removals = append(removals, delta)
					case "modify":
						modifications = append(modifications, delta)
					}
				}

				// Output modifications
				if len(modifications) > 0 {
					b.WriteString("Functions (modified):\n")
					for _, mod := range modifications {
						name := matcher.getSymbolName(mod.OldFunc, dat1.SymbolMap)
						oldSize := mod.OldFunc.EndAddr - mod.OldFunc.StartAddr
						newSize := mod.NewFunc.EndAddr - mod.NewFunc.StartAddr
						b.WriteString(fmt.Sprintf("~ %s : %d -> %d\n", name, oldSize, newSize))
					}
				}

				// Output additions
				if len(additions) > 0 {
					if b.Len() > 0 {
						b.WriteString("\n")
					}
					b.WriteString("Functions (added):\n")
					for _, add := range additions {
						if add.BlockSize > 0 {
							// Contiguous block
							b.WriteString(fmt.Sprintf("+ [%d functions added in block]\n", add.BlockSize))
						} else {
							// Individual addition
							name := matcher.getSymbolName(add.Function, dat2.SymbolMap)
							b.WriteString(fmt.Sprintf("+ %s\n", name))
						}
					}
				}

				// Output removals
				if len(removals) > 0 {
					if b.Len() > 0 {
						b.WriteString("\n")
					}
					b.WriteString("Functions (removed):\n")
					for _, rm := range removals {
						if rm.BlockSize > 0 {
							// Contiguous block
							b.WriteString(fmt.Sprintf("- [%d functions removed in block]\n", rm.BlockSize))
						} else {
							// Individual removal
							name := matcher.getSymbolName(rm.Function, dat1.SymbolMap)
							b.WriteString(fmt.Sprintf("- %s\n", name))
						}
					}
				}

				if b.Len() > 0 {
					diff.Updated[currentFileKey] += b.String()
				}
			}

			/* DIFF CStrings */
			if conf.CStrings {
				newStrs := utils.Difference(dat2.CStrings, dat1.CStrings)
				sort.Strings(newStrs)
				rmStrs := utils.Difference(dat1.CStrings, dat2.CStrings)
				sort.Strings(rmStrs)
				if len(newStrs) > 0 || len(rmStrs) > 0 {
					diff.Updated[currentFileKey] += "CStrings:\n"
					for _, s := range newStrs {
						diff.Updated[currentFileKey] += fmt.Sprintf("+ %#v\n", s)
					}
					for _, s := range rmStrs {
						diff.Updated[currentFileKey] += fmt.Sprintf("- %#v\n", s)
					}
				}
			}

			if conf.Markdown {
				diff.Updated[currentFileKey] += "\n```\n"
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
		return nil, fmt.Errorf("failed to parse firmwares in 'Old' IPSW: %v", err)
	}

	/* NEXT IPSW */

	next := make(map[string]*DiffInfo)

	if err := search.ForEachIm4pInIPSW(newIPSW, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'Old' IPSW: %v", err)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}
