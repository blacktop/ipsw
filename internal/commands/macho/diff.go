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
				// Helper for printable name
				printable := func(f types.Function, smap map[uint64]string) string {
					sym, ok := smap[f.StartAddr]
					if ok {
						return sym
					}
					return fmt.Sprintf("sub_%x", f.StartAddr)
				}

				funcs1 := dat1.Starts
				funcs2 := dat2.Starts

				n1, n2 := len(funcs1), len(funcs2)

				var b strings.Builder
				appendLine := func(s string) {
					if b.Len() == 0 {
						b.WriteString("Functions:\n")
					}
					b.WriteString(s)
				}

				// same count
				if n1 == n2 {
					consecutiveMismatch := 0
					const maxMismatch = 5

					for i := range n1 {
						f1 := funcs1[i]
						f2 := funcs2[i]
						f1.Name = printable(f1, dat1.SymbolMap)
						f2.Name = printable(f2, dat2.SymbolMap)

						if f1.Name != "" && f1.Name == f2.Name {
							// same symbol – only record if size changed
							sz1 := f1.EndAddr - f1.StartAddr
							sz2 := f2.EndAddr - f2.StartAddr
							if sz1 != sz2 {
								appendLine(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
							}
							consecutiveMismatch = 0
							continue
						}

						// unnamed or different names – compare size
						sz1 := f1.EndAddr - f1.StartAddr
						sz2 := f2.EndAddr - f2.StartAddr

						if sz1 == sz2 {
							consecutiveMismatch = 0
							continue // treat as aligned
						}

						// size diff
						appendLine(fmt.Sprintf("~ %s -> %s : %d -> %d\n", f1.Name, f2.Name, sz1, sz2))
						consecutiveMismatch++

						if consecutiveMismatch >= maxMismatch {
							// scan ahead for 3 consecutive size matches to recover
							recovered := false
							const seekAhead = 6
							if i+seekAhead < n1 {
								matches := 0
								for k := 1; k <= seekAhead && i+k < n1; k++ {
									if (funcs1[i+k].EndAddr - funcs1[i+k].StartAddr) == (funcs2[i+k].EndAddr - funcs2[i+k].StartAddr) {
										matches++
										if matches >= 3 {
											recovered = true
											break
										}
									} else {
										matches = 0
									}
								}
							}
							if !recovered {
								// bail out – noisy diff
								b.Reset()
								break
							}
						}
					}

					if b.Len() > 0 {
						diff.Updated[currentFileKey] += b.String()
					}
					goto CStringBlock
				}

				// different counts – two-pointer scan with simple heuristics
				i, j := 0, 0
				consecutiveNoise := 0
				const noiseLimit = 6

				for i < n1 && j < n2 {
					f1 := funcs1[i]
					f2 := funcs2[j]
					f1.Name = printable(f1, dat1.SymbolMap)
					f2.Name = printable(f2, dat2.SymbolMap)
					// strong name match
					if f1.Name != "" && f1.Name == f2.Name {
						sz1 := f1.EndAddr - f1.StartAddr
						sz2 := f2.EndAddr - f2.StartAddr
						if sz1 != sz2 {
							appendLine(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
						}
						i++
						j++
						consecutiveNoise = 0
						continue
					}

					// size match
					if (f1.EndAddr - f1.StartAddr) == (f2.EndAddr - f2.StartAddr) {
						i++
						j++
						consecutiveNoise = 0
						continue
					}

					// try simple insert/delete to recoup
					if j+1 < n2 && (f1.EndAddr-f1.StartAddr) == (funcs2[j+1].EndAddr-funcs2[j+1].StartAddr) {
						appendLine(fmt.Sprintf("+ %s\n", f2.Name))
						j++
						consecutiveNoise++
					} else if i+1 < n1 && (funcs1[i+1].EndAddr-funcs1[i+1].StartAddr) == (f2.EndAddr-f2.StartAddr) {
						appendLine(fmt.Sprintf("- %s\n", f1.Name))
						i++
						consecutiveNoise++
					} else {
						consecutiveNoise++
					}

					if consecutiveNoise >= noiseLimit {
						b.Reset()
						break
					}
				}

				if b.Len() > 0 {
					diff.Updated[currentFileKey] += b.String()
				}
			}

		CStringBlock:

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
