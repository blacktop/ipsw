package macho

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/signature"
)

type cachedDiffInfo struct {
	Info *DiffInfo
}

func cacheFileForKey(cacheDir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(cacheDir, hex.EncodeToString(sum[:]) + ".gob")
}

func writeCachedDiffInfo(cacheDir, key string, info *DiffInfo) error {
	path := cacheFileForKey(cacheDir, key)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(&cachedDiffInfo{Info: info})
}

func readCachedDiffInfo(cacheDir, key string) (*DiffInfo, error) {
	path := cacheFileForKey(cacheDir, key)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c cachedDiffInfo
	if err := gob.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}
	if c.Info == nil {
		return nil, fmt.Errorf("cached diff info missing for %s", key)
	}
	return c.Info, nil
}

// FormatUpdatedDiff formats a single-file diff in the same style as MachoDiff.Generate.
// Returns an empty string if no printable diff content is produced.
func FormatUpdatedDiff(oldInfo, newInfo *DiffInfo, conf *DiffConfig) (string, error) {
	if oldInfo == nil || newInfo == nil {
		return "", fmt.Errorf("nil diff info")
	}

	out, err := utils.GitDiff(oldInfo.String()+"\n", newInfo.String()+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
	if err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "", nil
	}

	var b strings.Builder
	if conf.Markdown {
		b.WriteString("```diff\n")
		b.WriteString(out)
	} else {
		b.WriteString(out)
	}

	// Symbols
	newSyms := utils.Difference(newInfo.Symbols, oldInfo.Symbols)
	sort.Strings(newSyms)
	rmSyms := utils.Difference(oldInfo.Symbols, newInfo.Symbols)
	sort.Strings(rmSyms)
	if len(newSyms) > 0 || len(rmSyms) > 0 {
		b.WriteString("Symbols:\n")
		for _, s := range newSyms {
			b.WriteString(fmt.Sprintf("+ %s\n", s))
		}
		for _, s := range rmSyms {
			b.WriteString(fmt.Sprintf("- %s\n", s))
		}
	}

	// Functions
	if conf.FuncStarts {
		printable := func(f types.Function, smap map[uint64]string) string {
			sym, ok := smap[f.StartAddr]
			if ok {
				return sym
			}
			return fmt.Sprintf("sub_%x", f.StartAddr)
		}

		funcs1 := oldInfo.Starts
		funcs2 := newInfo.Starts
		n1, n2 := len(funcs1), len(funcs2)

		var fb strings.Builder
		appendLine := func(s string) {
			if fb.Len() == 0 {
				fb.WriteString("Functions:\n")
			}
			fb.WriteString(s)
		}

		if n1 == n2 {
			consecutiveMismatch := 0
			const maxMismatch = 5

			for i := range n1 {
				f1 := funcs1[i]
				f2 := funcs2[i]
				f1.Name = printable(f1, oldInfo.SymbolMap)
				f2.Name = printable(f2, newInfo.SymbolMap)

				if f1.Name != "" && f1.Name == f2.Name {
					sz1 := f1.EndAddr - f1.StartAddr
					sz2 := f2.EndAddr - f2.StartAddr
					if sz1 != sz2 {
						appendLine(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
					}
					consecutiveMismatch = 0
					continue
				}

				sz1 := f1.EndAddr - f1.StartAddr
				sz2 := f2.EndAddr - f2.StartAddr

				if sz1 == sz2 {
					consecutiveMismatch = 0
					continue
				}

				appendLine(fmt.Sprintf("~ %s -> %s : %d -> %d\n", f1.Name, f2.Name, sz1, sz2))
				consecutiveMismatch++

				if consecutiveMismatch >= maxMismatch {
					recovered := false
					const seekAhead = 6
					if i+seekAhead < n1 {
						matches := 0
						for k := 1; k <= seekAhead && i+k < n1; k++ {
							if (funcs1[i+k].EndAddr-funcs1[i+k].StartAddr) == (funcs2[i+k].EndAddr-funcs2[i+k].StartAddr) {
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
						fb.Reset()
						break
					}
				}
			}

			if fb.Len() > 0 {
				b.WriteString(fb.String())
			}
		} else {
			i, j := 0, 0
			consecutiveNoise := 0
			const noiseLimit = 6

			for i < n1 && j < n2 {
				f1 := funcs1[i]
				f2 := funcs2[j]
				f1.Name = printable(f1, oldInfo.SymbolMap)
				f2.Name = printable(f2, newInfo.SymbolMap)
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

				if (f1.EndAddr-f1.StartAddr) == (f2.EndAddr-f2.StartAddr) {
					i++
					j++
					consecutiveNoise = 0
					continue
				}

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
					fb.Reset()
					break
				}
			}

			if fb.Len() > 0 {
				b.WriteString(fb.String())
			}
		}
	}

	// CStrings
	if conf.CStrings {
		newStrs := utils.Difference(newInfo.CStrings, oldInfo.CStrings)
		sort.Strings(newStrs)
		rmStrs := utils.Difference(oldInfo.CStrings, newInfo.CStrings)
		sort.Strings(rmStrs)
		if len(newStrs) > 0 || len(rmStrs) > 0 {
			b.WriteString("CStrings:\n")
			for _, s := range newStrs {
				b.WriteString(fmt.Sprintf("+ %#v\n", s))
			}
			for _, s := range rmStrs {
				b.WriteString(fmt.Sprintf("- %#v\n", s))
			}
		}
	}

	if conf.Markdown {
		b.WriteString("\n```\n")
	}

	return b.String(), nil
}

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
	LowMemory  bool // Use disk caching to reduce RAM usage
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
	var out strings.Builder
	out.WriteString(i.Version + "\n")
	for _, sec := range i.Sections {
		out.WriteString(fmt.Sprintf("  %s: %#x\n", sec.Name, sec.Size))
	}
	slices.Sort(i.Imports)
	for _, i := range i.Imports {
		out.WriteString(fmt.Sprintf("  - %s\n", i))
	}
	out.WriteString(fmt.Sprintf("  UUID: %s\n", i.UUID))
	out.WriteString(fmt.Sprintf("  Functions: %d\n", i.Functions))
	out.WriteString(fmt.Sprintf("  Symbols:   %d\n", len(i.Symbols)))
	out.WriteString(fmt.Sprintf("  CStrings:  %d\n", len(i.CStrings)))
	return out.String()
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
			var formatted string
			formatted, err = FormatUpdatedDiff(dat1, dat2, conf)
			if err != nil {
				return err
			}
			if formatted == "" {
				continue
			}
			diff.Updated[currentFileKey] = formatted
		}
	}

	return nil
}

// DiffIPSW diffs two IPSW's MachOs
func DiffIPSW(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}

	if conf.LowMemory {
		// Low-memory mode: cache DiffInfo to disk to avoid holding all in RAM
		return diffIPSWLowMemory(oldIPSW, newIPSW, conf, diff)
	}

	// Default: fast in-memory mode
	prev := make(map[string]*DiffInfo)

	if err := search.ForEachMachoInIPSW(oldIPSW, conf.PemDB, func(path string, m *macho.File) error {
		prev[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	next := make(map[string]*DiffInfo)

	if err := search.ForEachMachoInIPSW(newIPSW, conf.PemDB, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'New' IPSW: %v", err)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}

// diffIPSWLowMemory uses disk caching to reduce RAM usage
func diffIPSWLowMemory(oldIPSW, newIPSW string, conf *DiffConfig, diff *MachoDiff) (*MachoDiff, error) {
	cacheDir, err := os.MkdirTemp("", "ipsw_macho_diff_cache")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cacheDir)

	prevKeys := make(map[string]bool) // value==true => already matched

	if err := search.ForEachMachoInIPSW(oldIPSW, conf.PemDB, func(path string, m *macho.File) error {
		prevKeys[path] = false
		return writeCachedDiffInfo(cacheDir, path, GenerateDiffInfo(m, conf))
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'Old' IPSW: %v", err)
	}

	if err := search.ForEachMachoInIPSW(newIPSW, conf.PemDB, func(path string, m *macho.File) error {
		matched, ok := prevKeys[path]
		if !ok {
			diff.New = append(diff.New, path)
			return nil
		}

		// If we've already matched this old entry earlier in the walk,
		// skip duplicate occurrences (avoid false-New classification).
		if matched {
			return nil
		}

		oldInfo, err := readCachedDiffInfo(cacheDir, path)
		if err != nil {
			return err
		}
		newInfo := GenerateDiffInfo(m, conf)
		if newInfo.Equal(*oldInfo) {
			prevKeys[path] = true
			return nil
		}
		formatted, err := FormatUpdatedDiff(oldInfo, newInfo, conf)
		if err != nil {
			return err
		}
		if formatted != "" {
			diff.Updated[path] = formatted
		}
		prevKeys[path] = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse machos in 'New' IPSW: %v", err)
	}

	for path, matched := range prevKeys {
		if !matched {
			diff.Removed = append(diff.Removed, path)
		}
	}
	sort.Strings(diff.New)
	sort.Strings(diff.Removed)

	return diff, nil
}

// DiffFirmwares diffs two IPSW's im4p firmware MachOs
func DiffFirmwares(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}

	if conf.LowMemory {
		// Low-memory mode: cache DiffInfo to disk to avoid holding all in RAM
		return diffFirmwaresLowMemory(oldIPSW, newIPSW, conf, diff)
	}

	// Default: fast in-memory mode
	prev := make(map[string]*DiffInfo)

	if err := search.ForEachIm4pInIPSW(oldIPSW, func(path string, m *macho.File) error {
		prev[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'Old' IPSW: %v", err)
	}

	next := make(map[string]*DiffInfo)

	if err := search.ForEachIm4pInIPSW(newIPSW, func(path string, m *macho.File) error {
		next[path] = GenerateDiffInfo(m, conf)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'New' IPSW: %v", err)
	}

	if err := diff.Generate(prev, next, conf); err != nil {
		return nil, err
	}

	return diff, nil
}

// diffFirmwaresLowMemory uses disk caching to reduce RAM usage
func diffFirmwaresLowMemory(oldIPSW, newIPSW string, conf *DiffConfig, diff *MachoDiff) (*MachoDiff, error) {
	cacheDir, err := os.MkdirTemp("", "ipsw_firmware_diff_cache")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cacheDir)

	prevKeys := make(map[string]bool) // value==true => already matched
	if err := search.ForEachIm4pInIPSW(oldIPSW, func(path string, m *macho.File) error {
		prevKeys[path] = false
		return writeCachedDiffInfo(cacheDir, path, GenerateDiffInfo(m, conf))
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'Old' IPSW: %v", err)
	}

	if err := search.ForEachIm4pInIPSW(newIPSW, func(path string, m *macho.File) error {
		matched, ok := prevKeys[path]
		if !ok {
			diff.New = append(diff.New, path)
			return nil
		}

		// If we've already matched this old entry earlier in the walk,
		// skip duplicate occurrences (avoid false-New classification).
		if matched {
			return nil
		}

		oldInfo, err := readCachedDiffInfo(cacheDir, path)
		if err != nil {
			return err
		}
		newInfo := GenerateDiffInfo(m, conf)
		if newInfo.Equal(*oldInfo) {
			prevKeys[path] = true
			return nil
		}
		formatted, err := FormatUpdatedDiff(oldInfo, newInfo, conf)
		if err != nil {
			return err
		}
		if formatted != "" {
			diff.Updated[path] = formatted
		}
		prevKeys[path] = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'New' IPSW: %v", err)
	}

	for path, matched := range prevKeys {
		if !matched {
			diff.Removed = append(diff.Removed, path)
		}
	}
	sort.Strings(diff.New)
	sort.Strings(diff.Removed)

	return diff, nil
}
