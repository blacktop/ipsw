package macho

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/signature"
)

// hashStreamPool reuses sha256 hashers and copy buffers across the many
// non-code per-section hashes a single GenerateDiffInfo computes, so section
// content is hashed incrementally instead of slurped whole into a []byte
// (Section.Data was the dominant cold-path allocation: ~71% of alloc-space
// and most of the alloc-count).
var hashStreamPool = sync.Pool{New: func() any {
	return &hashStream{h: sha256.New(), buf: make([]byte, 32*1024)}
}}

type hashStream struct {
	h   hash.Hash
	buf []byte
}

// streamSHA256 hashes r incrementally and returns the hex digest. ok is false
// when r yields no bytes or errors before any data, matching the previous
// "empty data -> no hash" behavior of the slurp-based hashers.
func streamSHA256(r io.Reader) (string, bool) {
	hs := hashStreamPool.Get().(*hashStream)
	defer hashStreamPool.Put(hs)
	hs.h.Reset()
	n, err := io.CopyBuffer(hs.h, r, hs.buf)
	if err != nil || n == 0 {
		return "", false
	}
	var sum [sha256.Size]byte
	return hex.EncodeToString(hs.h.Sum(sum[:0])), true
}

// xbsTemporaryBuildPathRE matches the per-build rotating XBS temp-dir token. It
// is intentionally NOT anchored: these paths appear both as a whole symbol/
// string value AND embedded mid-string (e.g. inside a libmalloc assertion
// message: `... failed (/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory
// .<TMP>/Sources/.../file.c:114)`), and both forms churn every build.
var xbsTemporaryBuildPathRE = regexp.MustCompile(`/Library/Caches/com\.apple\.xbs/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/TemporaryDirectory\.[^/\s]+`)

const xbsTemporaryBuildPathPlaceholder = "/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>"

// appleInternalBuildRootRE matches the per-build rotating token in an
// /AppleInternal/Library/BuildRoots/<token>/... path (the meaningful SDK/path
// suffix is kept). Also unanchored, for the same embedded-in-a-longer-string
// reason as xbsTemporaryBuildPathRE.
var appleInternalBuildRootRE = regexp.MustCompile(`/AppleInternal/Library/BuildRoots/[^/\s]+`)

const appleInternalBuildRootPlaceholder = "/AppleInternal/Library/BuildRoots/<BUILDROOT>"

// normalizeBuildPathForDiff collapses every occurrence of the two per-build
// rotating build-root paths Apple embeds in Mach-O strings and object-file
// (debug-map) symbols so a rebuild of identical source does not show as a diff.
func normalizeBuildPathForDiff(value string) string {
	value = xbsTemporaryBuildPathRE.ReplaceAllString(value, xbsTemporaryBuildPathPlaceholder)
	return appleInternalBuildRootRE.ReplaceAllString(value, appleInternalBuildRootPlaceholder)
}

func normalizeCStringForDiff(value string) string {
	return normalizeBuildPathForDiff(value)
}

// generatedSymbolCounterRE matches the trailing compiler-assigned disambiguator
// on local symbols — e.g. ..._block_invoke.323, ..._block_invoke.870.cold.1,
// ___block_literal_global.686 — which the linker renumbers every build. Only
// the trailing dotted counter/.cold run is stripped, so distinct blocks keep
// their base name (..._block_invoke vs ..._block_invoke_2).
var generatedSymbolCounterRE = regexp.MustCompile(`(\.cold|\.[0-9]+)+$`)

// normalizeSymbolForDiff collapses build-root path churn and strips the
// trailing generated disambiguator counter so recompiled-but-unchanged local
// symbols cancel in the diff instead of flooding it with renumber noise.
func normalizeSymbolForDiff(value string) string {
	value = normalizeBuildPathForDiff(value)
	return generatedSymbolCounterRE.ReplaceAllString(value, "")
}

func normalizeSymbolsForDiff(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, len(values))
	for idx, value := range values {
		normalized[idx] = normalizeSymbolForDiff(value)
	}
	return normalized
}

// diffNormalizedSymbols returns the added and removed symbols after normalizing
// both sides (build-root paths + generated counters). utils.Difference is
// set-based, so renumbered duplicates collapse and cancel; a genuinely new or
// removed symbol family still surfaces.
func diffNormalizedSymbols(oldValues, newValues []string) ([]string, []string) {
	normalizedOld := normalizeSymbolsForDiff(oldValues)
	normalizedNew := normalizeSymbolsForDiff(newValues)

	added := utils.Difference(normalizedNew, normalizedOld)
	sort.Strings(added)
	removed := utils.Difference(normalizedOld, normalizedNew)
	sort.Strings(removed)

	return added, removed
}

func normalizeCStringsForDiff(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, len(values))
	for idx, value := range values {
		normalized[idx] = normalizeCStringForDiff(value)
	}
	return normalized
}

func diffNormalizedCStrings(oldValues, newValues []string) ([]string, []string) {
	normalizedOldValues := normalizeCStringsForDiff(oldValues)
	normalizedNewValues := normalizeCStringsForDiff(newValues)

	added := utils.Difference(normalizedNewValues, normalizedOldValues)
	sort.Strings(added)
	removed := utils.Difference(normalizedOldValues, normalizedNewValues)
	sort.Strings(removed)

	return added, removed
}

type cachedDiffInfo struct {
	Info *DiffInfo
}

func cacheFileForKey(cacheDir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(cacheDir, hex.EncodeToString(sum[:])+".gob")
}

// WriteCachedDiffInfo serializes a single DiffInfo to disk under cacheDir,
// keyed by the binary's mount-relative path. Used by the LowMemory paths.
func WriteCachedDiffInfo(cacheDir, key string, info *DiffInfo) error {
	path := cacheFileForKey(cacheDir, key)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(&cachedDiffInfo{Info: info})
}

// ReadCachedDiffInfo deserializes a previously cached DiffInfo. Used by
// the LowMemory paths.
func ReadCachedDiffInfo(cacheDir, key string) (*DiffInfo, error) {
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

	var b strings.Builder
	hasDiffRows := containsAddedOrRemovedRows(out)
	if len(out) > 0 {
		b.WriteString(out)
	}

	sectionChanges := sectionContentChanges(oldInfo, newInfo)
	if len(sectionChanges) > 0 && !conf.Markdown {
		b.WriteString("Sections with same size but changed content:\n")
		for _, name := range sectionChanges {
			b.WriteString(fmt.Sprintf("- %s\n", name))
		}
	}

	// Symbols
	newSyms, rmSyms := diffNormalizedSymbols(oldInfo.Symbols, newInfo.Symbols)
	if len(newSyms) > 0 || len(rmSyms) > 0 {
		hasDiffRows = true
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
						fb.WriteString(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
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

				fb.WriteString(fmt.Sprintf("~ %s -> %s : %d -> %d\n", f1.Name, f2.Name, sz1, sz2))
				consecutiveMismatch++

				if consecutiveMismatch >= maxMismatch {
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
						fb.Reset()
						break
					}
				}
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
						fb.WriteString(fmt.Sprintf("~ %s : %d -> %d\n", f1.Name, sz1, sz2))
					}
					i++
					j++
					consecutiveNoise = 0
					continue
				}

				if (f1.EndAddr - f1.StartAddr) == (f2.EndAddr - f2.StartAddr) {
					i++
					j++
					consecutiveNoise = 0
					continue
				}

				if j+1 < n2 && (f1.EndAddr-f1.StartAddr) == (funcs2[j+1].EndAddr-funcs2[j+1].StartAddr) {
					fb.WriteString(fmt.Sprintf("+ %s\n", f2.Name))
					j++
					consecutiveNoise++
				} else if i+1 < n1 && (funcs1[i+1].EndAddr-funcs1[i+1].StartAddr) == (f2.EndAddr-f2.StartAddr) {
					fb.WriteString(fmt.Sprintf("- %s\n", f1.Name))
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
		}

		hasDiffRows = hasDiffRows || containsAddedOrRemovedRows(fb.String())
		appendFunctionSummary(&b, &fb)
	}

	// CStrings
	if conf.CStrings {
		newStrs, rmStrs := diffNormalizedCStrings(oldInfo.CStrings, newInfo.CStrings)
		if len(newStrs) > 0 || len(rmStrs) > 0 {
			hasDiffRows = true
			b.WriteString("CStrings:\n")
			for _, s := range newStrs {
				b.WriteString(fmt.Sprintf("+ %#v\n", s))
			}
			for _, s := range rmStrs {
				b.WriteString(fmt.Sprintf("- %#v\n", s))
			}
		}
	}

	if b.Len() == 0 && len(sectionChanges) == 0 {
		return "", nil
	}
	if !conf.Markdown {
		return b.String(), nil
	}

	var md strings.Builder
	if len(sectionChanges) > 0 {
		md.WriteString("### Sections with Same Size but Changed Content\n\n")
		for _, name := range sectionChanges {
			md.WriteString(fmt.Sprintf("- `%s`\n", name))
		}
	}
	if b.Len() == 0 {
		return md.String(), nil
	}
	if md.Len() > 0 {
		md.WriteByte('\n')
	}
	fence := "text"
	if hasDiffRows {
		fence = "diff"
	}
	body := b.String()
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	md.WriteString("```" + fence + "\n" + body + "```\n")
	return md.String(), nil
}

type DiffConfig struct {
	Markdown           bool
	Color              bool
	DiffTool           string
	AllowList          []string
	BlockList          []string
	CStrings           bool
	FuncStarts         bool
	IgnoreLoadCommands bool
	PemDB              string
	SymMap             map[string]signature.SymbolMap
	Verbose            bool
}

type MachoDiff struct {
	New     []string          `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"updated,omitempty"`
}

type section struct {
	Name string `json:"name,omitempty"`
	Size uint64 `json:"size,omitempty"`
	Hash string `json:"hash,omitempty"`
}

type DiffInfo struct {
	Version     string
	UUID        string
	LoadCmdHash string // internal structural digest; not rendered in reports
	Imports     []string
	Sections    []section
	Functions   int
	Starts      []types.Function
	Symbols     []string
	CStrings    []string
	SymbolMap   map[uint64]string
	Verbose     bool
}

func GenerateDiffInfo(m *macho.File, conf *DiffConfig, smaps ...signature.SymbolMap) *DiffInfo {
	var secs []section
	for _, s := range m.Sections {
		name := s.Seg + "." + s.Name
		if !sectionIncluded(name, conf) {
			continue
		}
		sec := section{
			Name: name,
			Size: s.Size,
		}
		sec.Hash, _ = sectionContentHash(s)
		secs = append(secs, sec)
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
	var loadCmdHash string
	if !conf.IgnoreLoadCommands {
		loadCmdHash, _ = loadCommandsHash(m)
	}
	return &DiffInfo{
		Version:     sourceVersion,
		UUID:        uuidStr,
		LoadCmdHash: loadCmdHash,
		Imports:     m.ImportedLibraries(),
		Sections:    secs,
		Functions:   len(starts),
		Starts:      starts,
		Symbols:     syms,
		CStrings:    strs,
		SymbolMap:   smap,
		Verbose:     conf.Verbose,
	}
}

// loadCommandsHash returns sha256(header || load_commands) with volatile
// build-metadata and linkedit-position fields zeroed. Structural load-command
// changes — dependency names, rpaths, segment layout, command additions/removals
// — still flip the hash, while point-release metadata churn does not.
//
// Returns ("", err) on read failure; callers should treat an empty hash as
// "not available" and skip the LoadCmdHash leg of the comparison.
func loadCommandsHash(m *macho.File) (string, error) {
	if m == nil {
		return "", nil
	}
	hdrSize := 28
	if m.Magic == types.Magic64 {
		hdrSize = 32
	}
	region := hdrSize + int(m.SizeCommands)
	if region <= hdrSize {
		return "", nil
	}
	buf := make([]byte, region)
	n, err := m.ReadAt(buf, 0)
	if err != nil || n != region {
		return "", err
	}
	return loadCommandsDigest(buf, hdrSize, m.Loads), nil
}

// loadCommandsDigest hashes the header + load-command region with each
// command's VOLATILE bytes zeroed, so the digest flips only on STRUCTURAL
// load-command changes (a dependency added/removed/renamed, an rpath change,
// segment layout) and not on the per-release build-metadata churn that
// rebuilds every binary in a point release (SDK/min-OS/source/dylib versions,
// re-signed code-signature size, shifted linkedit offsets). This mirrors the
// kernelcache diff's "functional segments unchanged; only build metadata
// differs -> skip" stance so the two paths agree on what counts as a change.
func loadCommandsDigest(buf []byte, hdrSize int, loads []macho.Load) string {
	off := hdrSize
	for _, l := range loads {
		sz := int(l.LoadSize())
		if sz <= 0 || off+sz > len(buf) {
			break
		}
		for _, r := range volatileLoadCmdRanges(l.Command(), sz) {
			start, end := off+r[0], off+r[1]
			if start < off+8 { // never touch the cmd/cmdsize header
				start = off + 8
			}
			if end > off+sz {
				end = off + sz
			}
			for i := start; i < end; i++ {
				buf[i] = 0
			}
		}
		off += sz
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// volatileLoadCmdRanges returns the byte ranges (relative to the start of a
// load command of the given type and size) whose contents are build metadata
// or linkedit position rather than structural identity, and so are zeroed
// before hashing. Offsets follow the Mach-O load_command layouts; the 8-byte
// cmd/cmdsize header is never included. Anything not listed here (segments,
// LC_RPATH, LC_MAIN, encryption info, ...) is hashed verbatim.
func volatileLoadCmdRanges(cmd types.LoadCmd, sz int) [][2]int {
	switch cmd {
	case types.LC_UUID:
		return [][2]int{{8, 24}} // the 16-byte UUID
	case types.LC_SOURCE_VERSION:
		return [][2]int{{8, 16}} // version uint64
	case types.LC_BUILD_VERSION:
		return [][2]int{{12, sz}} // keep platform; drop minos/sdk/ntools/tools
	case types.LC_VERSION_MIN_MACOSX, types.LC_VERSION_MIN_IPHONEOS,
		types.LC_VERSION_MIN_TVOS, types.LC_VERSION_MIN_WATCHOS:
		return [][2]int{{8, 16}} // version + sdk
	case types.LC_LOAD_DYLIB, types.LC_ID_DYLIB, types.LC_LOAD_WEAK_DYLIB,
		types.LC_REEXPORT_DYLIB, types.LC_LAZY_LOAD_DYLIB, types.LC_LOAD_UPWARD_DYLIB:
		// Keep name_offset[8:12] and the name string[24:]; drop timestamp +
		// current_version + compatibility_version so a dependency's version
		// bump is ignored but adding/removing/renaming one still flips.
		return [][2]int{{12, 24}}
	case types.LC_CODE_SIGNATURE, types.LC_FUNCTION_STARTS, types.LC_DATA_IN_CODE,
		types.LC_DYLD_EXPORTS_TRIE, types.LC_DYLD_CHAINED_FIXUPS, types.LC_SEGMENT_SPLIT_INFO,
		types.LC_DYLIB_CODE_SIGN_DRS, types.LC_LINKER_OPTIMIZATION_HINT:
		return [][2]int{{8, 16}} // linkedit_data_command dataoff + datasize
	case types.LC_DYLD_INFO, types.LC_DYLD_INFO_ONLY:
		return [][2]int{{8, 48}} // 5 (offset,size) pairs into linkedit
	case types.LC_SYMTAB:
		return [][2]int{{8, 24}} // symoff, nsyms, stroff, strsize
	case types.LC_DYSYMTAB:
		return [][2]int{{8, sz}} // all index/offset fields are linkedit position
	}
	return nil
}

func sectionIncluded(name string, conf *DiffConfig) bool {
	if len(conf.AllowList) > 0 && !slices.Contains(conf.AllowList, name) {
		return false
	}
	if len(conf.BlockList) > 0 && slices.Contains(conf.BlockList, name) {
		return false
	}
	return true
}

func sectionContentHash(s *types.Section) (string, bool) {
	if s == nil || s.Size == 0 || sectionContainsCode(s) {
		return "", false
	}
	// Stream the section through the hasher rather than slurping s.Data():
	// DSC dylib sections can be multi-MB, and this runs for every included
	// non-code section of every binary on both sides.
	return streamSHA256(s.Open())
}

func sectionContainsCode(s *types.Section) bool {
	if s == nil {
		return false
	}
	flags := s.Flags
	return flags.IsPureInstructions() ||
		flags.IsSomeInstructions() ||
		flags.IsSymbolStubs() ||
		flags.IsSelfModifyingCode()
}

func appendFunctionSummary(out, functions *strings.Builder) {
	if functions.Len() == 0 {
		return
	}
	out.WriteString("Functions:\n")
	out.WriteString(functions.String())
}

// sectionContentChanges reports the sections whose content hash changed while
// their size stayed the same. A size change already shows in the diff'd section
// list, so those are skipped; this surfaces the same-size content edits that
// dropping the per-section sha256 from DiffInfo.String would otherwise hide,
// without re-introducing the sha256 wall.
func sectionContentChanges(oldInfo, newInfo *DiffInfo) []string {
	if len(oldInfo.Sections) == 0 || len(newInfo.Sections) == 0 {
		return nil
	}
	newSections := make(map[string]section, len(newInfo.Sections))
	for _, sec := range newInfo.Sections {
		newSections[sec.Name] = sec
	}
	var changes []string
	for _, oldSec := range oldInfo.Sections {
		if newSec, ok := newSections[oldSec.Name]; ok && sameSizeContentChanged(oldSec, newSec) {
			changes = append(changes, oldSec.Name)
		}
	}
	return changes
}

// sameSizeContentChanged reports whether two same-named sections have different
// content hashes but the same size (a size change already shows in the diff'd
// section list, so it is excluded here).
func sameSizeContentChanged(oldSec, newSec section) bool {
	return oldSec.Hash != "" && newSec.Hash != "" &&
		oldSec.Hash != newSec.Hash &&
		oldSec.Size == newSec.Size
}

// containsAddedOrRemovedRows reports whether body has a real added or removed
// row. Summary-only rows (including "~" modified rows) belong in a text fence.
func containsAddedOrRemovedRows(body string) bool {
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			return true
		}
	}
	return false
}

// Equivalent reports whether two DiffInfos have the same report-visible
// semantics for conf. It deliberately ignores absolute function addresses,
// which shift when unrelated layout changes move a function without changing
// its size sequence.
func (i DiffInfo) Equivalent(x DiffInfo, conf *DiffConfig) bool {
	if conf == nil {
		conf = &DiffConfig{}
	}
	if !equivalentStringSet(i.Imports, x.Imports) ||
		!equivalentSections(i.Sections, x.Sections) ||
		!equivalentNormalizedStrings(i.Symbols, x.Symbols, normalizeSymbolForDiff) {
		return false
	}
	if conf.CStrings && !equivalentNormalizedStrings(i.CStrings, x.CStrings, normalizeCStringForDiff) {
		return false
	}
	if i.Functions != x.Functions {
		return false
	}
	if conf.FuncStarts && !equivalentFunctions(i, x) {
		return false
	}
	if !conf.IgnoreLoadCommands && i.LoadCmdHash != "" && x.LoadCmdHash != "" && i.LoadCmdHash != x.LoadCmdHash {
		return false
	}
	if conf.Verbose && (i.Version != x.Version || i.UUID != x.UUID) {
		return false
	}
	return true
}

func equivalentStringSet(a, b []string) bool {
	if slices.Equal(a, b) {
		return true
	}
	left := slices.Clone(a)
	right := slices.Clone(b)
	slices.Sort(left)
	slices.Sort(right)
	left = slices.Compact(left)
	right = slices.Compact(right)
	return slices.Equal(left, right)
}

func equivalentNormalizedStrings(a, b []string, normalize func(string) string) bool {
	if slices.Equal(a, b) {
		return true
	}
	left := normalizedStringSet(a, normalize)
	right := normalizedStringSet(b, normalize)
	return slices.Equal(left, right)
}

func normalizedStringSet(values []string, normalize func(string) string) []string {
	normalized := make([]string, len(values))
	for idx := range values {
		normalized[idx] = normalize(values[idx])
	}
	slices.Sort(normalized)
	return slices.Compact(normalized)
}

func equivalentSections(a, b []section) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx].Name != b[idx].Name || a[idx].Size != b[idx].Size {
			return false
		}
		if a[idx].Hash != "" && b[idx].Hash != "" && a[idx].Hash != b[idx].Hash {
			return false
		}
	}
	return true
}

func equivalentFunctions(i, x DiffInfo) bool {
	if len(i.Starts) != len(x.Starts) {
		return false
	}
	for idx := range i.Starts {
		if i.Starts[idx].EndAddr-i.Starts[idx].StartAddr != x.Starts[idx].EndAddr-x.Starts[idx].StartAddr {
			return false
		}
	}
	return true
}

func (i *DiffInfo) String() string {
	var out strings.Builder
	if i.Verbose && i.Version != "" {
		out.WriteString(i.Version + "\n")
	}
	for _, sec := range i.Sections {
		out.WriteString(fmt.Sprintf("  %s: %#x\n", sec.Name, sec.Size))
	}
	slices.Sort(i.Imports)
	for _, i := range i.Imports {
		out.WriteString(fmt.Sprintf("  - %s\n", i))
	}
	if i.Verbose && i.UUID != "" {
		out.WriteString(fmt.Sprintf("  UUID: %s\n", i.UUID))
	}
	out.WriteString(fmt.Sprintf("  Functions: %d\n", i.Functions))
	out.WriteString(fmt.Sprintf("  Symbols:   %d\n", len(normalizedStringSet(i.Symbols, normalizeSymbolForDiff))))
	out.WriteString(fmt.Sprintf("  CStrings:  %d\n", len(normalizedStringSet(i.CStrings, normalizeCStringForDiff))))
	return out.String()
}

func (diff *MachoDiff) Generate(prev, next map[string]*DiffInfo, conf *DiffConfig) error {

	/* DIFF IPSW */
	diff.New = utils.Difference(slices.Collect(maps.Keys(next)), slices.Collect(maps.Keys(prev)))
	diff.Removed = utils.Difference(slices.Collect(maps.Keys(prev)), slices.Collect(maps.Keys(next)))
	// Keys come from map iteration (random order); sort so the rendered diff is
	// deterministic and matches the low-memory path (which already sorts).
	slices.Sort(diff.New)
	slices.Sort(diff.Removed)

	var err error
	for _, currentFileKey := range slices.Sorted(maps.Keys(next)) {
		dat2 := next[currentFileKey]
		if dat1, ok := prev[currentFileKey]; ok {
			if dat2.Equivalent(*dat1, conf) {
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
// DiffIPSW diffs Mach-Os across two IPSW archives. Old-side DiffInfo is
// written to a temp cache on disk so peak heap stays bounded regardless of
// IPSW size; new-side DiffInfo is compared incrementally and the per-file
// diff string is emitted as we go.
func DiffIPSW(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}
	cacheDir, err := os.MkdirTemp("", "ipsw_macho_diff_cache")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cacheDir)

	prevKeys := make(map[string]bool) // value==true => already matched

	if err := search.ForEachMachoInIPSW(oldIPSW, conf.PemDB, func(path string, m *macho.File) error {
		prevKeys[path] = false
		return WriteCachedDiffInfo(cacheDir, path, GenerateDiffInfo(m, conf))
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

		oldInfo, err := ReadCachedDiffInfo(cacheDir, path)
		if err != nil {
			return err
		}
		newInfo := GenerateDiffInfo(m, conf)
		if newInfo.Equivalent(*oldInfo, conf) {
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

// MountRoot is an already-mounted volume to diff. Label is the consumer-facing
// volume name (unused for machos, which key on bare mount-relative paths, but
// shared with the file/entitlement walkers).
type MountRoot struct {
	Label      string
	MountPoint string
}

// DiffMounts is the in-mount twin of DiffIPSW: it diffs Mach-Os across volumes
// that are already mounted (via a mount.Session), walking oldRoots/newRoots in
// the caller's order so cross-volume last-writer-wins matches DiffIPSW. Old-side
// DiffInfo is cached on disk to keep peak heap bounded.
func DiffMounts(oldRoots, newRoots []MountRoot, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}
	cacheDir, err := os.MkdirTemp("", "ipsw_macho_diff_cache")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cacheDir)

	prevKeys := make(map[string]bool) // value==true => already matched

	for _, root := range oldRoots {
		if err := search.ForEachMachoInMount(root.MountPoint, func(path string, m *macho.File) error {
			prevKeys[path] = false
			return WriteCachedDiffInfo(cacheDir, path, GenerateDiffInfo(m, conf))
		}); err != nil {
			return nil, fmt.Errorf("failed to parse machos in 'Old' mount %s: %v", root.MountPoint, err)
		}
	}

	for _, root := range newRoots {
		if err := search.ForEachMachoInMount(root.MountPoint, func(path string, m *macho.File) error {
			matched, ok := prevKeys[path]
			if !ok {
				diff.New = append(diff.New, path)
				return nil
			}
			// Skip duplicate occurrences of an already-matched old entry.
			if matched {
				return nil
			}
			oldInfo, err := ReadCachedDiffInfo(cacheDir, path)
			if err != nil {
				return err
			}
			newInfo := GenerateDiffInfo(m, conf)
			if newInfo.Equivalent(*oldInfo, conf) {
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
			return nil, fmt.Errorf("failed to parse machos in 'New' mount %s: %v", root.MountPoint, err)
		}
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

// DiffFirmwares diffs two IPSW's im4p firmware Mach-Os. Old-side DiffInfo
// is cached on disk to keep peak heap bounded.
func DiffFirmwares(oldIPSW, newIPSW string, conf *DiffConfig) (*MachoDiff, error) {
	diff := &MachoDiff{
		Updated: make(map[string]string),
	}
	cacheDir, err := os.MkdirTemp("", "ipsw_firmware_diff_cache")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cacheDir)

	prevKeys := make(map[string]bool) // value==true => already matched
	oldSkippedExclaveMembers := make(map[string]struct{})
	if err := search.ForEachIm4pInIPSW(oldIPSW, func(path string, m *macho.File) error {
		prevKeys[path] = false
		return WriteCachedDiffInfo(cacheDir, path, GenerateDiffInfo(m, conf))
	}, func(member string) {
		oldSkippedExclaveMembers[member] = struct{}{}
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'Old' IPSW: %v", err)
	}

	newSkippedExclaveMembers := make(map[string]struct{})
	if err := search.ForEachIm4pInIPSW(newIPSW, func(path string, m *macho.File) error {
		matched, ok := prevKeys[path]
		if !ok {
			if generatedExclaveKeyFromSkippedBundle(path, oldSkippedExclaveMembers) {
				return nil
			}
			diff.New = append(diff.New, path)
			return nil
		}

		// If we've already matched this old entry earlier in the walk,
		// skip duplicate occurrences (avoid false-New classification).
		if matched {
			return nil
		}

		oldInfo, err := ReadCachedDiffInfo(cacheDir, path)
		if err != nil {
			return err
		}
		newInfo := GenerateDiffInfo(m, conf)
		if newInfo.Equivalent(*oldInfo, conf) {
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
	}, func(member string) {
		newSkippedExclaveMembers[member] = struct{}{}
	}); err != nil {
		return nil, fmt.Errorf("failed to parse firmwares in 'New' IPSW: %v", err)
	}

	for path, matched := range prevKeys {
		if !matched {
			if generatedExclaveKeyFromSkippedBundle(path, newSkippedExclaveMembers) {
				continue
			}
			diff.Removed = append(diff.Removed, path)
		}
	}
	sort.Strings(diff.New)
	sort.Strings(diff.Removed)

	return diff, nil
}

func generatedExclaveKeyFromSkippedBundle(path string, skippedMembers map[string]struct{}) bool {
	for member := range skippedMembers {
		if strings.HasPrefix(path, search.FirmwareMemberKey(member, "exclave_")) {
			return true
		}
	}
	return false
}
