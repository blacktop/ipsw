package macho

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"maps"
	"math/bits"
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

// hashStreamBufSize is the streaming read size, and also the point at which
// bufio.Scanner refills in the normalized CString hashers.
const hashStreamBufSize = 32 * 1024

// hashStreamPool reuses sha256 hashers and copy buffers across the many
// per-section hashes a single GenerateDiffInfo computes, so section content is
// hashed incrementally instead of slurped whole into a []byte (Section.Data was
// the dominant cold-path allocation: ~71% of alloc-space and most of the
// alloc-count).
var hashStreamPool = sync.Pool{New: func() any {
	return &hashStream{h: sha256.New(), buf: make([]byte, hashStreamBufSize)}
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

// xbsBuildUUIDRE matches the per-build XBS job UUID directory. It is
// intentionally NOT anchored: these paths appear both as a whole symbol/string
// value AND embedded mid-string (e.g. inside a libmalloc assertion message:
// `... failed (/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>/
// Sources/.../file.c:114)`), and both forms churn every build.
var xbsBuildUUIDRE = regexp.MustCompile(`/Library/Caches/com\.apple\.xbs/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(/|$)`)

const xbsBuildUUIDPlaceholder = "/Library/Caches/com.apple.xbs/<UUID>"
const xbsBuildUUIDReplacement = xbsBuildUUIDPlaceholder + "${1}"

// xbsTemporaryDirectoryRE matches the mkdtemp-rotated `TemporaryDirectory.<TOK>`
// path component on its own rather than as a suffix of xbsBuildUUIDRE, because
// the two rotate independently and appear in more than one combination:
//
//	/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TOK>/Sources/...
//	/AppleInternal/Library/BuildRoots/<ROOT>/Library/Caches/com.apple.xbs/TemporaryDirectory.<TOK>/Sources/...
//
// It is deliberately narrow, because collapsing a token that is NOT a build
// temp dir would make two genuinely different paths compare equal:
//
//   - the XBS prefix is required, so `/tmp/TemporaryDirectory.alpha/x` and a
//     source file named `.../TemporaryDirectory.h` are left alone;
//   - the token is exactly the six characters mkdtemp substitutes for XXXXXX,
//     so a real extension cannot be swallowed;
//   - a trailing `/` or end-of-string is required, so the match covers a whole
//     path component.
//
// It runs after xbsBuildUUIDRE, hence the literal `<UUID>` in the optional
// group.
var xbsTemporaryDirectoryRE = regexp.MustCompile(`(/Library/Caches/com\.apple\.xbs(?:/<UUID>)?)/TemporaryDirectory\.[A-Za-z0-9]{6}(/|$)`)

const xbsTemporaryDirectoryReplacement = "${1}/TemporaryDirectory.<TMP>${2}"

// appleInternalBuildRootRE matches the per-build rotating token in an
// /AppleInternal/Library/BuildRoots/<token>/... path (the meaningful SDK/path
// suffix is kept). Also unanchored, for the same embedded-in-a-longer-string
// reason as xbsBuildUUIDRE.
var appleInternalBuildRootRE = regexp.MustCompile(`/AppleInternal/Library/BuildRoots/[^/\s]+`)

const appleInternalBuildRootPlaceholder = "/AppleInternal/Library/BuildRoots/<BUILDROOT>"

// normalizeBuildPathForDiff collapses every occurrence of the two per-build
// rotating build-root paths Apple embeds in Mach-O strings and object-file
// (debug-map) symbols so a rebuild of identical source does not show as a diff.
func normalizeBuildPathForDiff(value string) string {
	// Every pattern below is rooted at a '/', so a value without one cannot
	// match any of them. The gate matters because this runs over every symbol
	// and every cstring of both sides in DiffInfo.Equivalent: regexp allocates
	// even when it does not match, so three unconditional passes cost ~9
	// allocations per string, and ~99% of strings hold no path at all.
	if !strings.ContainsRune(value, '/') {
		return value
	}
	value = xbsBuildUUIDRE.ReplaceAllString(value, xbsBuildUUIDReplacement)
	value = xbsTemporaryDirectoryRE.ReplaceAllString(value, xbsTemporaryDirectoryReplacement)
	return appleInternalBuildRootRE.ReplaceAllString(value, appleInternalBuildRootPlaceholder)
}

func normalizeCStringForDiff(value string) string {
	return normalizeBuildPathForDiff(value)
}

// compilerBuildTimestampRE matches whole CString forms produced from
// __DATE__, __TIME__, __TIMESTAMP__, and Apple's timezone-bearing equivalent.
// Anchoring is intentional: a timestamp inside a diagnostic or other
// meaningful string must remain reportable.
const (
	compilerMonthPattern   = `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`
	compilerWeekdayPattern = `(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)`
	compilerDayPattern     = `(?: [1-9]|[12][0-9]|3[01])`
	compilerTimePattern    = `(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]`
)

var compilerBuildTimestampRE = regexp.MustCompile(
	`^(?:` +
		compilerTimePattern + `|` +
		compilerMonthPattern + ` ` + compilerDayPattern + ` [0-9]{4}(?:(?: |, )?` + compilerTimePattern + `)?|` +
		compilerWeekdayPattern + ` ` + compilerMonthPattern + ` ` + compilerDayPattern + ` ` + compilerTimePattern + `(?: [A-Z]{2,5})? [0-9]{4}` +
		`)$`,
)

const compilerBuildTimestampPlaceholder = "<BUILD_TIMESTAMP>"

func normalizeCStringForDiffIgnoringBuildTimestamp(value string) string {
	if compilerBuildTimestampRE.MatchString(value) {
		return compilerBuildTimestampPlaceholder
	}
	return normalizeCStringForDiff(value)
}

func cstringNormalizer(ignoreBuildTimestamps bool) func(string) string {
	if ignoreBuildTimestamps {
		return normalizeCStringForDiffIgnoringBuildTimestamp
	}
	return normalizeCStringForDiff
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

func normalizeCStringsForDiff(values []string, ignoreBuildTimestamps bool) []string {
	if len(values) == 0 {
		return nil
	}

	normalize := cstringNormalizer(ignoreBuildTimestamps)
	normalized := make([]string, len(values))
	for idx, value := range values {
		normalized[idx] = normalize(value)
	}
	return normalized
}

func diffNormalizedCStrings(oldValues, newValues []string, ignoreBuildTimestamps bool) ([]string, []string) {
	normalizedOldValues := normalizeCStringsForDiff(oldValues, ignoreBuildTimestamps)
	normalizedNewValues := normalizeCStringsForDiff(newValues, ignoreBuildTimestamps)

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

	out, err := utils.GitDiff(oldInfo.stringForDiff(conf)+"\n", newInfo.stringForDiff(conf)+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
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
		newStrs, rmStrs := diffNormalizedCStrings(oldInfo.CStrings, newInfo.CStrings, conf.IgnoreBuildTimestamps)
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
	Markdown              bool
	Color                 bool
	DiffTool              string
	AllowList             []string
	BlockList             []string
	CStrings              bool
	FuncStarts            bool
	IgnoreBuildTimestamps bool
	IgnoreLoadCommands    bool
	PemDB                 string
	SymMap                map[string]signature.SymbolMap
	Verbose               bool
}

type MachoDiff struct {
	New     []string          `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"updated,omitempty"`
}

type section struct {
	Name     string            `json:"name,omitempty"`
	Size     uint64            `json:"size,omitempty"`
	Hash     string            `json:"hash,omitempty"`
	Type     types.SectionFlag `json:"-"`
	HashMode sectionHashMode   `json:"-"`
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

// GenerateDiffInfo generates diff information for a standalone Mach-O, whose
// non-code section bytes are meaningful without container relocation context.
func GenerateDiffInfo(m *macho.File, conf *DiffConfig, smaps ...signature.SymbolMap) *DiffInfo {
	return generateDiffInfo(m, conf, false, smaps...)
}

// GenerateContainerDiffInfo generates diff information for an image whose
// relocations are owned by a shared cache or fileset container.
func GenerateContainerDiffInfo(m *macho.File, conf *DiffConfig, smaps ...signature.SymbolMap) *DiffInfo {
	return generateDiffInfo(m, conf, true, smaps...)
}

func generateDiffInfo(m *macho.File, conf *DiffConfig, containerImage bool, smaps ...signature.SymbolMap) *DiffInfo {
	compareAllContent := !containerImage || len(conf.AllowList) > 0
	var secs []section
	for _, s := range m.Sections {
		name := s.Seg + "." + s.Name
		if !sectionIncluded(name, conf) {
			continue
		}
		sec := section{
			Name:     name,
			Size:     s.Size,
			Type:     s.Flags & types.SectionType,
			HashMode: sectionContentHashMode(s, compareAllContent),
		}
		sec.Hash, _ = sectionContentHashWithMode(s, sec.HashMode, conf.IgnoreBuildTimestamps)
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
		loadCmdHash, _ = loadCommandsHash(m, conf)
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

// loadCommandsHash returns a digest of the Mach header and load commands with
// volatile build metadata and linkedit positions removed. When section filters
// are active, segment commands are represented canonically so excluded sections
// and address/offset shifts cannot bypass the filter.
//
// Returns ("", err) on read failure; callers should treat an empty hash as
// "not available" and skip the LoadCmdHash leg of the comparison.
func loadCommandsHash(m *macho.File, conf *DiffConfig) (string, error) {
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
	return loadCommandsDigest(buf, hdrSize, m.Loads, m.Sections, conf), nil
}

// loadCommandsDigest hashes the header + load-command region with volatile
// fields zeroed. With an allow- or block-list, raw segment commands are replaced
// by a policy-aware representation produced by writeFilteredSegmentDigest.
func loadCommandsDigest(buf []byte, hdrSize int, loads []macho.Load, sections []*types.Section, conf *DiffConfig) string {
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
			clear(buf[start:end])
		}
		off += sz
	}

	filtered := conf != nil && (len(conf.AllowList) > 0 || len(conf.BlockList) > 0)
	if !filtered {
		sum := sha256.Sum256(buf)
		return hex.EncodeToString(sum[:])
	}

	// sizeofcmds includes every raw section record, including blocked ones.
	// The canonical command stream below already carries its own boundaries.
	if hdrSize >= 24 {
		clear(buf[20:24])
	}
	h := sha256.New()
	_, _ = h.Write(buf[:hdrSize])
	off = hdrSize
	for _, l := range loads {
		sz := int(l.LoadSize())
		if sz <= 0 || off+sz > len(buf) {
			break
		}
		if l.Command() == types.LC_SEGMENT || l.Command() == types.LC_SEGMENT_64 {
			if seg, ok := l.(*macho.Segment); ok {
				writeFilteredSegmentDigest(h, seg, sections, conf)
				off += sz
				continue
			}
		}
		_, _ = h.Write(buf[off : off+sz])
		off += sz
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeFilteredSegmentDigest retains structural segment data while omitting
// excluded sections and positions derived from section layout. Included section
// sizes and selected content hashes are compared separately in DiffInfo.Sections,
// but flags, alignment, relocation counts, and section-type-specific reserved
// fields still need representation here.
func writeFilteredSegmentDigest(h hash.Hash, seg *macho.Segment, sections []*types.Section, conf *DiffConfig) {
	var lane [8]byte
	writeUint32 := func(value uint32) {
		binary.LittleEndian.PutUint32(lane[:4], value)
		_, _ = h.Write(lane[:4])
	}
	writeUint64 := func(value uint64) {
		binary.LittleEndian.PutUint64(lane[:], value)
		_, _ = h.Write(lane[:])
	}
	writeName := func(value string) {
		var name [16]byte
		copy(name[:], value)
		_, _ = h.Write(name[:])
	}

	writeUint32(uint32(seg.Command()))
	writeName(seg.Name)
	writeUint32(uint32(seg.Maxprot))
	writeUint32(uint32(seg.Prot))
	writeUint32(uint32(seg.Flag))
	// __PAGEZERO has no sections, so its guard size has no other semantic
	// representation. Other segment positions are derived from section layout.
	if seg.Name == "__PAGEZERO" {
		writeUint64(seg.Addr)
		writeUint64(seg.Memsz)
		writeUint64(seg.Offset)
		writeUint64(seg.Filesz)
	}

	start := uint64(seg.Firstsect)
	end := min(start+uint64(seg.Nsect), uint64(len(sections)))
	var included uint32
	for idx := start; idx < end; idx++ {
		s := sections[idx]
		if s != nil && sectionIncluded(s.Seg+"."+s.Name, conf) {
			included++
		}
	}
	writeUint32(included)
	for idx := start; idx < end; idx++ {
		s := sections[idx]
		if s == nil || !sectionIncluded(s.Seg+"."+s.Name, conf) {
			continue
		}
		writeName(s.Seg)
		writeName(s.Name)
		writeUint64(s.Size)
		writeUint32(s.Align)
		writeUint32(s.Nreloc)
		writeUint32(uint32(s.Flags))
		writeUint32(s.Reserved1)
		writeUint32(s.Reserved2)
		writeUint32(s.Reserved3)
	}
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

// sectionHashMode says how — or whether — a section's content is digested.
type sectionHashMode int

const (
	// hashSkip means section content is intentionally ignored. It is the zero
	// value so missing classification metadata defaults to no content hash.
	hashSkip sectionHashMode = iota
	// hashVerbatim digests the raw bytes.
	hashVerbatim
	// hashCStringsOrdered digests normalized NUL-terminated strings in section
	// order. Standalone and explicitly allowed section bytes are address-sensitive.
	hashCStringsOrdered
	// hashCStringsMultiset ignores literal-pool order in a default container
	// comparison, where linker reshuffling is otherwise dominant noise.
	hashCStringsMultiset
)

// stableSectionHashModes names the sections whose bytes still mean the same
// thing after everything around them moves. Literal section TYPES are recognized
// by flag in sectionContentHashMode, so only sections typed S_REGULAR belong here.
//
// Most non-code sections are deliberately absent. In a shared-cache or fileset
// image, pointer slots are stored as cache-/collection-relative offsets, and the
// __TEXT metadata sections (__unwind_info, __eh_frame, __objc_methlist, the
// __swift5_* tables) store image-relative offsets. Every one of those bytes
// changes when an unrelated image earlier in the container grows by a byte, so
// hashing them reports "this container was rebuilt", not "this binary changed":
// across two adjacent iOS betas it flagged 4515 of 4646 dylibs, which buried the
// real diffs. Literal data has no such dependence, so that is all we hash.
//
// Expect this list to grow: Apple adds literal sections (particularly __swift*)
// most releases. For container images without an explicit allow-list, a missing
// entry fails quiet — the section simply stops being compared — so new literal
// sections belong here as they appear.
var stableSectionHashModes = map[string]sectionHashMode{
	// Runs of NUL-terminated strings a producer may emit as S_REGULAR rather
	// than S_CSTRING_LITERALS. __os_log is listed because go-macho's GetCStrings
	// counts it, and the rendered CStrings list and the section hash have to
	// agree about what a literal pool is.
	"__TEXT.__objc_methname":  hashCStringsMultiset,
	"__TEXT.__objc_classname": hashCStringsMultiset,
	"__TEXT.__objc_methtype":  hashCStringsMultiset,
	"__TEXT.__swift5_reflstr": hashCStringsMultiset,
	"__TEXT.__os_log":         hashCStringsMultiset,

	// __ustring is UTF-16, so splitting it on single NUL bytes would be wrong.
	"__TEXT.__ustring":              hashVerbatim,
	"__TEXT.__info_plist":           hashVerbatim,
	"__TEXT.__entitlements":         hashVerbatim,
	"__DATA_CONST.__objc_imageinfo": hashVerbatim,
}

// sectionContentHashMode reports how a section's content should be digested.
// compareAllContent is true for standalone Mach-Os and for container images
// whose caller supplied an explicit allow-list.
func sectionContentHashMode(s *types.Section, compareAllContent bool) sectionHashMode {
	if s == nil {
		return hashSkip
	}
	flags := s.Flags
	if sectionContainsCode(s) ||
		flags.IsZerofill() || flags.IsGbZerofill() || flags.IsThreadLocalZerofill() {
		return hashSkip
	}
	if flags.IsCstringLiterals() {
		if compareAllContent {
			return hashCStringsOrdered
		}
		return hashCStringsMultiset
	}
	if flags.Is4ByteLiterals() || flags.Is8ByteLiterals() || flags.Is16ByteLiterals() {
		return hashVerbatim
	}
	if mode, ok := stableSectionHashModes[s.Seg+"."+s.Name]; ok {
		if compareAllContent && mode == hashCStringsMultiset {
			return hashCStringsOrdered
		}
		return mode
	}
	if compareAllContent {
		// Standalone content is meaningful verbatim; an explicit container
		// allow-list requests the same comparison for otherwise unclassified
		// sections despite relocation noise.
		return hashVerbatim
	}
	return hashSkip
}

func sectionContentHashWithMode(s *types.Section, mode sectionHashMode, ignoreBuildTimestamps bool) (string, bool) {
	if s == nil || s.Size == 0 {
		return "", false
	}
	switch mode {
	case hashCStringsOrdered:
		return normalizedCStringOrderedHash(s, ignoreBuildTimestamps)
	case hashCStringsMultiset:
		return normalizedCStringMultisetHash(s, ignoreBuildTimestamps)
	case hashVerbatim:
		// Stream the section through the hasher rather than slurping s.Data():
		// DSC dylib sections can be multi-MB, and this runs for every included
		// section of every binary on both sides.
		return streamSHA256(s.Open())
	default:
		return "", false
	}
}

// normalizedCStringBytes collapses rotating build-path tokens in one literal.
// The '/' gate keeps the ~99% of strings that hold no path off the regex path
// and avoids their []byte->string copy.
func normalizedCStringBytes(value []byte, ignoreBuildTimestamps bool) []byte {
	if ignoreBuildTimestamps && compilerBuildTimestampRE.Match(value) {
		return []byte(compilerBuildTimestampPlaceholder)
	}
	if bytes.IndexByte(value, '/') < 0 {
		return value
	}
	return []byte(normalizeBuildPathForDiff(string(value)))
}

// maxCStringToken bounds how far bufio.Scanner may grow its buffer for a single
// string in a literal pool.
const maxCStringToken = 1 << 20

// splitCString is a bufio.SplitFunc yielding each NUL-terminated string in a
// literal pool, plus any unterminated tail. Empty strings between adjacent NULs
// are emitted too, so alignment padding counts toward the digest.
func splitCString(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func newCStringScanner(s *types.Section, buf []byte) *bufio.Scanner {
	sc := bufio.NewScanner(s.Open())
	// Keep the token cap independent of the input-controlled section size. A
	// malformed unterminated token then fails without driving an equally large
	// allocation, and callers fall back to the bounded raw section hash.
	limit := maxCStringToken
	if s.Size < uint64(limit) {
		limit = int(s.Size) + 1
	}
	sc.Buffer(buf, limit)
	sc.Split(splitCString)
	return sc
}

// normalizedCStringOrderedHash preserves the address order of normalized
// literals. Length prefixes keep token boundaries unambiguous after build-path
// normalization.
func normalizedCStringOrderedHash(s *types.Section, ignoreBuildTimestamps bool) (string, bool) {
	hs := hashStreamPool.Get().(*hashStream)
	defer hashStreamPool.Put(hs)
	hs.h.Reset()

	sc := newCStringScanner(s, hs.buf)
	var count uint64
	var lane [8]byte
	for sc.Scan() {
		value := normalizedCStringBytes(sc.Bytes(), ignoreBuildTimestamps)
		binary.LittleEndian.PutUint64(lane[:], uint64(len(value)))
		_, _ = hs.h.Write(lane[:])
		_, _ = hs.h.Write(value)
		count++
	}
	if sc.Err() != nil {
		return streamSHA256(s.Open())
	}
	if count == 0 {
		return "", false
	}

	var sum [sha256.Size]byte
	return hex.EncodeToString(hs.h.Sum(sum[:0])), true
}

// addCStringDigest adds a SHA-256 digest to a 256-bit wrapping accumulator.
func addCStringDigest(acc *[4]uint64, digest [sha256.Size]byte) {
	var carry uint64
	for idx := range acc {
		acc[idx], carry = bits.Add64(acc[idx], binary.LittleEndian.Uint64(digest[idx*8:(idx+1)*8]), carry)
	}
}

// normalizedCStringMultisetHash digests a section's literal pool as a
// MULTISET: every string is normalized, reduced to a SHA-256 digest, and added
// to a 256-bit wrapping accumulator. Addition is commutative and still counts
// duplicates (n copies contribute n*d). The string count is folded in as well
// so multisets of different sizes cannot agree on the accumulator alone.
//
// Discarding order is deliberate only for a default container comparison, where
// the linker may reshuffle a pool and rewrite its references as part of the same
// rebuild. That reshuffling alone accounted for 106 of the 233 dylibs still
// flagged after build-path normalization across two adjacent iOS betas.
// Standalone and explicitly allowed sections use normalizedCStringOrderedHash.
//
// Addition rather than sorting the digests keeps memory bounded and avoids the
// sorting cost while retaining a 256-bit accumulator of cryptographic digests.
//
// The section is streamed rather than slurped: __cstring runs to several MB in
// the larger dylibs, and this runs for both sides of every binary.
func normalizedCStringMultisetHash(s *types.Section, ignoreBuildTimestamps bool) (string, bool) {
	hs := hashStreamPool.Get().(*hashStream)
	defer hashStreamPool.Put(hs)

	sc := newCStringScanner(s, hs.buf)
	var acc [4]uint64
	var count uint64
	for sc.Scan() {
		addCStringDigest(&acc, sha256.Sum256(normalizedCStringBytes(sc.Bytes(), ignoreBuildTimestamps)))
		count++
	}
	if sc.Err() != nil {
		return streamSHA256(s.Open())
	}
	if count == 0 {
		return "", false
	}

	hs.h.Reset()
	var lane [8]byte
	for _, value := range acc {
		binary.LittleEndian.PutUint64(lane[:], value)
		_, _ = hs.h.Write(lane[:])
	}
	binary.LittleEndian.PutUint64(lane[:], count)
	_, _ = hs.h.Write(lane[:])
	var sum [sha256.Size]byte
	return hex.EncodeToString(hs.h.Sum(sum[:0])), true
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

// sectionContentChanges reports the sections whose hash mode or content hash
// changed while their size stayed the same. A size change already shows in the
// diff'd section list, so those are skipped; this surfaces the same-size content
// edits that dropping the per-section sha256 from DiffInfo.String would otherwise
// hide, without re-introducing the sha256 wall.
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
// section types, hash modes, or content hashes but the same size (a size change
// already shows in the diff'd section list, so it is excluded here).
func sameSizeContentChanged(oldSec, newSec section) bool {
	return oldSec.Size == newSec.Size &&
		(oldSec.Type != newSec.Type || !equivalentSectionContent(oldSec, newSec))
}

// equivalentSectionContent compares both the selected hash policy and its
// result. A missing required hash is a change; a skipped hash stays a wildcard.
func equivalentSectionContent(a, b section) bool {
	if a.HashMode != b.HashMode {
		return false
	}
	if a.HashMode != hashSkip && (a.Hash == "") != (b.Hash == "") {
		return false
	}
	return a.Hash == "" || b.Hash == "" || a.Hash == b.Hash
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
	if conf.CStrings && !equivalentNormalizedStrings(i.CStrings, x.CStrings, cstringNormalizer(conf.IgnoreBuildTimestamps)) {
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
		if a[idx].Name != b[idx].Name || a[idx].Size != b[idx].Size || a[idx].Type != b[idx].Type ||
			!equivalentSectionContent(a[idx], b[idx]) {
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
	return i.stringForDiff(nil)
}

func (i *DiffInfo) stringForDiff(conf *DiffConfig) string {
	ignoreBuildTimestamps := conf != nil && conf.IgnoreBuildTimestamps
	var out strings.Builder
	if i.Version != "" {
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
	out.WriteString(fmt.Sprintf("  CStrings:  %d\n", len(normalizedStringSet(i.CStrings, cstringNormalizer(ignoreBuildTimestamps)))))
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
