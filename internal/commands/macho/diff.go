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
// per-section and per-function hashes a single GenerateDiffInfo computes, so
// section/function content is hashed incrementally instead of slurped whole
// into a []byte (Section.Data / GetFunctionData were the dominant cold-path
// allocations: ~71% of alloc-space and most of the alloc-count).
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

var xbsTemporaryBuildPathRE = regexp.MustCompile(`^/Library/Caches/com\.apple\.xbs/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/TemporaryDirectory\.[^/\s]+`)

const xbsTemporaryBuildPathPlaceholder = "/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>"

func normalizeCStringForDiff(value string) string {
	return xbsTemporaryBuildPathRE.ReplaceAllString(value, xbsTemporaryBuildPathPlaceholder)
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
					} else {
						appendFunctionHashChange(appendLine, oldInfo, newInfo, f1, f2)
					}
					consecutiveMismatch = 0
					continue
				}

				sz1 := f1.EndAddr - f1.StartAddr
				sz2 := f2.EndAddr - f2.StartAddr

				if sz1 == sz2 {
					appendFunctionHashChange(appendLine, oldInfo, newInfo, f1, f2)
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
					} else {
						appendFunctionHashChange(appendLine, oldInfo, newInfo, f1, f2)
					}
					i++
					j++
					consecutiveNoise = 0
					continue
				}

				if (f1.EndAddr - f1.StartAddr) == (f2.EndAddr - f2.StartAddr) {
					appendFunctionHashChange(appendLine, oldInfo, newInfo, f1, f2)
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
		newStrs, rmStrs := diffNormalizedCStrings(oldInfo.CStrings, newInfo.CStrings)
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
	Version        string
	UUID           string
	LoadCmdHash    string // internal structural digest; not rendered in reports
	Imports        []string
	Sections       []section
	Functions      int
	Starts         []types.Function
	FunctionHashes map[uint64]string
	Symbols        []string
	CStrings       []string
	SymbolMap      map[uint64]string
	Verbose        bool
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
		if hash, ok := sectionContentHash(s); ok {
			sec.Hash = hash
		}
		secs = append(secs, sec)
	}
	var starts []types.Function
	if fns := m.GetFunctions(); fns != nil {
		starts = fns
	}
	functionHashes := functionContentHashes(m, starts, conf)
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
		Version:        sourceVersion,
		UUID:           uuidStr,
		LoadCmdHash:    loadCmdHash,
		Imports:        m.ImportedLibraries(),
		Sections:       secs,
		Functions:      len(starts),
		Starts:         starts,
		FunctionHashes: functionHashes,
		Symbols:        syms,
		CStrings:       strs,
		SymbolMap:      smap,
		Verbose:        conf.Verbose,
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
	if s == nil || s.Size == 0 {
		return "", false
	}
	// Stream the section through the hasher rather than slurping s.Data():
	// __TEXT and DSC dylib sections are multi-MB, and this runs for every
	// included section of every binary on both sides.
	return streamSHA256(s.Open())
}

func functionContentHashes(m *macho.File, funcs []types.Function, conf *DiffConfig) map[uint64]string {
	if !conf.FuncStarts || len(funcs) == 0 {
		return nil
	}

	hashes := make(map[uint64]string, len(funcs))
	// secReader reads each containing section's bytes once and slices every
	// function out of that in-memory buffer. Functions arrive address-sorted
	// from LC_FUNCTION_STARTS, so this reads each section at most once instead
	// of issuing a pread per function (the cold-path profile showed ~66% of
	// CPU was GetFunctionData's per-function read, redundant with the section
	// content hash that already read the same code section).
	var r functionSectionReader
	for _, fn := range funcs {
		sec := m.FindSectionForVMAddr(fn.StartAddr)
		if sec != nil && !sectionIncluded(sec.Seg+"."+sec.Name, conf) {
			continue
		}
		if hash, ok := r.hash(m, sec, fn); ok {
			hashes[fn.StartAddr] = hash
		}
	}
	return hashes
}

// functionSectionReader caches the bytes of the section the previous function
// belonged to, so a run of functions in the same section reads that section
// only once. It is reset implicitly when a function maps to a different
// section.
type functionSectionReader struct {
	sec  *types.Section
	data []byte
}

// hash returns sha256(fn's bytes) as hex. It slices the function out of the
// cached section buffer when possible and falls back to a direct per-function
// read for functions with no resolvable section or whose range escapes the
// section bytes. The digest is byte-identical to hashing GetFunctionData(fn).
func (r *functionSectionReader) hash(m *macho.File, sec *types.Section, fn types.Function) (string, bool) {
	size := fn.EndAddr - fn.StartAddr
	if size == 0 {
		return "", false
	}
	if sec != nil {
		if r.sec != sec {
			data, err := sec.Data()
			if err != nil {
				r.sec, r.data = nil, nil
			} else {
				r.sec, r.data = sec, data
			}
		}
		if r.sec == sec && fn.StartAddr >= sec.Addr {
			off := fn.StartAddr - sec.Addr
			if off+size <= uint64(len(r.data)) {
				sum := sha256.Sum256(r.data[off : off+size])
				return hex.EncodeToString(sum[:]), true
			}
		}
	}
	// Fallback: unknown section, read error, or range outside the section.
	data, err := m.GetFunctionData(fn)
	if err != nil || len(data) == 0 {
		return "", false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), true
}

func appendFunctionHashChange(appendLine func(string), oldInfo, newInfo *DiffInfo, oldFunc, newFunc types.Function) {
	line, ok := functionHashChangeLine(oldInfo, newInfo, oldFunc, newFunc)
	if ok {
		appendLine(line)
	}
}

func functionHashChangeLine(oldInfo, newInfo *DiffInfo, oldFunc, newFunc types.Function) (string, bool) {
	oldHash, newHash, ok := changedFunctionHash(oldInfo, newInfo, oldFunc, newFunc)
	if !ok {
		return "", false
	}
	if oldFunc.Name != "" && oldFunc.Name == newFunc.Name {
		return fmt.Sprintf("~ %s : sha256 %s -> %s\n", oldFunc.Name, oldHash, newHash), true
	}
	return fmt.Sprintf("~ %s -> %s : sha256 %s -> %s\n", oldFunc.Name, newFunc.Name, oldHash, newHash), true
}

func changedFunctionHash(oldInfo, newInfo *DiffInfo, oldFunc, newFunc types.Function) (string, string, bool) {
	if len(oldInfo.FunctionHashes) == 0 || len(newInfo.FunctionHashes) == 0 {
		return "", "", false
	}
	oldHash := oldInfo.FunctionHashes[oldFunc.StartAddr]
	newHash := newInfo.FunctionHashes[newFunc.StartAddr]
	if oldHash == "" || newHash == "" || oldHash == newHash {
		return "", "", false
	}
	return oldHash, newHash, true
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
	if i.LoadCmdHash != "" && x.LoadCmdHash != "" && i.LoadCmdHash != x.LoadCmdHash {
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
		if sec.Hash != "" {
			out.WriteString(fmt.Sprintf("  %s: %#x sha256:%s\n", sec.Name, sec.Size, sec.Hash))
			continue
		}
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
	// Keys come from map iteration (random order); sort so the rendered diff is
	// deterministic and matches the low-memory path (which already sorts).
	slices.Sort(diff.New)
	slices.Sort(diff.Removed)

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
