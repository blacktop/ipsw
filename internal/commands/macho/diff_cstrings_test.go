package macho

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomacho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func baseDiffInfo() *DiffInfo {
	return &DiffInfo{
		Version:   "1.0.0",
		UUID:      "11111111-1111-1111-1111-111111111111",
		Imports:   []string{"libSystem.B.dylib"},
		Sections:  []section{{Name: "__TEXT.__text", Size: 0x1000}},
		Functions: 1,
		Symbols:   []string{"_foo"},
	}
}

func TestDiffInfoEquivalentUsesLoadCmdHash(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.LoadCmdHash = strings.Repeat("a", 64)
	newInfo.LoadCmdHash = strings.Repeat("b", 64)

	if newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("expected differing LoadCmdHash to make diff info unequal")
	}
}

func TestDiffInfoStringOmitsLoadCmdHash(t *testing.T) {
	info := baseDiffInfo()
	info.LoadCmdHash = strings.Repeat("a", 64)
	info.Sections[0].Hash = strings.Repeat("b", 64)

	if got := info.String(); strings.Contains(got, "load_commands") || strings.Contains(got, "sha256") || strings.Contains(got, info.LoadCmdHash) {
		t.Fatalf("DiffInfo.String rendered internal hash evidence:\n%s", got)
	}
}

func TestDiffInfoStringReportsVersionWithoutVerbose(t *testing.T) {
	info := baseDiffInfo()
	got := info.String()

	if !strings.HasPrefix(got, info.Version+"\n") {
		t.Fatalf("DiffInfo.String omitted source version without verbose mode:\n%s", got)
	}
	if strings.Contains(got, info.UUID) {
		t.Fatalf("DiffInfo.String rendered UUID without verbose mode:\n%s", got)
	}
}

func TestDiffInfoStringReportsUUIDOnlyWhenVerbose(t *testing.T) {
	info := baseDiffInfo()
	info.Verbose = true

	if got := info.String(); !strings.Contains(got, info.UUID) {
		t.Fatalf("DiffInfo.String omitted UUID in verbose mode:\n%s", got)
	}
}

func TestFormatUpdatedDiffOmitsLoadCommandOnlyChanges(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.LoadCmdHash = strings.Repeat("a", 64)
	newInfo.LoadCmdHash = strings.Repeat("b", 64)

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out != "" {
		t.Fatalf("expected no rendered diff for a load-command-only change, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffReportsVersionWhenOtherMetricsDiffer(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.Version = "2.0.0"
	newInfo.UUID = "22222222-2222-2222-2222-222222222222"
	newInfo.Sections[0].Size++

	if newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("expected the section-size change to make the binary reportable")
	}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{Markdown: true, DiffTool: "git"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if !strings.Contains(out, "-1.0.0") || !strings.Contains(out, "+2.0.0") {
		t.Fatalf("expected source-version context for a reportable binary, got:\n%s", out)
	}
	if !strings.HasPrefix(out, "```diff\n") {
		t.Fatalf("expected source-version changes to use a diff fence, got:\n%s", out)
	}
	if strings.Contains(out, oldInfo.UUID) || strings.Contains(out, newInfo.UUID) {
		t.Fatalf("expected UUIDs to remain hidden without verbose mode, got:\n%s", out)
	}
}

func TestDiffInfoEquivalentIgnoresVersionWithoutVerbose(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.Version = "2.0.0"

	if !newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("expected a source-version-only change to be ignored without verbose mode")
	}
	if newInfo.Equivalent(*oldInfo, &DiffConfig{Verbose: true}) {
		t.Fatal("expected a source-version change to be detected in verbose mode")
	}
}

func TestDiffInfoEquivalentGatesUUIDOnVerbose(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.UUID = "22222222-2222-2222-2222-222222222222"

	if !newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("expected a UUID-only change to be ignored without verbose mode")
	}
	if newInfo.Equivalent(*oldInfo, &DiffConfig{Verbose: true}) {
		t.Fatal("expected a UUID-only change to be detected in verbose mode")
	}
}

func TestDiffInfoEquivalentSkipsLoadCmdHashWhenMissingOnEitherSide(t *testing.T) {
	// Backward compatibility: if one side has no LoadCmdHash (e.g. older
	// cached DiffInfo, or a binary where loadCommandsHash returned ""),
	// Equivalent should not flip on the LoadCmdHash leg.
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.LoadCmdHash = ""
	newInfo.LoadCmdHash = strings.Repeat("a", 64)
	if !newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("expected Equivalent to ignore LoadCmdHash when one side is missing")
	}
}

func TestGenerateDiffInfoCanIgnoreLoadCommands(t *testing.T) {
	m := openSelfT(t)
	withLoadCommands := GenerateDiffInfo(m, &DiffConfig{})
	if withLoadCommands.LoadCmdHash == "" {
		t.Skip("test binary did not produce a load-command hash")
	}

	withoutLoadCommands := GenerateDiffInfo(m, &DiffConfig{IgnoreLoadCommands: true})
	if withoutLoadCommands.LoadCmdHash != "" {
		t.Fatalf("LoadCmdHash = %q, want empty when IgnoreLoadCommands is set", withoutLoadCommands.LoadCmdHash)
	}
}

func TestSectionContentHashSkipsCodeSections(t *testing.T) {
	for _, flags := range []types.SectionFlag{
		types.PURE_INSTRUCTIONS,
		types.SOME_INSTRUCTIONS,
		types.SymbolStubs,
		types.SELF_MODIFYING_CODE,
	} {
		hash, ok := sectionContentHash(&types.Section{
			SectionHeader: types.SectionHeader{
				Size:  4,
				Flags: flags,
			},
		}, true)
		if ok || hash != "" {
			t.Fatalf("sectionContentHash(%s) = (%q, %t), want no hash", flags, hash, ok)
		}
	}
}

func TestSectionContentHashSkipsZeroFillSections(t *testing.T) {
	for _, flags := range []types.SectionFlag{
		types.Zerofill,
		types.GbZerofill,
		types.ThreadLocalZerofill,
	} {
		oldSection := newTestSection("__DATA", "__bss", flags, []byte{1, 2, 3, 4})
		for _, compareAllContent := range []bool{false, true} {
			if mode := sectionContentHashMode(oldSection, compareAllContent); mode != hashSkip {
				t.Errorf("sectionContentHashMode(%s, compareAllContent=%t) = %d, want hashSkip", flags, compareAllContent, mode)
			}
			hash, ok := sectionContentHash(oldSection, compareAllContent)
			if ok || hash != "" {
				t.Errorf("sectionContentHash(%s, compareAllContent=%t) = (%q, %t), want no hash", flags, compareAllContent, hash, ok)
			}
		}

		conf := &DiffConfig{IgnoreLoadCommands: true}
		oldInfo := GenerateDiffInfo(newTestMachO(oldSection), conf)
		newInfo := GenerateDiffInfo(newTestMachO(
			newTestSection("__DATA", "__bss", flags, []byte{4, 3, 2, 1}),
		), conf)
		if !newInfo.Equivalent(*oldInfo, conf) {
			t.Errorf("%s backing bytes produced a standalone diff", flags)
		}
		largerInfo := GenerateDiffInfo(newTestMachO(
			newTestSection("__DATA", "__bss", flags, []byte{0, 0, 0, 0, 0}),
		), conf)
		if largerInfo.Equivalent(*oldInfo, conf) {
			t.Errorf("%s size change was suppressed", flags)
		}
	}
}

// TestSectionContentHashMode locks both halves of the rule. In a CACHE image
// pointer tables and image-relative metadata change their bytes whenever
// anything in the cache moves, so hashing them reports a rebuild rather than a
// change. When all content is requested, same-size data edits must stay visible.
func TestSectionContentHashMode(t *testing.T) {
	for _, tc := range []struct {
		seg, name          string
		flags              types.SectionFlag
		wantCache, wantAll sectionHashMode
	}{
		// Cache-relative in a DSC/fileset image; ordinary data in a standalone
		// binary, where a changed constant is exactly what we want to report.
		{seg: "__DATA_CONST", name: "__objc_classlist", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__DATA_CONST", name: "__objc_selrefs", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__DATA_CONST", name: "__objc_superrefs", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__DATA_CONST", name: "__got", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__DATA_CONST", name: "__const", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__AUTH_CONST", name: "__const", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__AUTH_CONST", name: "__objc_const", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__AUTH_CONST", name: "__cfstring", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__AUTH", name: "__objc_data", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__DATA", name: "__data", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__const", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__objc_methlist", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__unwind_info", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__eh_frame", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__gcc_except_tab", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__swift5_typeref", wantCache: hashSkip, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__constg_swiftt", wantCache: hashSkip, wantAll: hashVerbatim},

		// Literal pools, recognized by section type. Default containers ignore
		// linker order; standalone and explicitly allowed comparisons preserve it.
		{seg: "__TEXT", name: "__cstring", flags: types.CstringLiterals, wantCache: hashCStringsMultiset, wantAll: hashCStringsOrdered},
		{seg: "__TEXT", name: "__literal4", flags: types.ByteLiterals4, wantCache: hashVerbatim, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__literal8", flags: types.ByteLiterals8, wantCache: hashVerbatim, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__literal16", flags: types.ByteLiterals16, wantCache: hashVerbatim, wantAll: hashVerbatim},

		// String runs a producer may emit as S_REGULAR. __os_log must agree with
		// go-macho's GetCStrings, which feeds the rendered CStrings list. Both
		// modes normalize build-path churn; only default containers discard order.
		{seg: "__TEXT", name: "__objc_methname", wantCache: hashCStringsMultiset, wantAll: hashCStringsOrdered},
		{seg: "__TEXT", name: "__objc_classname", wantCache: hashCStringsMultiset, wantAll: hashCStringsOrdered},
		{seg: "__TEXT", name: "__objc_methtype", wantCache: hashCStringsMultiset, wantAll: hashCStringsOrdered},
		{seg: "__TEXT", name: "__swift5_reflstr", wantCache: hashCStringsMultiset, wantAll: hashCStringsOrdered},
		{seg: "__TEXT", name: "__os_log", wantCache: hashCStringsMultiset, wantAll: hashCStringsOrdered},

		// __ustring is UTF-16: stable, but splitting on single NUL bytes would
		// be wrong, so it must be hashed verbatim.
		{seg: "__TEXT", name: "__ustring", wantCache: hashVerbatim, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__info_plist", wantCache: hashVerbatim, wantAll: hashVerbatim},
		{seg: "__TEXT", name: "__entitlements", wantCache: hashVerbatim, wantAll: hashVerbatim},
		{seg: "__DATA_CONST", name: "__objc_imageinfo", wantCache: hashVerbatim, wantAll: hashVerbatim},
	} {
		s := &types.Section{SectionHeader: types.SectionHeader{
			Seg: tc.seg, Name: tc.name, Flags: tc.flags,
		}}
		if got := sectionContentHashMode(s, false); got != tc.wantCache {
			t.Errorf("%s.%s (cache image): mode = %d, want %d", tc.seg, tc.name, got, tc.wantCache)
		}
		if got := sectionContentHashMode(s, true); got != tc.wantAll {
			t.Errorf("%s.%s (all content): mode = %d, want %d", tc.seg, tc.name, got, tc.wantAll)
		}
	}
}

// TestSectionContentHashKeepsDataForSelfContainedBinaries is the regression for
// the case the relocation filter must not swallow: two ordinary Mach-Os that
// differ only in a same-size initialized global. Nothing else moves — same
// sizes, symbols, function starts, load commands — so if __DATA.__data is not
// hashed the binaries compare equal and `ipsw diff` renders nothing.
func TestSectionContentHashKeepsDataForSelfContainedBinaries(t *testing.T) {
	oldData := newTestSection("__DATA", "__data", 0, []byte{1, 0, 0, 0})
	newData := newTestSection("__DATA", "__data", 0, []byte{2, 0, 0, 0})

	oldHash, ok := sectionContentHash(oldData, true)
	if !ok || oldHash == "" {
		t.Fatal("__DATA.__data must be hashed for a self-contained binary")
	}
	newHash, _ := sectionContentHash(newData, true)
	if oldHash == newHash {
		t.Fatal("a same-size __DATA.__data edit must change the section hash")
	}

	// The same section in a cache image stays unhashed: there the bytes are
	// cache-relative pointer slots.
	if _, ok := sectionContentHash(oldData, false); ok {
		t.Fatal("__DATA.__data must stay unhashed for a cache image")
	}
}

func TestGenerateDiffInfoKeepsDataForStaticFirmware(t *testing.T) {
	oldM := newTestMachO(newTestSection("__DATA", "__data", 0, []byte{1, 0, 0, 0}))
	newM := newTestMachO(newTestSection("__DATA", "__data", 0, []byte{2, 0, 0, 0}))

	conf := &DiffConfig{DiffTool: "go", IgnoreLoadCommands: true}
	oldInfo := GenerateDiffInfo(oldM, conf)
	newInfo := GenerateDiffInfo(newM, conf)
	if len(oldInfo.Sections) != 1 || oldInfo.Sections[0].Hash == "" {
		t.Fatal("a static firmware data section must be hashed")
	}
	if newInfo.Equivalent(*oldInfo, conf) {
		t.Fatal("a same-size __DATA.__data edit in static firmware must be reported")
	}
	out, err := FormatUpdatedDiff(oldInfo, newInfo, conf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out == "" {
		t.Fatal("expected a rendered diff for a static firmware data edit")
	}
}

func TestGenerateContainerDiffInfoHonorsExplicitAllowList(t *testing.T) {
	oldM := newTestMachO(newTestSection("__DATA", "__data", 0, []byte{1, 0, 0, 0}))
	newM := newTestMachO(newTestSection("__DATA", "__data", 0, []byte{2, 0, 0, 0}))

	defaultConf := &DiffConfig{DiffTool: "go", IgnoreLoadCommands: true}
	oldDefault := GenerateContainerDiffInfo(oldM, defaultConf)
	newDefault := GenerateContainerDiffInfo(newM, defaultConf)
	if !newDefault.Equivalent(*oldDefault, defaultConf) {
		t.Fatal("container-relative data should remain suppressed without an allow-list")
	}

	allowConf := &DiffConfig{
		DiffTool:           "go",
		IgnoreLoadCommands: true,
		AllowList:          []string{"__DATA.__data"},
	}
	oldAllowed := GenerateContainerDiffInfo(oldM, allowConf)
	newAllowed := GenerateContainerDiffInfo(newM, allowConf)
	if len(oldAllowed.Sections) != 1 || oldAllowed.Sections[0].Hash == "" {
		t.Fatal("an explicitly allowed container section must be hashed")
	}
	if newAllowed.Equivalent(*oldAllowed, allowConf) {
		t.Fatal("an explicitly allowed same-size container data edit must be reported")
	}
	out, err := FormatUpdatedDiff(oldAllowed, newAllowed, allowConf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out == "" {
		t.Fatal("expected a rendered diff for an explicitly allowed container section")
	}
}

func TestGenerateContainerDiffInfoReportsSectionClassificationTransitions(t *testing.T) {
	for _, tc := range []struct {
		name               string
		oldFlags, newFlags types.SectionFlag
		newData            []byte
	}{
		{name: "cstring", newFlags: types.CstringLiterals, newData: []byte{'b', 0, 0, 0}},
		{name: "byte literal", newFlags: types.ByteLiterals4, newData: []byte{2, 0, 0, 0}},
		{name: "zero fill", newFlags: types.Zerofill, newData: []byte{2, 0, 0, 0}},
		{name: "zero-fill kind", oldFlags: types.Zerofill, newFlags: types.ThreadLocalZerofill, newData: []byte{1, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldM := newTestMachO(newTestSection("__DATA", "__data", tc.oldFlags, []byte{1, 0, 0, 0}))
			newM := newTestMachO(newTestSection("__DATA", "__data", tc.newFlags, tc.newData))
			conf := &DiffConfig{DiffTool: "go", IgnoreLoadCommands: true}

			oldInfo := GenerateContainerDiffInfo(oldM, conf)
			newInfo := GenerateContainerDiffInfo(newM, conf)
			if newInfo.Equivalent(*oldInfo, conf) {
				t.Fatal("a same-size section classification transition must be reported")
			}
			out, err := FormatUpdatedDiff(oldInfo, newInfo, conf)
			if err != nil {
				t.Fatalf("FormatUpdatedDiff failed: %v", err)
			}
			if !strings.Contains(out, "__DATA.__data") {
				t.Fatalf("expected the classification-changing section in rendered output, got:\n%s", out)
			}
		})
	}
}

func TestCachedDiffInfoPreservesSectionClassification(t *testing.T) {
	want := &DiffInfo{Sections: []section{{
		Name:     "__TEXT.__cstring",
		Size:     4,
		Hash:     strings.Repeat("a", 64),
		Type:     types.CstringLiterals,
		HashMode: hashCStringsMultiset,
	}}}
	cacheDir := t.TempDir()
	if err := WriteCachedDiffInfo(cacheDir, "test", want); err != nil {
		t.Fatalf("WriteCachedDiffInfo failed: %v", err)
	}
	got, err := ReadCachedDiffInfo(cacheDir, "test")
	if err != nil {
		t.Fatalf("ReadCachedDiffInfo failed: %v", err)
	}
	if len(got.Sections) != 1 || got.Sections[0].Type != types.CstringLiterals || got.Sections[0].HashMode != hashCStringsMultiset {
		t.Fatalf("cached section classification = %v, want type=%v mode=%v", got.Sections, types.CstringLiterals, hashCStringsMultiset)
	}
}

func TestRequiredSectionHashAvailabilityIsCompared(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Sections[0] = section{
		Name:     "__DATA.__data",
		Size:     4,
		Hash:     strings.Repeat("a", 64),
		HashMode: hashVerbatim,
	}
	newInfo.Sections[0] = oldInfo.Sections[0]
	newInfo.Sections[0].Hash = ""

	if newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("a missing required section hash must not compare equal to an available hash")
	}
	if !sameSizeContentChanged(oldInfo.Sections[0], newInfo.Sections[0]) {
		t.Fatal("asymmetric required-hash availability must render as a section change")
	}
	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if !strings.Contains(out, "__DATA.__data") {
		t.Fatalf("expected missing hash availability to render the section, got:\n%s", out)
	}
}

// TestNormalizeBuildPathForDiffOnlyCollapsesXBSTempDirs guards the normalizer
// against collapsing paths that merely resemble a build temp dir. Over-matching
// here is a silent false negative: two different paths would compare equal.
func TestNormalizeBuildPathForDiffOnlyCollapsesXBSTempDirs(t *testing.T) {
	unchanged := []string{
		"/tmp/TemporaryDirectory.alpha/file",
		"/tmp/TemporaryDirectory.bravo/file",
		"/src/TemporaryDirectory.h",
		"/src/TemporaryDirectory.m",
		"/Library/Caches/com.apple.xbs/Sources/AlderShared/utility/TSUTemporaryDirectory.h",
		"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464A/Sources/a.c",
		"/Library/Caches/com.apple.xbs/89507FCF-0946-4F63-8219-988EAE885958A/Sources/a.c",
	}
	for _, in := range unchanged {
		if got := normalizeBuildPathForDiff(in); got != in {
			t.Errorf("normalizeBuildPathForDiff(%q) = %q, want unchanged", in, got)
		}
	}
	// Distinct non-XBS paths must stay distinct.
	if normalizeBuildPathForDiff("/tmp/TemporaryDirectory.alpha/f") == normalizeBuildPathForDiff("/tmp/TemporaryDirectory.bravo/f") {
		t.Error("non-XBS temp-dir paths must not normalize to the same value")
	}
	if normalizeBuildPathForDiff("/src/TemporaryDirectory.h") == normalizeBuildPathForDiff("/src/TemporaryDirectory.m") {
		t.Error("a real file extension must not be collapsed")
	}
	if normalizeBuildPathForDiff(unchanged[5]) == normalizeBuildPathForDiff(unchanged[6]) {
		t.Error("UUID-prefixed XBS path components with distinct suffixes must not collapse")
	}
}

// TestNormalizedCStringSectionHashBoundsTokenGrowth pins the memory bound: a
// section claiming one huge unterminated string must not drive an unbounded
// allocation off an attacker-controlled header field.
func TestNormalizedCStringSectionHashBoundsTokenGrowth(t *testing.T) {
	oldHuge := bytes.Repeat([]byte{'a'}, maxCStringToken+1) // no NUL anywhere
	newHuge := bytes.Clone(oldHuge)
	newHuge[len(newHuge)-1] = 'b'
	oldM := newTestMachO(newTestSection("__TEXT", "__cstring", types.CstringLiterals, oldHuge))
	newM := newTestMachO(newTestSection("__TEXT", "__cstring", types.CstringLiterals, newHuge))

	conf := &DiffConfig{DiffTool: "go", IgnoreLoadCommands: true}
	oldInfo := GenerateDiffInfo(oldM, conf)
	newInfo := GenerateDiffInfo(newM, conf)
	if len(oldInfo.Sections) != 1 || oldInfo.Sections[0].Hash == "" {
		t.Fatal("an over-long cstring token must fall back to a raw section hash")
	}
	rawHash, ok := streamSHA256(oldM.Sections[0].Open())
	if !ok || oldInfo.Sections[0].Hash != rawHash {
		t.Fatal("an over-long cstring token must use the bounded raw-hash fallback")
	}
	if newInfo.Equivalent(*oldInfo, conf) {
		t.Fatal("a same-size edit inside an over-long cstring token must be reported")
	}
	out, err := FormatUpdatedDiff(oldInfo, newInfo, conf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out == "" {
		t.Fatal("expected a rendered diff for an over-long cstring edit")
	}
	// A pool of ordinary strings that merely sums past the cap is still fine,
	// because the cap is per token, not per section.
	many := make([]string, 0, 4096)
	for range 4096 {
		many = append(many, strings.Repeat("b", 512))
	}
	if _, ok := sectionContentHash(cstringSection(many...), false); !ok {
		t.Fatal("a large pool of short strings must still hash")
	}
}

func newTestMachO(sections ...*types.Section) *gomacho.File {
	m := &gomacho.File{}
	m.Sections = sections
	return m
}

func newTestSection(seg, name string, flags types.SectionFlag, data []byte) *types.Section {
	s := &types.Section{SectionHeader: types.SectionHeader{
		Seg: seg, Name: name, Size: uint64(len(data)), Flags: flags,
	}}
	r := bytes.NewReader(data)
	s.SetReaders(r, io.NewSectionReader(r, 0, int64(len(data))))
	return s
}

func sectionContentHash(s *types.Section, compareAllContent bool) (string, bool) {
	return sectionContentHashWithMode(s, sectionContentHashMode(s, compareAllContent), false)
}

func cstringBlob(values ...string) []byte {
	var b bytes.Buffer
	for _, v := range values {
		b.WriteString(v)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// cstringSection builds a __TEXT.__cstring literal pool holding values.
func cstringSection(values ...string) *types.Section {
	return newTestSection("__TEXT", "__cstring", types.CstringLiterals, cstringBlob(values...))
}

// TestSectionContentHashNormalizesCStrings covers the residue behind the
// reported libORTools.dylib diff: a rotating TemporaryDirectory token is the
// same length every build, so __TEXT.__cstring keeps its size and lands in
// "Sections with Same Size but Changed Content" even after the rendered
// CStrings list cancels. The section hash has to normalize too.
func TestSectionContentHashNormalizesCStrings(t *testing.T) {
	const (
		oldPath = "/AppleInternal/Library/BuildRoots/4~B_v4ugAaKm1/Library/Caches/com.apple.xbs/TemporaryDirectory.CmqfS7/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc"
		newPath = "/AppleInternal/Library/BuildRoots/4~CAoEugDuHK1/Library/Caches/com.apple.xbs/TemporaryDirectory.gI9rxL/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc"
	)
	if len(oldPath) != len(newPath) {
		t.Fatalf("test paths must be the same length to reproduce the same-size case")
	}

	oldSec := cstringSection("shared", oldPath)
	newSec := cstringSection("shared", newPath)

	for _, compareAllContent := range []bool{false, true} {
		oldHash, ok := sectionContentHash(oldSec, compareAllContent)
		if !ok {
			t.Fatal("expected a hash for __TEXT.__cstring")
		}
		newHash, ok := sectionContentHash(newSec, compareAllContent)
		if !ok {
			t.Fatal("expected a hash for __TEXT.__cstring")
		}
		if oldHash != newHash {
			t.Fatalf("__cstring differing only by rotating build-path tokens should hash equal (compareAllContent=%t)", compareAllContent)
		}
	}
}

func TestCompilerBuildTimestampNormalizationIsOptInAndAnchored(t *testing.T) {
	for _, value := range []string{
		"02:03:04",
		"Jul 31 2026 22:43:54",
		"Jul  9 2026 02:03:04",
		"Jul 31 2026",
		"Jul 31 2026, 22:43:54",
		"Jul 31 202622:43:54",
		"Fri Jul 31 21:54:19 PDT 2026",
		"Fri Jul 31 21:54:19 2026",
	} {
		if got := normalizeCStringForDiff(value); got != value {
			t.Errorf("default normalization changed %q to %q", value, got)
		}
		if got := normalizeCStringForDiffIgnoringBuildTimestamp(value); got != compilerBuildTimestampPlaceholder {
			t.Errorf("timestamp normalization of %q = %q, want %q", value, got, compilerBuildTimestampPlaceholder)
		}
	}

	for _, value := range []string{
		"24:43:54",
		"built 22:43:54",
		"built Jul 31 2026 22:43:54",
		"Jul 31 2026 24:43:54",
		"July 31 2026 22:43:54",
		"Jul 31 2026 22:43:54 UTC",
		"Jul 31 2026T22:43:54",
		"Fri Jul 31 21:54:19 PDT 2026 trailing",
	} {
		if got := normalizeCStringForDiffIgnoringBuildTimestamp(value); got != value {
			t.Errorf("non-compiler timestamp %q normalized to %q", value, got)
		}
	}
}

func TestIgnoreBuildTimestampsSuppressesBareTimeChanges(t *testing.T) {
	const (
		oldTimestamp = "18:44:33"
		newTimestamp = "22:43:54"
	)
	oldM := newTestMachO(cstringSection(oldTimestamp))
	newM := newTestMachO(cstringSection(newTimestamp))

	conf := &DiffConfig{
		DiffTool:              "go",
		IgnoreBuildTimestamps: true,
		IgnoreLoadCommands:    true,
	}
	oldInfo := GenerateDiffInfo(oldM, conf)
	newInfo := GenerateDiffInfo(newM, conf)
	oldInfo.CStrings = []string{oldTimestamp}
	newInfo.CStrings = []string{newTimestamp}
	conf.CStrings = true

	if !newInfo.Equivalent(*oldInfo, conf) {
		t.Fatal("bare __TIME__ CString and section-hash changes must compare equal when ignored")
	}
	out, err := FormatUpdatedDiff(oldInfo, newInfo, conf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out != "" {
		t.Fatalf("bare __TIME__ diff was not suppressed:\n%s", out)
	}
}

func TestIgnoreBuildTimestampsSuppressesOnlyTimestampChanges(t *testing.T) {
	const (
		oldTimestamp = "Jul 11 2026 18:44:33"
		newTimestamp = "Jul 31 2026 22:43:54"
	)
	oldM := newTestMachO(cstringSection(oldTimestamp))
	newM := newTestMachO(cstringSection(newTimestamp))

	defaultConf := &DiffConfig{DiffTool: "go", IgnoreLoadCommands: true}
	oldDefault := GenerateDiffInfo(oldM, defaultConf)
	newDefault := GenerateDiffInfo(newM, defaultConf)
	oldDefault.CStrings = []string{oldTimestamp}
	newDefault.CStrings = []string{newTimestamp}
	defaultConf.CStrings = true
	if newDefault.Equivalent(*oldDefault, defaultConf) {
		t.Fatal("build timestamps must remain reportable by default")
	}

	ignoreConf := &DiffConfig{
		DiffTool:              "go",
		IgnoreBuildTimestamps: true,
		IgnoreLoadCommands:    true,
	}
	oldIgnored := GenerateDiffInfo(oldM, ignoreConf)
	newIgnored := GenerateDiffInfo(newM, ignoreConf)
	oldIgnored.CStrings = []string{oldTimestamp}
	newIgnored.CStrings = []string{newTimestamp}
	ignoreConf.CStrings = true
	if !newIgnored.Equivalent(*oldIgnored, ignoreConf) {
		t.Fatal("timestamp-only CString and section-hash changes must compare equal when ignored")
	}
	out, err := FormatUpdatedDiff(oldIgnored, newIgnored, ignoreConf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out != "" {
		t.Fatalf("timestamp-only diff was not suppressed:\n%s", out)
	}

	ignoreConf.CStrings = false
	oldReal := GenerateDiffInfo(newTestMachO(cstringSection(oldTimestamp, "alpha")), ignoreConf)
	newReal := GenerateDiffInfo(newTestMachO(cstringSection(newTimestamp, "bravo")), ignoreConf)
	oldReal.CStrings = []string{oldTimestamp, "alpha"}
	newReal.CStrings = []string{newTimestamp, "bravo"}
	ignoreConf.CStrings = true
	if newReal.Equivalent(*oldReal, ignoreConf) {
		t.Fatal("a real CString change alongside a timestamp must remain reportable")
	}
	out, err = FormatUpdatedDiff(oldReal, newReal, ignoreConf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if !strings.Contains(out, `+ "bravo"`) || !strings.Contains(out, `- "alpha"`) {
		t.Fatalf("real CString change missing from output:\n%s", out)
	}
	if strings.Contains(out, oldTimestamp) || strings.Contains(out, newTimestamp) {
		t.Fatalf("ignored build timestamp leaked into companion diff:\n%s", out)
	}
}

func TestSectionContentHashStillDetectsRealCStringChanges(t *testing.T) {
	oldSec := cstringSection("alpha", "beta")
	newSec := cstringSection("alpha", "gamma")

	oldHash, _ := sectionContentHash(oldSec, false)
	newHash, _ := sectionContentHash(newSec, false)
	if oldHash == newHash {
		t.Fatal("a genuinely changed cstring must still change the section hash")
	}

	// Regrouping the same bytes across the NUL boundary is a real change: the
	// pool is a multiset of strings, not a bag of bytes.
	groupedA, _ := sectionContentHash(cstringSection("ab", "c"), false)
	groupedB, _ := sectionContentHash(cstringSection("a", "bc"), false)
	if groupedA == groupedB {
		t.Fatal("regrouped strings must not collide")
	}

	// Duplicate counts are part of the multiset, so dropping one copy shows.
	dupTwice, _ := sectionContentHash(cstringSection("x", "x"), false)
	dupOnce, _ := sectionContentHash(cstringSection("x"), false)
	if dupTwice == dupOnce {
		t.Fatal("a removed duplicate must change the section hash")
	}
}

// TestSectionContentHashScopesLiteralPoolOrderToContainers keeps the DSC noise
// reduction without applying it to standalone binaries or explicit allow-list
// requests, where the byte-to-address mapping is part of the comparison.
func TestSectionContentHashScopesLiteralPoolOrderToContainers(t *testing.T) {
	forward := newTestSection("__TEXT", "__cstring", types.CstringLiterals,
		cstringBlob("alpha", "beta", "gamma"))
	shuffled := newTestSection("__TEXT", "__cstring", types.CstringLiterals,
		cstringBlob("gamma", "alpha", "beta"))

	forwardHash, ok := sectionContentHash(forward, false)
	if !ok {
		t.Fatal("expected a container hash")
	}
	shuffledHash, _ := sectionContentHash(shuffled, false)
	if forwardHash != shuffledHash {
		t.Fatal("a reordered default-container literal pool should hash equal")
	}

	forwardHash, ok = sectionContentHash(forward, true)
	if !ok {
		t.Fatal("expected a standalone hash")
	}
	shuffledHash, _ = sectionContentHash(shuffled, true)
	if forwardHash == shuffledHash {
		t.Fatal("a reordered standalone or explicitly allowed literal pool must change its hash")
	}
}

func TestGenerateDiffInfoReportsStandaloneAndAllowedLiteralPoolReordering(t *testing.T) {
	// The identical code bytes model a fixed reference to cstring offset zero:
	// only the two equal-length values at that address exchange places.
	oldM := newTestMachO(
		newTestSection("__TEXT", "__text", types.PURE_INSTRUCTIONS, []byte{0, 0, 0, 0}),
		cstringSection("alpha", "bravo"),
	)
	newM := newTestMachO(
		newTestSection("__TEXT", "__text", types.PURE_INSTRUCTIONS, []byte{0, 0, 0, 0}),
		cstringSection("bravo", "alpha"),
	)
	defaultConf := &DiffConfig{DiffTool: "go", IgnoreLoadCommands: true}

	oldStandalone := GenerateDiffInfo(oldM, defaultConf)
	newStandalone := GenerateDiffInfo(newM, defaultConf)
	if newStandalone.Equivalent(*oldStandalone, defaultConf) {
		t.Fatal("a standalone literal-pool reorder must be reported")
	}

	oldContainer := GenerateContainerDiffInfo(oldM, defaultConf)
	newContainer := GenerateContainerDiffInfo(newM, defaultConf)
	if !newContainer.Equivalent(*oldContainer, defaultConf) {
		t.Fatal("default container comparison should retain multiset semantics")
	}

	allowConf := &DiffConfig{
		DiffTool:           "go",
		IgnoreLoadCommands: true,
		AllowList:          []string{"__TEXT.__cstring"},
	}
	oldAllowed := GenerateContainerDiffInfo(oldM, allowConf)
	newAllowed := GenerateContainerDiffInfo(newM, allowConf)
	if newAllowed.Equivalent(*oldAllowed, allowConf) {
		t.Fatal("an explicitly allowed container literal-pool reorder must be reported")
	}
	out, err := FormatUpdatedDiff(oldAllowed, newAllowed, allowConf)
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if !strings.Contains(out, "__TEXT.__cstring") {
		t.Fatalf("expected reordered allow-listed literal pool in output, got:\n%s", out)
	}
}

func TestAddCStringDigestCarriesAcrossFullAccumulator(t *testing.T) {
	acc := [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	var digest [sha256.Size]byte
	binary.LittleEndian.PutUint64(digest[:8], 1)
	addCStringDigest(&acc, digest)
	if acc != [4]uint64{} {
		t.Fatalf("256-bit accumulator did not carry across every lane: %#v", acc)
	}
}

// TestContainerDiffCallersUseContainerPolicy is the call-site guard paired with
// the behavioral GenerateContainerDiffInfo tests above. It catches accidental
// rerouting through the standalone default before a real DSC/fileset run floods
// the report with relocation noise.
func TestContainerDiffCallersUseContainerPolicy(t *testing.T) {
	for _, tc := range []struct {
		path      string
		wantCalls int
	}{
		{path: filepath.Join("..", "dsc", "diff.go"), wantCalls: 2},
		{path: filepath.Join("..", "kernel", "diff.go"), wantCalls: 2},
	} {
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if got := bytes.Count(data, []byte("mcmd.GenerateContainerDiffInfo(")); got != tc.wantCalls {
			t.Errorf("%s container calls = %d, want %d", tc.path, got, tc.wantCalls)
		}
		if bytes.Contains(data, []byte("mcmd.GenerateDiffInfo(")) {
			t.Errorf("%s routes a container image through standalone GenerateDiffInfo", tc.path)
		}
	}
}

// TestSectionContentHashNormalizesAcrossReadBoundary exercises scanner refills:
// a build path that straddles the initial buffer boundary must still be
// reassembled before normalization.
func TestSectionContentHashNormalizesAcrossReadBoundary(t *testing.T) {
	const (
		oldPath = "/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Sources/a.c"
		newPath = "/Library/Caches/com.apple.xbs/89507FCF-0946-4F63-8219-988EAE885958/TemporaryDirectory.6Xk4l2/Sources/a.c"
	)
	// Start the path before the scanner's refill boundary and end it after, so
	// the token must be reassembled across two reads.
	filler := strings.Repeat("a", hashStreamBufSize-len(oldPath)/2)

	oldSec := cstringSection(filler, oldPath)
	newSec := cstringSection(filler, newPath)

	oldHash, ok := sectionContentHash(oldSec, false)
	if !ok {
		t.Fatal("expected a hash")
	}
	newHash, _ := sectionContentHash(newSec, false)
	if oldHash != newHash {
		t.Fatal("a build path straddling a read boundary should still normalize")
	}
}

func TestGenerateDiffInfoSkipsCodeSectionHashes(t *testing.T) {
	m := openSelfT(t)
	info := GenerateDiffInfo(m, &DiffConfig{})
	if len(info.Sections) != len(m.Sections) {
		t.Fatalf("sections = %d, want %d", len(info.Sections), len(m.Sections))
	}

	sawSkippedSection := false
	for idx, raw := range m.Sections {
		if !sectionContainsCode(raw) {
			continue
		}
		sawSkippedSection = true
		if got := info.Sections[idx].Hash; got != "" {
			t.Fatalf("%s.%s hash = %q, want empty for code section", raw.Seg, raw.Name, got)
		}
	}
	if !sawSkippedSection {
		t.Skip("test binary has no skipped code sections")
	}
}

func TestDiffInfoEquivalentUsesSectionHash(t *testing.T) {
	configs := []struct {
		name string
		conf *DiffConfig
	}{
		{name: "ordinary Mach-O", conf: &DiffConfig{}},
		{name: "DSC", conf: &DiffConfig{IgnoreLoadCommands: true}},
	}
	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			oldInfo := baseDiffInfo()
			newInfo := baseDiffInfo()
			oldInfo.Sections[0].Hash = strings.Repeat("a", 64)
			newInfo.Sections[0].Hash = strings.Repeat("b", 64)

			if newInfo.Equivalent(*oldInfo, tc.conf) {
				t.Fatal("expected section hash changes to make diff info unequal")
			}
		})
	}
}

func TestFormatUpdatedDiffReportsSameSizeSectionHashChanges(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldHash := strings.Repeat("a", 64)
	newHash := strings.Repeat("b", 64)
	oldInfo.Sections[0].Name = "__DATA_CONST.__const"
	newInfo.Sections[0].Name = "__DATA_CONST.__const"
	oldInfo.Sections[0].Hash = oldHash
	newInfo.Sections[0].Hash = newHash

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}

	if !strings.Contains(out, "Sections with same size but changed content:\n- __DATA_CONST.__const") {
		t.Fatalf("expected section content change summary in output, got:\n%s", out)
	}
	if strings.Contains(out, "size unchanged") {
		t.Fatalf("expected section content summary to omit unchanged size, got:\n%s", out)
	}
	if strings.Contains(out, "sha256") || strings.Contains(out, oldHash) || strings.Contains(out, newHash) {
		t.Fatalf("expected section hashes to stay hidden, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffDoesNotDuplicateSizeChangedSectionHash(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Sections[0] = section{Name: "__DATA_CONST.__const", Size: 0x100, Hash: strings.Repeat("a", 64)}
	newInfo.Sections[0] = section{Name: "__DATA_CONST.__const", Size: 0x200, Hash: strings.Repeat("b", 64)}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out == "" {
		t.Fatal("expected section size diff output")
	}
	if got := strings.Count(out, "__DATA_CONST.__const"); got != 1 {
		t.Fatalf("section size change rendered %d times, want 1; output:\n%s", got, out)
	}
	if strings.Contains(out, "content changed (0x100 -> 0x200)") {
		t.Fatalf("expected size change to omit sized content-change row, got:\n%s", out)
	}
	if strings.Contains(out, "Sections with same size but changed content:\n") || strings.Contains(out, "- __DATA_CONST.__const") {
		t.Fatalf("expected size change to be reported only by the git diff block, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffOmitsSameSizeFunctionHashNoise(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldSectionHash := strings.Repeat("a", 64)
	newSectionHash := strings.Repeat("b", 64)
	fn := types.Function{StartAddr: 0x1000, EndAddr: 0x1020}
	oldInfo.Sections[0].Hash = oldSectionHash
	newInfo.Sections[0].Hash = newSectionHash
	oldInfo.Starts = []types.Function{fn}
	newInfo.Starts = []types.Function{fn}
	oldInfo.SymbolMap = map[uint64]string{fn.StartAddr: "_foo"}
	newInfo.SymbolMap = map[uint64]string{fn.StartAddr: "_foo"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{
		DiffTool:   "go",
		FuncStarts: true,
	})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}

	if strings.Contains(out, "Functions:") || strings.Contains(out, "sha256") {
		t.Fatalf("expected same-size function bytes to stay out of report, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffUsesMarkdownForSectionSummary(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Sections[0].Hash = strings.Repeat("a", 64)
	newInfo.Sections[0].Hash = strings.Repeat("b", 64)

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{
		Markdown: true,
		DiffTool: "go",
	})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	want := "### Sections with Same Size but Changed Content\n\n- `__TEXT.__text`\n"
	if out != want {
		t.Fatalf("expected same-size section changes to render as Markdown, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffUsesTextFenceForFunctionSummary(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Starts = []types.Function{{StartAddr: 0x1000, EndAddr: 0x1020}}
	newInfo.Starts = []types.Function{{StartAddr: 0x1000, EndAddr: 0x1021}}
	oldInfo.SymbolMap = map[uint64]string{0x1000: "_foo"}
	newInfo.SymbolMap = map[uint64]string{0x1000: "_foo"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{Markdown: true, DiffTool: "go", FuncStarts: true})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	want := "```text\nFunctions:\n~ _foo : 32 -> 33\n```\n"
	if out != want {
		t.Fatalf("expected function summary Markdown to use a text fence, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffUsesDiffFenceForMixedSummaryAndDiffRows(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Sections[0].Hash = strings.Repeat("a", 64)
	newInfo.Sections[0].Hash = strings.Repeat("b", 64)
	oldInfo.CStrings = []string{"old"}
	newInfo.CStrings = []string{"new"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{Markdown: true, DiffTool: "go", CStrings: true})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if !strings.Contains(out, "\n```diff\n") {
		t.Fatalf("expected added/removed rows to use a diff fence, got:\n%s", out)
	}
	if !strings.HasPrefix(out, "### Sections with Same Size but Changed Content\n\n- `__TEXT.__text`\n") {
		t.Fatalf("expected section summary list in mixed output, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffLeavesPlainTextUnfenced(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Sections[0].Hash = strings.Repeat("a", 64)
	newInfo.Sections[0].Hash = strings.Repeat("b", 64)

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if strings.Contains(out, "```") {
		t.Fatalf("expected non-Markdown output to remain unfenced, got:\n%s", out)
	}
}

func TestDiffInfoEquivalentDetectsEqualCountSemanticReplacements(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Symbols = []string{"_old"}
	newInfo.Symbols = []string{"_new"}
	oldInfo.CStrings = []string{"old"}
	newInfo.CStrings = []string{"new"}

	if newInfo.Equivalent(*oldInfo, &DiffConfig{CStrings: true}) {
		t.Fatal("expected equal-count symbol and CString replacements to be detected")
	}
}

func TestDiffInfoEquivalentCancelsNormalizedBuildChurn(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Symbols = []string{"___block_literal_global.680"}
	newInfo.Symbols = []string{"___block_literal_global.686"}
	oldInfo.CStrings = []string{"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Sources/a.c"}
	newInfo.CStrings = []string{"/Library/Caches/com.apple.xbs/89507FCF-0946-4F63-8219-988EAE885958/TemporaryDirectory.6Xk4l2/Sources/a.c"}

	if !newInfo.Equivalent(*oldInfo, &DiffConfig{CStrings: true}) {
		t.Fatal("expected normalized build-path and counter churn to cancel")
	}
}

func TestDiffInfoEquivalentUsesFunctionSizeSequence(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Starts = []types.Function{{StartAddr: 0x1000, EndAddr: 0x1020}}
	newInfo.Starts = []types.Function{{StartAddr: 0x2000, EndAddr: 0x2020}}

	if !newInfo.Equivalent(*oldInfo, &DiffConfig{FuncStarts: true}) {
		t.Fatal("expected shifted functions with identical sizes to be equivalent")
	}
	newInfo.Starts[0].EndAddr++
	if newInfo.Equivalent(*oldInfo, &DiffConfig{FuncStarts: true}) {
		t.Fatal("expected a function-size change to be detected")
	}
}

func TestDiffInfoEquivalentUsesFunctionCountWithoutStarts(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.Functions++

	if newInfo.Equivalent(*oldInfo, &DiffConfig{}) {
		t.Fatal("expected a report-visible function-count change to be detected without --starts")
	}
}

func TestFormatUpdatedDiffOmitsNormalizedSetCountChurn(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Symbols = []string{"___block_literal_global.680", "___block_literal_global.681"}
	newInfo.Symbols = []string{"___block_literal_global.686"}
	oldInfo.CStrings = []string{"same", "same"}
	newInfo.CStrings = []string{"same"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go", CStrings: true})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out != "" {
		t.Fatalf("expected normalized set-equivalent count churn to render nothing, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffIgnoresXBSTemporaryBuildPathCStrings(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.UUID = "22222222-2222-2222-2222-222222222222"

	oldInfo.CStrings = []string{
		"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Sources/hfs/core/file.c",
	}
	newInfo.CStrings = []string{
		"/Library/Caches/com.apple.xbs/CB2898C6-8518-483E-977F-2D0117CA94BE/TemporaryDirectory.puUfSg/Sources/hfs/core/file.c",
	}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{
		DiffTool: "go",
		CStrings: true,
	})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}

	if strings.Contains(out, "CStrings:\n") {
		t.Fatalf("expected noisy XBS temp-path cstrings to be ignored, got:\n%s", out)
	}
	if strings.Contains(out, "/Library/Caches/com.apple.xbs/") {
		t.Fatalf("expected no XBS temp path in output, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffStillReportsNonIgnoredCStrings(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.UUID = "33333333-3333-3333-3333-333333333333"

	oldInfo.CStrings = []string{"legacy/path/value"}
	newInfo.CStrings = []string{"new/path/value"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{
		DiffTool: "go",
		CStrings: true,
	})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}

	if !strings.Contains(out, "CStrings:\n") {
		t.Fatalf("expected CStrings section for non-ignored differences, got:\n%s", out)
	}
	if !strings.Contains(out, `+ "new/path/value"`) {
		t.Fatalf("expected added CString in output, got:\n%s", out)
	}
	if !strings.Contains(out, `- "legacy/path/value"`) {
		t.Fatalf("expected removed CString in output, got:\n%s", out)
	}
}

// TestNormalizeCStringForDiffNormalizesEmbeddedBuildPath covers build paths that
// appear mid-string (e.g. libmalloc assertion messages), which the linker
// re-tokenizes every build. The normalizer is unanchored so these collapse and
// cancel instead of churning.
func TestNormalizeCStringForDiffNormalizesEmbeddedBuildPath(t *testing.T) {
	value := `"BUG IN LIBMALLOC: malloc assertion \"zone\" failed (/Library/Caches/com.apple.xbs/CB2898C6-8518-483E-977F-2D0117CA94BE/TemporaryDirectory.puUfSg/Sources/x/y.c:114)"`
	want := `"BUG IN LIBMALLOC: malloc assertion \"zone\" failed (/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>/Sources/x/y.c:114)"`
	if got := normalizeCStringForDiff(value); got != want {
		t.Fatalf("normalizeCStringForDiff(%q) = %q, want %q", value, got, want)
	}

	// Two builds of the same assertion differ only by the rotating UUID/TMP;
	// after normalization they must be identical (so they cancel in the diff).
	old := "assert (/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Sources/a.c:9)"
	newer := "assert (/Library/Caches/com.apple.xbs/89507FCF-0946-4F63-8219-988EAE885958/TemporaryDirectory.6Xk4l2/Sources/a.c:9)"
	if normalizeCStringForDiff(old) != normalizeCStringForDiff(newer) {
		t.Fatalf("embedded XBS paths differing only by token should normalize equal:\n old=%q\n new=%q",
			normalizeCStringForDiff(old), normalizeCStringForDiff(newer))
	}
}

// TestNormalizeBuildPathForDiffTemporaryDirectoryVariants covers the three
// combinations Apple emits: the XBS UUID alone, UUID + TemporaryDirectory, and
// a build root whose XBS path has no UUID component at all (the last one
// escaped normalization and still churned in `ipsw diff` output).
func TestNormalizeBuildPathForDiffTemporaryDirectoryVariants(t *testing.T) {
	cases := map[string]string{
		"/AppleInternal/Library/BuildRoots/4~CAoEugDuHK1/Library/Caches/com.apple.xbs/TemporaryDirectory.gI9rxL/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc": "/AppleInternal/Library/BuildRoots/<BUILDROOT>/Library/Caches/com.apple.xbs/TemporaryDirectory.<TMP>/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc",
		"/AppleInternal/Library/BuildRoots/4~B_v4ugAaKm1/Library/Caches/com.apple.xbs/TemporaryDirectory.CmqfS7/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc": "/AppleInternal/Library/BuildRoots/<BUILDROOT>/Library/Caches/com.apple.xbs/TemporaryDirectory.<TMP>/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc",
		"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464":                                                                                                "/Library/Caches/com.apple.xbs/<UUID>",
		"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Sources/a.c":                                                          "/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>/Sources/a.c",
		"/Library/Caches/com.apple.xbs/CB2898C6-8518-483E-977F-2D0117CA94BE/Sources/hfs/core/file.c":                                                                        "/Library/Caches/com.apple.xbs/<UUID>/Sources/hfs/core/file.c",
		// Real source file names that merely end in "TemporaryDirectory" keep
		// their extension: only a whole path component may be collapsed.
		"/Library/Caches/com.apple.xbs/Sources/AlderShared/utility/TSUTemporaryDirectory.h": "/Library/Caches/com.apple.xbs/Sources/AlderShared/utility/TSUTemporaryDirectory.h",
		"_PFTemporaryDirectory.cold.1": "_PFTemporaryDirectory.cold.1",
	}
	for in, want := range cases {
		if got := normalizeBuildPathForDiff(in); got != want {
			t.Errorf("normalizeBuildPathForDiff(%q) =\n %q, want\n %q", in, got, want)
		}
	}
}

func TestFormatUpdatedDiffIgnoresBuildRootTemporaryDirectoryCStrings(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()

	oldInfo.CStrings = []string{
		"/AppleInternal/Library/BuildRoots/4~B_v4ugAaKm1/Library/Caches/com.apple.xbs/TemporaryDirectory.CmqfS7/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc",
	}
	newInfo.CStrings = []string{
		"/AppleInternal/Library/BuildRoots/4~CAoEugDuHK1/Library/Caches/com.apple.xbs/TemporaryDirectory.gI9rxL/Sources/ANECompiler/ext/or-tools/src/ortools/util/stats.cc",
	}

	if !newInfo.Equivalent(*oldInfo, &DiffConfig{CStrings: true}) {
		t.Fatal("expected rotating TemporaryDirectory tokens to cancel")
	}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go", CStrings: true})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out != "" {
		t.Fatalf("expected no rendered diff for TemporaryDirectory churn, got:\n%s", out)
	}
}

func TestFormatUpdatedDiffReportsTailChangesAfterXBSNormalization(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	newInfo.UUID = "44444444-4444-4444-4444-444444444444"

	oldInfo.CStrings = []string{
		"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Sources/hfs/core/file_a.c",
	}
	newInfo.CStrings = []string{
		"/Library/Caches/com.apple.xbs/CB2898C6-8518-483E-977F-2D0117CA94BE/TemporaryDirectory.puUfSg/Sources/hfs/core/file_b.c",
	}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{
		DiffTool: "go",
		CStrings: true,
	})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}

	if !strings.Contains(out, "CStrings:\n") {
		t.Fatalf("expected CStrings section when normalized suffix differs, got:\n%s", out)
	}
	if !strings.Contains(out, `/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>/Sources/hfs/core/file_a.c`) {
		t.Fatalf("expected normalized removed CString in output, got:\n%s", out)
	}
	if !strings.Contains(out, `/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>/Sources/hfs/core/file_b.c`) {
		t.Fatalf("expected normalized added CString in output, got:\n%s", out)
	}
}

func TestNormalizeSymbolForDiff(t *testing.T) {
	cases := map[string]string{
		"___28-[BTSDevicesController init]_block_invoke.323":             "___28-[BTSDevicesController init]_block_invoke",
		"___28-[BTSDevicesController init]_block_invoke.317":             "___28-[BTSDevicesController init]_block_invoke",
		"___52-[C migrateHKPairedHealthDevices]_block_invoke.870.cold.1": "___52-[C migrateHKPairedHealthDevices]_block_invoke",
		"___50-[C startOutgoingCarPlaySetup:]_block_invoke_2.857":        "___50-[C startOutgoingCarPlaySetup:]_block_invoke_2",
		"___block_literal_global.686":                                    "___block_literal_global",
		"_OBJC_CLASS_$_NSMutableDictionary":                              "_OBJC_CLASS_$_NSMutableDictionary",
		"/Library/Caches/com.apple.xbs/20022CBB-7987-4277-B5C3-995958015464/TemporaryDirectory.VvPQcD/Binaries/x.a(sha256.o)": "/Library/Caches/com.apple.xbs/<UUID>/TemporaryDirectory.<TMP>/Binaries/x.a(sha256.o)",
		"/AppleInternal/Library/BuildRoots/4~CReaugCYOfRv/SDKs/iPhoneOS.Internal.sdk/x.a(y.o)":                                "/AppleInternal/Library/BuildRoots/<BUILDROOT>/SDKs/iPhoneOS.Internal.sdk/x.a(y.o)",
	}
	for in, want := range cases {
		if got := normalizeSymbolForDiff(in); got != want {
			t.Errorf("normalizeSymbolForDiff(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFormatUpdatedDiffCancelsRenumberedLocalSymbols locks the counter-strip:
// the same block/global with a different linker-assigned .NNN counter must not
// show as churn.
func TestFormatUpdatedDiffCancelsRenumberedLocalSymbols(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Symbols = []string{"___28-[C init]_block_invoke.317", "___block_literal_global.680"}
	newInfo.Symbols = []string{"___28-[C init]_block_invoke.323", "___block_literal_global.686"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if strings.Contains(out, "Symbols:") {
		t.Fatalf("renumbered local symbols should cancel, got:\n%s", out)
	}
	if strings.Contains(out, "block_invoke") || strings.Contains(out, "block_literal_global") {
		t.Fatalf("expected no renumbered-symbol churn, got:\n%s", out)
	}
}

// TestFormatUpdatedDiffReportsGenuinelyNewSymbolFamily confirms a truly new
// local symbol still surfaces (normalized, without its counter).
func TestFormatUpdatedDiffReportsGenuinelyNewSymbolFamily(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Symbols = []string{"_foo"}
	newInfo.Symbols = []string{"_foo", "-[NewClass newMethod]_block_invoke.42"}

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if !strings.Contains(out, "Symbols:") {
		t.Fatalf("a genuinely new symbol family should show, got:\n%s", out)
	}
	if !strings.Contains(out, "+ -[NewClass newMethod]_block_invoke") {
		t.Fatalf("expected normalized new symbol, got:\n%s", out)
	}
	if strings.Contains(out, ".42") {
		t.Fatalf("counter should be stripped from the reported symbol, got:\n%s", out)
	}
}
