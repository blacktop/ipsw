package macho

import (
	"strings"
	"testing"

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

func TestDiffInfoEqualUsesLoadCmdHash(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.LoadCmdHash = strings.Repeat("a", 64)
	newInfo.LoadCmdHash = strings.Repeat("b", 64)

	if newInfo.Equal(*oldInfo) {
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

func TestFormatUpdatedDiffOmitsLoadCommandOnlyChanges(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.LoadCmdHash = strings.Repeat("a", 64)
	newInfo.LoadCmdHash = strings.Repeat("b", 64)
	newInfo.Version = "2.0.0"
	newInfo.UUID = "22222222-2222-2222-2222-222222222222"

	out, err := FormatUpdatedDiff(oldInfo, newInfo, &DiffConfig{DiffTool: "go"})
	if err != nil {
		t.Fatalf("FormatUpdatedDiff failed: %v", err)
	}
	if out != "" {
		t.Fatalf("expected no rendered diff for a load-command-only change, got:\n%s", out)
	}
}

func TestDiffInfoEqualSkipsLoadCmdHashWhenMissingOnEitherSide(t *testing.T) {
	// Backward compatibility: if one side has no LoadCmdHash (e.g. older
	// cached DiffInfo, or a binary where loadCommandsHash returned ""),
	// Equal should not flip on the LoadCmdHash leg.
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.LoadCmdHash = ""
	newInfo.LoadCmdHash = strings.Repeat("a", 64)
	if !newInfo.Equal(*oldInfo) {
		t.Fatal("expected Equal to ignore LoadCmdHash when one side is missing")
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
		})
		if ok || hash != "" {
			t.Fatalf("sectionContentHash(%s) = (%q, %t), want no hash", flags, hash, ok)
		}
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

func TestDiffInfoEqualUsesSectionHash(t *testing.T) {
	oldInfo := baseDiffInfo()
	newInfo := baseDiffInfo()
	oldInfo.Sections[0].Hash = strings.Repeat("a", 64)
	newInfo.Sections[0].Hash = strings.Repeat("b", 64)

	if newInfo.Equal(*oldInfo) {
		t.Fatal("expected section hash changes to make diff info unequal")
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

	if !strings.Contains(out, "Sections:\n~ __DATA_CONST.__const : content changed") {
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
	if strings.Contains(out, "Sections:\n") || strings.Contains(out, "~ __DATA_CONST.__const : content changed") {
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

func TestFormatUpdatedDiffOmitsMarkdownFenceForSummaryOnlyChanges(t *testing.T) {
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
	if strings.Contains(out, "```diff") {
		t.Fatalf("expected summary-only Markdown to omit diff fence, got:\n%s", out)
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
