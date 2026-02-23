package macho

import (
	"strings"
	"testing"
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

func TestNormalizeCStringForDiffAnchoredPrefixOnly(t *testing.T) {
	value := "prefix /Library/Caches/com.apple.xbs/CB2898C6-8518-483E-977F-2D0117CA94BE/TemporaryDirectory.puUfSg/Sources/hfs/core/file.c"
	if got := normalizeCStringForDiff(value); got != value {
		t.Fatalf("expected non-path-prefixed CString to remain unchanged, got %q", got)
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
