package diff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSandboxMarkdownSplitsProfilesIntoSidecars locks the per-profile split: the
// README carries only headings and links, while each profile's full diff body
// lands in its own SANDBOX/<source>/<profile>.md side-car.
func TestSandboxMarkdownSplitsProfilesIntoSidecars(t *testing.T) {
	tmp := t.TempDir()
	d := &Diff{Sandbox: "### Sandbox Collection\n\n" +
		"#### New (1)\n\n##### com.apple.new\n\n```scheme\n(version 1)\n```\n\n" +
		"#### Changed (1)\n\n##### com.apple.changed\n\n```diff\n- old\n+ new\n```\n"}

	var w strings.Builder
	if err := newSandboxTask(d).Markdown(&w, tmp); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	got := w.String()

	for _, want := range []string{
		"## Sandbox Profiles",
		"### Sandbox Collection (2)",
		"#### 🆕 NEW (1)",
		"#### ⬆️ Updated (1)",
		"- [com.apple.new](SANDBOX/Sandbox-Collection/com.apple.new.md)",
		"- [com.apple.changed](SANDBOX/Sandbox-Collection/com.apple.changed.md)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("README missing %q\n%s", want, got)
		}
	}
	// Full profile bodies must live in the side-cars, never inline in the README.
	if strings.Contains(got, "(version 1)") || strings.Contains(got, "+ new") {
		t.Fatalf("profile bodies should not be inlined in the README:\n%s", got)
	}

	sidecar := filepath.Join(tmp, "SANDBOX", "Sandbox-Collection", "com.apple.changed.md")
	body, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatalf("read side-car: %v", err)
	}
	for _, want := range []string{"## com.apple.changed", "Group: ⬆️ Updated", "```diff", "+ new"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("side-car missing %q\n%s", want, body)
		}
	}
}

// TestParseSandboxMarkdownNormalizesGroupsAndRejectsGarbage covers the parser's
// group aliasing and its refusal to silently drop malformed input.
func TestParseSandboxMarkdownNormalizesGroupsAndRejectsGarbage(t *testing.T) {
	report, err := parseSandboxMarkdown("### S\n\n#### Added (1)\n\n##### p\n\n```diff\n- a\n+ b\n```\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(report.Sources) != 1 || len(report.Sources[0].Groups["Added"]) != 1 {
		t.Fatalf("Added should alias to the Added group: %+v", report)
	}

	if _, err := parseSandboxMarkdown("```diff\n- a\n+ b\n```"); err == nil {
		t.Fatal("expected error for header-less sandbox markdown")
	}
	if _, err := parseSandboxMarkdown("### S\n\n#### New (1)\n\n##### p\n\n```diff\n- a\n"); err == nil {
		t.Fatal("expected error for an incomplete fenced block")
	}
}
