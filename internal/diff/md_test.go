package diff

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
)

// smallDiff is a tiny rendered diff body used to populate Updated maps.
const smallDiff = "```diff\n- a\n+ b\n```"

// countMD counts the .md files under root recursively (side-cars now mirror the
// entry's path, so they live in nested folders).
func countMD(root string) int {
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
			n++
		}
		return nil
	})
	return n
}

// sec builds a MACHOS-rooted listSection with an explicit spill threshold
// (spillAt 0 = the package default of listSpillThreshold).
func sec(tag, title string, spillAt int) listSection {
	return listSection{headingPrefix: "####", title: title, tag: tag, subDir: "MACHOS", label: "SystemOS", spillAt: spillAt}
}

func updatedMap(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("/usr/lib/lib%03d.dylib", i)] = smallDiff
	}
	return m
}

func names(n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("/usr/lib/lib%03d.dylib", i)
	}
	return out
}

// --- Updated -----------------------------------------------------------------

// TestRenderUpdatedEntriesPlainUnderCollapse: < listCollapseThreshold entries
// render as a plain (no <details>) list of links, one per-file doc each.
func TestRenderUpdatedEntriesPlainUnderCollapse(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	updated := updatedMap(2)

	if err := renderUpdatedEntries(&out, sec("Updated", "⬆️ Updated", 0), updated, dir, filepath.Base); err != nil {
		t.Fatalf("renderUpdatedEntries: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "<details>") {
		t.Errorf("a small Updated list must render plain (no <details>), got:\n%s", got)
	}
	if strings.Contains(got, "```diff") {
		t.Errorf("Updated diffs must never be inlined, got:\n%s", got)
	}
	if links := strings.Count(got, "](MACHOS/"); links != len(updated) {
		t.Errorf("expected %d inline links, got %d:\n%s", len(updated), links, got)
	}
	if got := countMD(filepath.Join(dir, "MACHOS")); got != len(updated) {
		t.Fatalf("expected %d per-file docs, got %d", len(updated), got)
	}
}

// TestRenderUpdatedEntriesCollapsedAboveThreshold: >= listCollapseThreshold but
// below the spill threshold renders the full link list inside a <details>.
func TestRenderUpdatedEntriesCollapsedAboveThreshold(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	updated := updatedMap(listCollapseThreshold)

	if err := renderUpdatedEntries(&out, sec("Updated", "⬆️ Updated", 0), updated, dir, filepath.Base); err != nil {
		t.Fatalf("renderUpdatedEntries: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "<details>") || !strings.Contains(got, "</details>") {
		t.Errorf("a mid-size Updated list must be collapsed in <details>, got:\n%s", got)
	}
	if strings.Contains(got, "](MACHOS/SystemOS.Updated.md)") {
		t.Errorf("a mid-size Updated list must stay in the README, not spill, got:\n%s", got)
	}
	if links := strings.Count(got, "](MACHOS/"); links != len(updated) {
		t.Errorf("expected the full %d-link list in the README, got %d", len(updated), links)
	}
}

// TestRenderUpdatedEntriesSpillsAtThreshold: >= spillAt spills the full list to
// a side-car doc; the README shows a single link.
func TestRenderUpdatedEntriesSpillsAtThreshold(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	updated := updatedMap(5)

	if err := renderUpdatedEntries(&out, sec("Updated", "⬆️ Updated", 3), updated, dir, filepath.Base); err != nil {
		t.Fatalf("renderUpdatedEntries: %v", err)
	}

	got := out.String()
	want := fmt.Sprintf("- [View %d updated files](MACHOS/SystemOS.Updated.md)", len(updated))
	if !strings.Contains(got, want) {
		t.Errorf("expected single spill link %q, got:\n%s", want, got)
	}
	if strings.Contains(got, "<details>") {
		t.Errorf("a spilled Updated list should not render a <details> in the README, got:\n%s", got)
	}

	listDoc, err := os.ReadFile(filepath.Join(dir, "MACHOS", "SystemOS.Updated.md"))
	if err != nil {
		t.Fatalf("read spill list doc: %v", err)
	}
	if links := strings.Count(string(listDoc), "]("); links != len(updated) {
		t.Errorf("spill list doc should hold all %d links, got %d", len(updated), links)
	}
	if strings.Contains(string(listDoc), "](MACHOS/") {
		t.Errorf("spill list doc links must be relative to itself (no MACHOS/ prefix):\n%s", listDoc)
	}
	if got := countMD(filepath.Join(dir, "MACHOS")); got != len(updated)+1 {
		t.Fatalf("expected %d per-file docs + 1 list doc, got %d", len(updated), got)
	}
}

// TestRenderUpdatedEntriesSpillWithGroupDir: when a section has a groupDir
// (volume) and spills, per-entry docs live under the volume folder and the
// spilled list doc's links are relative to it (include the volume folder).
func TestRenderUpdatedEntriesSpillWithGroupDir(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	updated := updatedMap(4)
	s := listSection{headingPrefix: "####", title: "⬆️ Updated", tag: "Updated", subDir: "MACHOS", label: "SystemOS", groupDir: "SystemOS", spillAt: 3}

	if err := renderUpdatedEntries(&out, s, updated, dir, filepath.Base); err != nil {
		t.Fatalf("renderUpdatedEntries: %v", err)
	}

	if !strings.Contains(out.String(), "](MACHOS/SystemOS.Updated.md)") {
		t.Errorf("expected README spill link to MACHOS/SystemOS.Updated.md, got:\n%s", out.String())
	}
	if got := countMD(filepath.Join(dir, "MACHOS", "SystemOS")); got != len(updated) {
		t.Fatalf("expected %d per-entry docs under MACHOS/SystemOS, got %d", len(updated), got)
	}
	listDoc, err := os.ReadFile(filepath.Join(dir, "MACHOS", "SystemOS.Updated.md"))
	if err != nil {
		t.Fatalf("read spill list doc: %v", err)
	}
	if !strings.Contains(string(listDoc), "](SystemOS/") {
		t.Errorf("spill list-doc links must include the volume folder (relative to the doc), got:\n%s", listDoc)
	}
	if strings.Contains(string(listDoc), "](MACHOS/") {
		t.Errorf("spill list-doc links must not be README-relative, got:\n%s", listDoc)
	}
}

// TestRenderUpdatedEntriesEmpty: empty map emits nothing and creates no dir.
func TestRenderUpdatedEntriesEmpty(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	if err := renderUpdatedEntries(&out, sec("Updated", "⬆️ Updated", 0), nil, dir, filepath.Base); err != nil {
		t.Fatalf("renderUpdatedEntries: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output for empty Updated map, got:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "MACHOS")); !os.IsNotExist(err) {
		t.Errorf("MACHOS dir should not be created for an empty Updated map")
	}
}

// --- Name lists (NEW / Removed) ----------------------------------------------

// TestRenderNameListPlainUnderCollapse: < listCollapseThreshold names render as
// a plain bullet list with no <details> and no side-car file.
func TestRenderNameListPlainUnderCollapse(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder

	if err := renderNameList(&out, sec("NEW", "🆕 NEW", 0), names(2), dir); err != nil {
		t.Fatalf("renderNameList: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "<details>") {
		t.Errorf("a small NEW list must render plain (no <details>), got:\n%s", got)
	}
	if !strings.Contains(got, "- `/usr/lib/lib000.dylib`") {
		t.Errorf("a small NEW list must render inline bullets, got:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "MACHOS")); !os.IsNotExist(err) {
		t.Errorf("MACHOS dir should not be created for a small NEW list")
	}
}

// TestRenderNameListCollapsedAboveThreshold: >= listCollapseThreshold but below
// the spill threshold renders the full list inside a <details>.
func TestRenderNameListCollapsedAboveThreshold(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder

	if err := renderNameList(&out, sec("NEW", "🆕 NEW", 0), names(listCollapseThreshold), dir); err != nil {
		t.Fatalf("renderNameList: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "<details>") {
		t.Errorf("a mid-size NEW list must be collapsed in <details>, got:\n%s", got)
	}
	if strings.Contains(got, "](MACHOS/") {
		t.Errorf("a mid-size NEW list must stay in the README, not spill, got:\n%s", got)
	}
	if c := strings.Count(got, "- `"); c != listCollapseThreshold {
		t.Errorf("expected the full %d-name list, got %d", listCollapseThreshold, c)
	}
}

// TestRenderNameListSpillsAtThreshold: >= spillAt spills the full name list to a
// side-car doc; README shows a single link. Mirrors the `## Files` behavior.
func TestRenderNameListSpillsAtThreshold(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	ns := names(5)

	if err := renderNameList(&out, sec("NEW", "🆕 NEW", 3), ns, dir); err != nil {
		t.Fatalf("renderNameList: %v", err)
	}

	got := out.String()
	want := fmt.Sprintf("- [View %d new files](MACHOS/SystemOS.NEW.md)", len(ns))
	if !strings.Contains(got, want) {
		t.Errorf("expected single spill link %q, got:\n%s", want, got)
	}
	body, err := os.ReadFile(filepath.Join(dir, "MACHOS", "SystemOS.NEW.md"))
	if err != nil {
		t.Fatalf("read spill name list: %v", err)
	}
	if c := strings.Count(string(body), "- `"); c != len(ns) {
		t.Errorf("spill doc should contain all %d names, got %d", len(ns), c)
	}
}

// TestRenderBinStringListLinksBins: iBoot-style section renders each bin as a
// link, with its strings written to a side-car (## bin + bullets, no path quote).
func TestRenderBinStringListLinksBins(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	bins := map[string][]string{
		"iBoot.A": {"maybe one", "maybe two"},
		"iBEC.B":  {"maybe three"},
	}
	section := listSection{headingPrefix: "####", title: "🆕 NEW", tag: "NEW", subDir: "IBOOT", label: "iBoot", groupDir: "NEW"}

	if err := renderBinStringList(&out, section, bins, dir); err != nil {
		t.Fatalf("renderBinStringList: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "<details>") {
		t.Errorf("a small bin list must render plain, got:\n%s", got)
	}
	if strings.Contains(got, "maybe one") {
		t.Errorf("bin strings must not be inlined in the README, got:\n%s", got)
	}
	if links := strings.Count(got, "](IBOOT/NEW/"); links != len(bins) {
		t.Errorf("expected %d bin links under IBOOT/NEW/, got %d:\n%s", len(bins), links, got)
	}

	docs, _ := filepath.Glob(filepath.Join(dir, "IBOOT", "NEW", "*.md"))
	if len(docs) != len(bins) {
		t.Fatalf("expected %d side-car docs, got %d", len(bins), len(docs))
	}
	found := false
	for _, p := range docs {
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), "## iBoot.A") {
			continue
		}
		found = true
		if !strings.Contains(string(b), "- `maybe one`") || !strings.Contains(string(b), "- `maybe two`") {
			t.Errorf("iBoot.A side-car missing its strings:\n%s", b)
		}
		if strings.Contains(string(b), "> `") {
			t.Errorf("iBoot side-car should have no source-path quote line:\n%s", b)
		}
	}
	if !found {
		t.Fatalf("did not find the iBoot.A side-car among %v", docs)
	}
}

// TestRenderBinStringListNewRemovedSameBinDistinctDocs: a bin that appears in
// both NEW and Removed lands in separate NEW/Removed folders, so its strings
// stay distinct instead of one clobbering the other.
func TestRenderBinStringListNewRemovedSameBinDistinctDocs(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	bin := "iBoot.IBOOT.section"

	newSec := listSection{headingPrefix: "####", title: "🆕 NEW", tag: "NEW", subDir: "IBOOT", label: "iBoot", groupDir: "NEW"}
	rmSec := listSection{headingPrefix: "####", title: "❌ Removed", tag: "Removed", subDir: "IBOOT", label: "iBoot", groupDir: "Removed"}
	if err := renderBinStringList(&out, newSec, map[string][]string{bin: {"added string"}}, dir); err != nil {
		t.Fatalf("renderBinStringList NEW: %v", err)
	}
	if err := renderBinStringList(&out, rmSec, map[string][]string{bin: {"removed string"}}, dir); err != nil {
		t.Fatalf("renderBinStringList Removed: %v", err)
	}

	newDoc, err := os.ReadFile(filepath.Join(dir, "IBOOT", "NEW", "iBoot.IBOOT.section.md"))
	if err != nil {
		t.Fatalf("read NEW side-car: %v", err)
	}
	rmDoc, err := os.ReadFile(filepath.Join(dir, "IBOOT", "Removed", "iBoot.IBOOT.section.md"))
	if err != nil {
		t.Fatalf("read Removed side-car: %v", err)
	}
	if !strings.Contains(string(newDoc), "added string") {
		t.Errorf("NEW side-car missing its string:\n%s", newDoc)
	}
	if !strings.Contains(string(rmDoc), "removed string") {
		t.Errorf("Removed side-car missing its string:\n%s", rmDoc)
	}
}

// TestRenderMachoDiffIntegration: NEW/Removed/Updated wired together, full
// Updated list inline (small counts → plain), per-file docs written.
func TestRenderMachoDiffIntegration(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	diff := &mcmd.MachoDiff{
		New:     []string{"/usr/lib/new.dylib"},
		Removed: []string{"/usr/lib/gone.dylib"},
		Updated: map[string]string{"/usr/lib/up.dylib": smallDiff},
	}

	base := listSection{headingPrefix: "####", subDir: "MACHOS", label: "SystemOS", groupDir: "SystemOS"}
	if err := renderMachoDiff(&out, base, diff, dir); err != nil {
		t.Fatalf("renderMachoDiff: %v", err)
	}

	got := out.String()
	for _, want := range []string{"#### 🆕 NEW (1)", "#### ❌ Removed (1)", "#### ⬆️ Updated (1)", "](MACHOS/"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in section output, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<details>") || strings.Contains(got, "```diff") {
		t.Errorf("single-entry sections must be plain links/bullets, no <details>/inline diff, got:\n%s", got)
	}
}
