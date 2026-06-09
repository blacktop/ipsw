package diff

import (
	"fmt"
	"hash/fnv"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
)

// Markdown saves the diff as Markdown files.
func (d *Diff) Markdown() error {
	d.conf.Output = filepath.Join(d.conf.Output, d.TitleToFilename())
	if err := os.MkdirAll(d.conf.Output, 0o750); err != nil {
		return err
	}

	var out strings.Builder
	/* TOC */

	// SECTION: Inputs
	out.WriteString(
		fmt.Sprintf(
			"# %s\n\n"+
				"## Inputs\n\n"+
				"- `%s`\n"+
				"- `%s`\n\n",
			d.Title,
			filepath.Base(d.Old.IPSWPath),
			filepath.Base(d.New.IPSWPath),
		),
	)

	// SECTION: Kernel
	if d.Old.Kernel.Version != nil && d.New.Kernel.Version != nil {
		out.WriteString(
			fmt.Sprintf(
				"## Kernel\n\n"+
					"### Version\n\n"+
					"| iOS | Version | Build | Date |\n"+
					"| :-- | :------ | :---- | :--- |\n"+
					"| %s *(%s)* | %s | %s | %s |\n"+
					"| %s *(%s)* | %s | %s | %s |\n\n",
				d.Old.Version, d.Old.Build,
				d.Old.Kernel.Version.KernelVersion.Darwin, d.Old.Kernel.Version.KernelVersion.XNU,
				d.Old.Kernel.Version.KernelVersion.Date.Format("Mon, 02Jan2006 15:04:05 MST"),
				d.New.Version, d.New.Build,
				d.New.Kernel.Version.KernelVersion.Darwin, d.New.Kernel.Version.KernelVersion.XNU,
				d.New.Kernel.Version.KernelVersion.Date.Format("Mon, 02Jan2006 15:04:05 MST"),
			),
		)
	}

	// SUB-SECTION: Kexts — owned by kextsTask (body in tasks_kexts.go).
	if kt := newKextsTask(d); !kt.Empty() {
		if err := kt.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SUB-SECTION: KDKs — owned by kdksTask (body in tasks_kdks.go).
	if kt := newKDKsTask(d); !kt.Empty() {
		if err := kt.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: MachO (per-volume sub-grouping; empty volumes are hidden).
	// Owned by machosJob — body lives in machosRenderer.Markdown.
	if mr := newMachosRenderer(d.Machos); !mr.Empty() {
		if err := mr.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SUB-SECTION: Entitlements (per-volume sub-grouping). The per-volume
	// rendered diff strings are written into a single Entitlements.md file
	// with per-volume sub-headings; the README links to that file.
	// Owned by entsJob — body lives in entsRenderer.Markdown.
	if er := newEntsRenderer(d.Ents); !er.Empty() {
		if err := er.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SUB-SECTION: Sandbox — owned by sandboxTask (body in tasks_sandbox.go).
	if st := newSandboxTask(d); !st.Empty() {
		if err := st.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: Firmware — owned by firmwaresTask (body in tasks_firmwares.go).
	if ft := newFirmwaresTask(d); !ft.Empty() {
		if err := ft.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: iBoot — owned by ibootTask (body in tasks_iboot.go).
	if err := newIBootTask(d).Markdown(&out, d.conf.Output); err != nil {
		return err
	}

	// SECTION: Launchd — owned by launchdJob (body in launchdRenderer.Markdown).
	if lr := newLaunchdRenderer(d.Launchd); !lr.Empty() {
		if err := lr.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: DSC
	if d.Dylibs != nil {
		if (len(d.Old.Webkit) > 0 && len(d.New.Webkit) > 0) ||
			(d.Dylibs.New != nil || d.Dylibs.Removed != nil || d.Dylibs.Updated != nil) {
			out.WriteString("## DSC\n\n")
		}
	}
	if len(d.Old.Webkit) > 0 && len(d.New.Webkit) > 0 {
		out.WriteString(
			fmt.Sprintf(
				"### WebKit\n\n"+
					"| iOS | Version |\n"+
					"| :-- | :------ |\n"+
					"| %s *(%s)* | %s |\n"+
					"| %s *(%s)* | %s |\n\n",
				d.Old.Version, d.Old.Build, d.Old.Webkit,
				d.New.Version, d.New.Build, d.New.Webkit,
			),
		)
	}

	// SUB-SECTION: Dylibs
	if d.Dylibs != nil && (len(d.Dylibs.New) > 0 || len(d.Dylibs.Removed) > 0 || len(d.Dylibs.Updated) > 0) {
		out.WriteString("### Dylibs\n\n")
		if err := renderMachoDiff(&out, listSection{headingPrefix: "####", subDir: "DYLIBS", label: "Dylibs"}, d.Dylibs, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: Files — owned by filesJob (body in filesRenderer.Markdown).
	if fr := newFilesRenderer(d.Files); !fr.Empty() {
		if err := fr.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: Localizations (per-volume sub-grouping) — owned by locsJob
	// (body in locsRenderer.Markdown).
	if lr := newLocsRenderer(d.Localizations); !lr.Empty() {
		if err := lr.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	// SECTION: Feature Flags (per-volume sub-grouping) — owned by featuresJob
	// (body in featuresRenderer.Markdown).
	if fr := newFeaturesRenderer(d.Features); !fr.Empty() {
		if err := fr.Markdown(&out, d.conf.Output); err != nil {
			return err
		}
	}

	out.WriteString("## EOF\n")

	// Write README.md
	if err := os.MkdirAll(d.conf.Output, 0o750); err != nil {
		return err
	}
	fname := filepath.Join(d.conf.Output, "README.md")
	log.Infof("Creating diff file Markdown README: %s", fname)
	return os.WriteFile(fname, []byte(out.String()), 0o644)
}

// sortedVolumeKeys returns the keys of m in volumeOutputOrder; unknown
// volumes sort alphabetically after. Used by every per-volume diff section.
func sortedVolumeKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return sortVolumeNames(keys)
}

func hasEntitlementsContent(m map[string]string) bool {
	for _, rendered := range m {
		if entitlementsDiffHasContent(rendered) {
			return true
		}
	}
	return false
}

func hasPlistVolumeContent(m map[string]*PlistDiff) bool {
	for _, d := range m {
		if plistDiffHasContent(d) {
			return true
		}
	}
	return false
}

// plistVolumeRenderer is the per-volume config that distinguishes
// renderPlistVolume's two callers (Localizations vs FeatureFlags).
type plistVolumeRenderer struct {
	subDir      string              // "LOCALIZATIONS" or "FEATURES"
	fenceLang   string              // "text" or "xml" (for the New sub-section)
	displayName func(string) string // path → header label
}

// renderPlistVolume emits the New/Removed/Updated sub-sections for a single
// plist-style volume (localizations or feature flags). headingPrefix is the
// markdown heading level (e.g. "####" when the per-volume heading is "###").
// Overflow entries spill into per-file markdown under r.subDir, with FNV-hashed
// filenames so basename collisions stay deterministic.
func renderPlistVolume(out *strings.Builder, diff *PlistDiff, outputDir, headingPrefix, volLabel string, r plistVolumeRenderer) error {
	entryPrefix := headingPrefix + "#"
	if len(diff.New) > 0 {
		fmt.Fprintf(out, "%s 🆕 NEW (%d)\n\n", headingPrefix, len(diff.New))
		out.WriteString("<details>\n  <summary><i>View New</i></summary>\n\n")
		keys := slices.Collect(maps.Keys(diff.New))
		slices.Sort(keys)
		if len(diff.New) < plistNewInlineMax {
			for _, k := range keys {
				fmt.Fprintf(out, "%s %s\n\n", entryPrefix, r.displayName(k))
				fmt.Fprintf(out, ">  `%s`\n\n", k)
				fmt.Fprintf(out, "```%s\n%s\n```\n", r.fenceLang, diff.New[k])
			}
		} else {
			rel := sideCarRelNames(keys, volLabel)
			for _, k := range keys {
				body := plistDocBody(r.displayName(k), k, fmt.Sprintf("```%s\n%s\n```\n", r.fenceLang, diff.New[k]))
				if _, err := writeSideCar(outputDir, r.subDir, rel[k], body); err != nil {
					return err
				}
				fmt.Fprintf(out, "- [%s](%s)\n", k, filepath.Join(r.subDir, rel[k]))
			}
		}
		out.WriteString("\n</details>\n\n")
	}
	if err := renderNameList(out, listSection{headingPrefix: headingPrefix, title: "❌ Removed", tag: "Removed", subDir: r.subDir, label: volLabel}, diff.Removed, outputDir); err != nil {
		return err
	}
	if err := renderUpdatedEntries(out, listSection{headingPrefix: headingPrefix, title: "⬆️ Updated", tag: "Updated", subDir: r.subDir, label: volLabel, groupDir: volLabel}, diff.Updated, outputDir, r.displayName); err != nil {
		return err
	}
	return nil
}

var (
	localizationsRenderer = plistVolumeRenderer{subDir: "LOCALIZATIONS", fenceLang: "text", displayName: localizationDisplayName}
	featureFlagsRenderer  = plistVolumeRenderer{subDir: "FEATURES", fenceLang: "xml", displayName: filepath.Base}
)

// volumeOutputOrder is the deterministic order per-volume diff sections
// render in. Unknown volume names sort alphabetically after these.
var volumeOutputOrder = []string{"IPSW", "filesystem", "SystemOS", "AppOS", "ExclaveOS"}

func sortVolumeNames(names []string) []string {
	order := make(map[string]int, len(volumeOutputOrder))
	for i, name := range volumeOutputOrder {
		order[name] = i
	}
	slices.SortFunc(names, func(a, b string) int {
		ia, oka := order[a]
		ib, okb := order[b]
		switch {
		case oka && okb:
			return ia - ib
		case oka:
			return -1
		case okb:
			return 1
		default:
			return strings.Compare(a, b)
		}
	})
	return names
}

func hasMachoDiffVolumeContent(m map[string]*mcmd.MachoDiff) bool {
	for _, d := range m {
		if machoDiffHasContent(d) {
			return true
		}
	}
	return false
}

// listCollapseThreshold is the entry count below which a NEW/Removed/Updated
// list renders as a plain, always-visible bullet list. At or above it (but below
// the section's spill threshold) the list renders inside a collapsed-by-default
// <details> block.
const listCollapseThreshold = 30

// listSpillThreshold is the default entry count at or above which a list stops
// rendering in the README and instead spills to a side-car markdown doc that the
// README links to with a single line. It is high so ordinary sections keep their
// full list in the README; only very large lists spill. A section can override
// it via listSection.spillAt.
const listSpillThreshold = 1000

// filesSpillThreshold is the spill threshold for the `## Files` name lists.
// Those are noisy file-path dumps that read better as their own linked doc, so
// they spill much sooner than the default.
const filesSpillThreshold = 30

// plistNewInlineMax is the separate, lower spill threshold for a
// localizations/feature-flags "New" section. Unlike the other sections it
// inlines each new file's full content (not just a name or a link), so it
// spills sooner than listSpillThreshold to keep that bulkier content out of the
// README.
const plistNewInlineMax = 20

// nameListReplacer sanitizes a section label into a filename fragment. It is
// package-level because strings.Replacer is immutable and goroutine-safe, so
// there is no reason to rebuild it per call.
var nameListReplacer = strings.NewReplacer(" ", "_", "/", "_")

// listSection describes a NEW/Removed/Updated list sub-section.
type listSection struct {
	headingPrefix string // markdown heading level, e.g. "###" or "####"
	title         string // heading title, e.g. "🆕 NEW" / "⬆️ Updated" / a volume name
	tag           string // filename + summary tag, e.g. "NEW" / "Removed" / "Updated"
	subDir        string // side-car directory, e.g. "MACHOS" / "FILES"
	label         string // per-section disambiguator, e.g. "SystemOS" / "Dylibs"
	groupDir      string // per-entry side-car subfolder under subDir (volume / NEW|Removed); "" = none
	spillAt       int    // count at/above which the list spills to a side-car doc; 0 → listSpillThreshold
}

// sideCarPathReplacer sanitizes a mirrored path so it is a valid markdown link
// target. Folder separators ("/") are preserved; only characters that break a
// `[text](target)` link are replaced.
var sideCarPathReplacer = strings.NewReplacer(" ", "_", "(", "_", ")", "_", "#", "_", "?", "_")

// sideCarRelNames maps each key to its side-car path relative to the section
// subDir, mirroring the key's real path under groupDir (e.g.
// MACHOS/SystemOS/System/Library/Foo.md) so two distinct files can never
// collide. A short hash suffix is appended only in the rare case two keys
// sanitize to the same path.
func sideCarRelNames(keys []string, groupDir string) map[string]string {
	mirror := make(map[string]string, len(keys))
	count := make(map[string]int, len(keys))
	for _, k := range keys {
		p := sideCarPathReplacer.Replace(strings.TrimPrefix(filepath.ToSlash(k), "/"))
		// Drop a leading segment equal to groupDir so a key already prefixed with
		// its volume doesn't become groupDir/groupDir/... .
		if groupDir != "" {
			p = strings.TrimPrefix(p, groupDir+"/")
		}
		if p == "" {
			p = "entry"
		}
		mirror[k] = p
		count[p]++
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		p := mirror[k]
		if count[p] > 1 {
			h := fnv.New32a()
			_, _ = h.Write([]byte(filepath.ToSlash(k)))
			p = fmt.Sprintf("%s.%08x", p, h.Sum32())
		}
		out[k] = filepath.Join(groupDir, p+".md")
	}
	return out
}

// plistDocBody builds a side-car document body: an H2 display heading, the
// source path as a quote, then the content.
func plistDocBody(display, path, content string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", display)
	fmt.Fprintf(&b, "> `%s`\n\n", path)
	b.WriteString(content)
	return b.String()
}

// renderNameList renders a NEW/Removed name list under its own heading as
// backtick bullets, applying the shared plain/collapsed/spill rule (see
// emitListBody).
func renderNameList(out *strings.Builder, sec listSection, names []string, outputDir string) error {
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	fmt.Fprintf(out, "%s %s (%d)\n\n", sec.headingPrefix, sec.title, len(names))
	return emitListBody(out, sec, len(names), outputDir, func(w *strings.Builder, _ string) {
		for _, n := range names {
			fmt.Fprintf(w, "- `%s`\n", n)
		}
	})
}

// linkEntry is one README list item: the link text plus the side-car basename
// it points at (relative to the section's subDir).
type linkEntry struct {
	text    string
	relName string
}

// renderLinkList emits the section heading plus a list of side-car links,
// applying the shared plain/collapsed/spill rule via emitListBody. It is the
// shared core of the "list of links to per-entry side-car docs" sections
// (Updated diffs and iBoot bins).
func renderLinkList(out *strings.Builder, sec listSection, entries []linkEntry, outputDir string) error {
	fmt.Fprintf(out, "%s %s (%d)\n\n", sec.headingPrefix, sec.title, len(entries))
	return emitListBody(out, sec, len(entries), outputDir, func(w *strings.Builder, linkBase string) {
		for _, e := range entries {
			fmt.Fprintf(w, "- [%s](%s)\n", e.text, filepath.Join(linkBase, e.relName))
		}
	})
}

// renderSideCarEntries writes one side-car doc per entry (path-mirrored under
// sec.subDir/sec.groupDir, body from the body callback) and renders the README
// list of links under the shared plain/collapsed/spill rule. It is the shared
// core of every "one side-car doc per entry" section.
func renderSideCarEntries[V any](out *strings.Builder, sec listSection, m map[string]V, outputDir string, body func(key string, val V) string) error {
	if len(m) == 0 {
		return nil
	}
	keys := slices.Collect(maps.Keys(m))
	slices.Sort(keys)
	rel := sideCarRelNames(keys, sec.groupDir)
	entries := make([]linkEntry, 0, len(keys))
	for _, k := range keys {
		if _, err := writeSideCar(outputDir, sec.subDir, rel[k], body(k, m[k])); err != nil {
			return err
		}
		entries = append(entries, linkEntry{k, rel[k]})
	}
	return renderLinkList(out, sec, entries, outputDir)
}

// renderUpdatedEntries renders an "Updated" list: every entry's diff is written
// to its own path-mirrored side-car (never inlined) and the README shows the
// list of links under the shared plain/collapsed/spill rule.
func renderUpdatedEntries(out *strings.Builder, sec listSection, updated map[string]string, outputDir string, displayName func(string) string) error {
	return renderSideCarEntries(out, sec, updated, outputDir, func(k, diff string) string {
		return plistDocBody(displayName(k), k, diff)
	})
}

// renderBinStringList renders an iBoot-style section: each entry is a named bin
// whose side-car holds its strings as a bullet list.
func renderBinStringList(out *strings.Builder, sec listSection, bins map[string][]string, outputDir string) error {
	return renderSideCarEntries(out, sec, bins, outputDir, func(bin string, strs []string) string {
		var body strings.Builder
		fmt.Fprintf(&body, "## %s\n\n", bin)
		for _, s := range strs {
			fmt.Fprintf(&body, "- `%s`\n", s)
		}
		return body.String()
	})
}

// emitListBody writes a list body in one of three forms by entry count:
//   - count >= spill threshold → the whole list spills to a side-car doc and the
//     README shows a single "View N" link;
//   - count < listCollapseThreshold → a plain, always-visible bullet list;
//   - otherwise → the full list inside a collapsed-by-default <details>.
//
// The spill threshold is sec.spillAt, or listSpillThreshold when sec.spillAt is
// zero. renderItems writes the bullet/link lines to the given builder, joining
// any per-item link target with linkBase: sec.subDir for the README (the targets
// live under it) and "" inside the side-car doc (which lives in sec.subDir
// alongside the targets).
func emitListBody(out *strings.Builder, sec listSection, count int, outputDir string, renderItems func(w *strings.Builder, linkBase string)) error {
	spillAt := sec.spillAt
	if spillAt == 0 {
		spillAt = listSpillThreshold
	}
	if count >= spillAt {
		var b strings.Builder
		fmt.Fprintf(&b, "## %s — %s (%d)\n\n", sec.label, sec.tag, count)
		renderItems(&b, "")
		relName, err := writeListDoc(outputDir, sec, b.String())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "- [View %d %s files](%s)\n\n", count, strings.ToLower(sec.tag), filepath.Join(sec.subDir, relName))
		return nil
	}
	if count < listCollapseThreshold {
		renderItems(out, sec.subDir)
		out.WriteString("\n")
		return nil
	}
	fmt.Fprintf(out, "<details>\n  <summary><i>View %s</i></summary>\n\n", sec.tag)
	renderItems(out, sec.subDir)
	out.WriteString("\n</details>\n\n")
	return nil
}

// writeListDoc writes body to outputDir/sec.subDir/<label>.<tag>.md and returns
// the basename so the caller can link to it from the README.
func writeListDoc(output string, sec listSection, body string) (string, error) {
	relName := fmt.Sprintf("%s.%s.md", nameListReplacer.Replace(sec.label), sec.tag)
	return writeSideCar(output, sec.subDir, relName, body)
}

// renderMachoDiff renders the NEW/Removed/Updated triple for a MachoDiff-shaped
// section. base carries the per-section fields (headingPrefix, subDir, label,
// groupDir, spillAt); the title and tag for each of the three sub-sections are
// filled in here. NEW/Removed are name lists; Updated diffs each get their own
// path-mirrored side-car (named by basename).
func renderMachoDiff(out *strings.Builder, base listSection, diff *mcmd.MachoDiff, outputDir string) error {
	newSec := base
	newSec.title, newSec.tag = "🆕 NEW", "NEW"
	if err := renderNameList(out, newSec, diff.New, outputDir); err != nil {
		return err
	}
	rmSec := base
	rmSec.title, rmSec.tag = "❌ Removed", "Removed"
	if err := renderNameList(out, rmSec, diff.Removed, outputDir); err != nil {
		return err
	}
	upSec := base
	upSec.title, upSec.tag = "⬆️ Updated", "Updated"
	return renderUpdatedEntries(out, upSec, diff.Updated, outputDir, filepath.Base)
}

// writeSideCar writes body verbatim to outputDir/subDir/relName, creating the
// (possibly nested) parent directory, and returns relName. It is the shared
// write tail for every per-section side-car doc.
func writeSideCar(output, subDir, relName, body string) (string, error) {
	fname := filepath.Join(output, subDir, relName)
	if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
		return "", fmt.Errorf("failed to create side-car dir: %w", err)
	}
	log.Debugf("Creating diff %s Markdown file: %s", strings.ToLower(subDir), fname)
	if err := os.WriteFile(fname, []byte(body), 0o644); err != nil {
		return "", fmt.Errorf("failed to create diff file: %w", err)
	}
	return relName, nil
}
