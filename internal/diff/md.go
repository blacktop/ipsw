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
		if err := renderNameList(&out, nameListSection{headingPrefix: "####", title: "🆕 NEW", tag: "NEW", subDir: "DYLIBS", label: "Dylibs"}, d.Dylibs.New, d.conf.Output); err != nil {
			return err
		}
		if err := renderNameList(&out, nameListSection{headingPrefix: "####", title: "❌ Removed", tag: "Removed", subDir: "DYLIBS", label: "Dylibs"}, d.Dylibs.Removed, d.conf.Output); err != nil {
			return err
		}
		if len(d.Dylibs.Updated) > 0 {
			fmt.Fprintf(&out, "#### ⬆️ Updated (%d)\n\n", len(d.Dylibs.Updated))
			out.WriteString("<details>\n  <summary><i>View Updated</i></summary>\n\n")
			if err := renderUpdatedEntries(&out, d.Dylibs.Updated, d.conf.Output, "DYLIBS", "####"); err != nil {
				return err
			}
			out.WriteString("\n</details>\n\n")
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
func renderPlistVolume(out *strings.Builder, diff *PlistDiff, outputDir, headingPrefix string, r plistVolumeRenderer) error {
	entryPrefix := headingPrefix + "#"
	if len(diff.New) > 0 {
		fmt.Fprintf(out, "%s 🆕 NEW (%d)\n\n", headingPrefix, len(diff.New))
		out.WriteString("<details>\n  <summary><i>View New</i></summary>\n\n")
		keys := slices.Collect(maps.Keys(diff.New))
		slices.Sort(keys)
		if len(diff.New) < 20 {
			for _, k := range keys {
				fmt.Fprintf(out, "%s %s\n\n", entryPrefix, r.displayName(k))
				fmt.Fprintf(out, ">  `%s`\n\n", k)
				fmt.Fprintf(out, "```%s\n%s\n```\n", r.fenceLang, diff.New[k])
			}
		} else {
			if err := ensureSubDir(outputDir, r.subDir); err != nil {
				return err
			}
			for _, k := range keys {
				body := fmt.Sprintf("```%s\n%s\n```\n", r.fenceLang, diff.New[k])
				relName, err := writePlistMarkdownFile(outputDir, r.subDir, k, r.displayName, body)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "- [%s](%s)\n", k, filepath.Join(r.subDir, relName))
			}
		}
		out.WriteString("\n</details>\n\n")
	}
	if len(diff.Removed) > 0 {
		fmt.Fprintf(out, "%s ❌ Removed (%d)\n\n", headingPrefix, len(diff.Removed))
		if len(diff.Removed) > 30 {
			out.WriteString("<details>\n  <summary><i>View Removed</i></summary>\n\n")
		}
		for _, k := range diff.Removed {
			fmt.Fprintf(out, "- `%s`\n", k)
		}
		if len(diff.Removed) > 30 {
			out.WriteString("\n</details>\n")
		}
		out.WriteString("\n")
	}
	if len(diff.Updated) > 0 {
		fmt.Fprintf(out, "%s ⬆️ Updated (%d)\n\n", headingPrefix, len(diff.Updated))
		out.WriteString("<details>\n  <summary><i>View Updated</i></summary>\n\n")
		keys := slices.Collect(maps.Keys(diff.Updated))
		slices.Sort(keys)
		if len(diff.Updated) < 15 {
			for _, k := range keys {
				fmt.Fprintf(out, "%s %s\n\n", entryPrefix, r.displayName(k))
				fmt.Fprintf(out, ">  `%s`\n\n", k)
				fmt.Fprintf(out, "%s\n", diff.Updated[k])
			}
		} else {
			if err := ensureSubDir(outputDir, r.subDir); err != nil {
				return err
			}
			for _, k := range keys {
				relName, err := writePlistMarkdownFile(outputDir, r.subDir, k, r.displayName, diff.Updated[k])
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "- [%s](%s)\n", k, filepath.Join(r.subDir, relName))
			}
		}
		out.WriteString("\n</details>\n\n")
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

const (
	// updatedInlineMaxFiles is the maximum number of "Updated" entries rendered
	// inline in the README. Above it, every entry spills to a side-car markdown
	// file linked from the README so the README stays small enough to render.
	updatedInlineMaxFiles = 30
	// updatedInlineMaxLines is the maximum number of lines a single "Updated"
	// diff may contain before it spills to its own side-car file, even when the
	// entry count is at or below updatedInlineMaxFiles. A handful of very large
	// per-binary diffs (e.g. SystemOS) is enough to make the README
	// unrenderable, so they are linked rather than inlined.
	updatedInlineMaxLines = 100
)

// nameListReplacer sanitizes a section label into a filename fragment. It is
// package-level because strings.Replacer is immutable and goroutine-safe, so
// there is no reason to rebuild it per call.
var nameListReplacer = strings.NewReplacer(" ", "_", "/", "_")

// ensureSubDir creates outputDir/subDir if it does not already exist. Callers
// invoke it once before a spill loop so the per-entry writers do not each issue
// a redundant mkdir syscall.
func ensureSubDir(output, subDir string) error {
	if err := os.MkdirAll(filepath.Join(output, subDir), 0o750); err != nil {
		return fmt.Errorf("failed to create %s dir: %w", subDir, err)
	}
	return nil
}

// renderUpdatedEntries emits the body of an "Updated" sub-section. Each entry
// is rendered inline as an `entryPrefix base` heading followed by its diff,
// unless the entry count exceeds updatedInlineMaxFiles or the individual diff
// exceeds updatedInlineMaxLines, in which case that entry spills to a side-car
// markdown file under outputDir/subDir and is linked from the README. The
// caller owns the surrounding heading and <details> wrapper.
func renderUpdatedEntries(out *strings.Builder, updated map[string]string, outputDir, subDir, entryPrefix string) error {
	keys := slices.Collect(maps.Keys(updated))
	slices.Sort(keys)
	forceSidecar := len(updated) > updatedInlineMaxFiles
	dirReady := false
	for _, k := range keys {
		body := updated[k]
		if forceSidecar || strings.Count(body, "\n") > updatedInlineMaxLines {
			if !dirReady {
				if err := ensureSubDir(outputDir, subDir); err != nil {
					return err
				}
				dirReady = true
			}
			relName, err := writePlistMarkdownFile(outputDir, subDir, k, filepath.Base, body)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "- [%s](%s)\n", k, filepath.Join(subDir, relName))
			continue
		}
		fmt.Fprintf(out, "%s %s\n\n", entryPrefix, filepath.Base(k))
		fmt.Fprintf(out, ">  `%s`\n\n", k)
		fmt.Fprintf(out, "%s\n", body)
	}
	return nil
}

// nameListSection describes a NEW/Removed name-list sub-section: the heading
// level and title, the tag used in the side-car filename and link text, and
// the side-car subDir plus a per-volume label that disambiguates the file.
type nameListSection struct {
	headingPrefix string // markdown heading level, e.g. "####"
	title         string // heading title incl. emoji, e.g. "🆕 NEW"
	tag           string // filename + link-text tag, e.g. "NEW" / "Removed"
	subDir        string // side-car directory, e.g. "MACHOS" / "DYLIBS"
	label         string // per-volume/section disambiguator, e.g. "SystemOS"
}

// renderNameList emits a sorted bullet list of file paths under a
// `headingPrefix title (N)` heading. When the list exceeds
// updatedInlineMaxFiles, the whole list spills to a side-car markdown file
// (outputDir/subDir/<label>.<tag>.md) and the README shows a single link plus
// the count, so a volume with hundreds of new/removed files does not bloat the
// README.
func renderNameList(out *strings.Builder, sec nameListSection, names []string, outputDir string) error {
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	fmt.Fprintf(out, "%s %s (%d)\n\n", sec.headingPrefix, sec.title, len(names))
	if len(names) > updatedInlineMaxFiles {
		relName, err := writeNameListFile(outputDir, sec, names)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "- [View %d %s files](%s)\n\n", len(names), strings.ToLower(sec.tag), filepath.Join(sec.subDir, relName))
		return nil
	}
	for _, k := range names {
		fmt.Fprintf(out, "- `%s`\n", k)
	}
	out.WriteString("\n")
	return nil
}

// writeNameListFile writes the full name list to outputDir/subDir/<label>.<tag>.md
// and returns the basename so renderNameList can link to it from the README.
func writeNameListFile(output string, sec nameListSection, names []string) (string, error) {
	if err := ensureSubDir(output, sec.subDir); err != nil {
		return "", err
	}
	relName := fmt.Sprintf("%s.%s.md", nameListReplacer.Replace(sec.label), sec.tag)
	fname := filepath.Join(output, sec.subDir, relName)
	log.Debugf("Creating diff %s Markdown file: %s", strings.ToLower(sec.subDir), fname)

	var b strings.Builder
	fmt.Fprintf(&b, "## %s — %s (%d)\n\n", sec.label, sec.tag, len(names))
	for _, n := range names {
		fmt.Fprintf(&b, "- `%s`\n", n)
	}
	if err := os.WriteFile(fname, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("failed to create diff file: %w", err)
	}
	return relName, nil
}

func renderMachoDiffSection(out *strings.Builder, diff *mcmd.MachoDiff, outputDir, headingPrefix, label string) error {
	if err := renderNameList(out, nameListSection{headingPrefix: headingPrefix, title: "🆕 NEW", tag: "NEW", subDir: "MACHOS", label: label}, diff.New, outputDir); err != nil {
		return err
	}
	if err := renderNameList(out, nameListSection{headingPrefix: headingPrefix, title: "❌ Removed", tag: "Removed", subDir: "MACHOS", label: label}, diff.Removed, outputDir); err != nil {
		return err
	}
	if len(diff.Updated) > 0 {
		fmt.Fprintf(out, "%s ⬆️ Updated (%d)\n\n", headingPrefix, len(diff.Updated))
		out.WriteString("<details>\n  <summary><i>View Updated</i></summary>\n\n")
		if err := renderUpdatedEntries(out, diff.Updated, outputDir, "MACHOS", headingPrefix+"#"); err != nil {
			return err
		}
		out.WriteString("\n</details>\n\n")
	}
	return nil
}

// plistMarkdownFilename derives the per-entry markdown filename from a path
// and a displayName resolver. FNV-hashing the path keeps filenames
// deterministic even when multiple keys share a basename.
func plistMarkdownFilename(path string, displayName func(string) string) string {
	base := strings.ReplaceAll(displayName(path), " ", "_")
	if base == "" || base == "." {
		base = "entry"
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(filepath.ToSlash(path)))
	return fmt.Sprintf("%08x_%s.md", hash.Sum32(), base)
}

// writePlistMarkdownFile writes a single per-key markdown file under
// outputDir/subDir/ and returns the basename so the caller can link to it
// from the README.
func writePlistMarkdownFile(output, subDir, path string, displayName func(string) string, content string) (string, error) {
	relName := plistMarkdownFilename(path, displayName)
	fname := filepath.Join(output, subDir, relName)
	log.Debugf("Creating diff %s Markdown file: %s", strings.ToLower(subDir), fname)

	var out strings.Builder
	fmt.Fprintf(&out, "## %s\n\n", displayName(path))
	fmt.Fprintf(&out, "> `%s`\n\n", path)
	out.WriteString(content)

	if err := os.WriteFile(fname, []byte(out.String()), 0o644); err != nil {
		return "", fmt.Errorf("failed to create diff file: %w", err)
	}
	return relName, nil
}
