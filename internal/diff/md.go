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
	"golang.org/x/exp/rand"
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
		if len(d.Dylibs.New) > 0 {
			out.WriteString(fmt.Sprintf("#### 🆕 NEW (%d)\n\n", len(d.Dylibs.New)))
			slices.Sort(d.Dylibs.New)
			if len(d.Dylibs.New) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View NEW</i></summary>\n\n")
			}
			for _, k := range d.Dylibs.New {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Dylibs.New) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Dylibs.Removed) > 0 {
			out.WriteString(fmt.Sprintf("#### ❌ Removed (%d)\n\n", len(d.Dylibs.Removed)))
			slices.Sort(d.Dylibs.Removed)
			if len(d.Dylibs.Removed) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View Removed</i></summary>\n\n")
			}
			for _, k := range d.Dylibs.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Dylibs.Removed) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Dylibs.Updated) > 0 {
			out.WriteString(fmt.Sprintf("#### ⬆️ Updated (%d)\n\n", len(d.Dylibs.Updated)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Updated</i></summary>\n\n")

			keys := slices.Collect(maps.Keys(d.Dylibs.Updated))
			slices.Sort(keys)

			if len(d.Dylibs.Updated) < 20 {
				for _, k := range keys {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", d.Dylibs.Updated[k]))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "DYLIBS"), 0o750); err != nil {
					return err
				}
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "DYLIBS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "DYLIBS", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
					}
					log.Debugf("Creating diff dylib Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, "%s", d.Dylibs.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("DYLIBS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
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
			if err := os.MkdirAll(filepath.Join(outputDir, r.subDir), 0o750); err != nil {
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
			if err := os.MkdirAll(filepath.Join(outputDir, r.subDir), 0o750); err != nil {
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

func renderMachoDiffSection(out *strings.Builder, diff *mcmd.MachoDiff, outputDir, headingPrefix string) error {
	if len(diff.New) > 0 {
		fmt.Fprintf(out, "%s 🆕 NEW (%d)\n\n", headingPrefix, len(diff.New))
		slices.Sort(diff.New)
		if len(diff.New) > 30 {
			out.WriteString("<details>\n  <summary><i>View NEW</i></summary>\n\n")
		}
		for _, k := range diff.New {
			fmt.Fprintf(out, "- `%s`\n", k)
		}
		if len(diff.New) > 30 {
			out.WriteString("\n</details>\n")
		}
		out.WriteString("\n")
	}
	if len(diff.Removed) > 0 {
		fmt.Fprintf(out, "%s ❌ Removed (%d)\n\n", headingPrefix, len(diff.Removed))
		slices.Sort(diff.Removed)
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

		entryPrefix := headingPrefix + "#"
		if len(diff.Updated) < 20 {
			for _, k := range keys {
				fmt.Fprintf(out, "%s %s\n\n", entryPrefix, filepath.Base(k))
				fmt.Fprintf(out, ">  `%s`\n\n", k)
				fmt.Fprintf(out, "%s\n", diff.Updated[k])
			}
		} else {
			if err := os.MkdirAll(filepath.Join(outputDir, "MACHOS"), 0o750); err != nil {
				return err
			}
			for _, k := range keys {
				fname := filepath.Join(outputDir, "MACHOS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
				if _, err := os.Stat(fname); os.IsExist(err) {
					fname = filepath.Join(outputDir, "MACHOS", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
				}
				log.Debugf("Creating diff macho Markdown file: %s", fname)
				f, err := os.Create(fname)
				if err != nil {
					return fmt.Errorf("failed to create diff file: %w", err)
				}
				fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
				fmt.Fprintf(f, "> `%s`\n\n", k)
				fmt.Fprintf(f, "%s", diff.Updated[k])
				f.Close()
				fmt.Fprintf(out, "- [%s](%s)\n", k, filepath.Join("MACHOS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md"))
			}
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
