package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
)

// testFixtureDiff builds a deterministic Diff value that populates every
// section the current renderers know how to emit, EXCEPT the kernel-version
// header (Kernel.Version is intentionally nil so the section is skipped --
// the table embeds a time.Time which the test does not want to pin).
//
// Section content embeds the section name in every value so any cross-section
// regression surfaces immediately in the golden diff. Sizes stay below every
// renderer "overflow" threshold (kexts updated < 10, plist updated < 15,
// plist new < 20, macho updated < 20, dylibs updated < 20, generic new/removed
// list < 30) so the goldens never exercise the per-file spill paths -- those
// paths still get covered by the side-effect file writes, but the README link
// shape is deterministic.
//
// outputDir is wired into d.conf.Output so Markdown() can write its
// side-effect files (Entitlements.md, Sandbox.md, etc.) without polluting
// the repo. Callers should pass a t.TempDir().
func testFixtureDiff(t *testing.T, outputDir string) *Diff {
	t.Helper()

	d := &Diff{
		Title: "26.5_22F76__vs__26.5.1_22F84",
		conf: &Config{
			Title:   "26.5_22F76__vs__26.5.1_22F84",
			IpswOld: "/tmp/iPhone18,1_26.5_22F76_Restore.ipsw",
			IpswNew: "/tmp/iPhone18,1_26.5.1_22F84_Restore.ipsw",
			Output:  outputDir,
		},
	}
	d.Old.IPSWPath = d.conf.IpswOld
	d.New.IPSWPath = d.conf.IpswNew
	d.Old.Version = "26.5"
	d.Old.Build = "22F76"
	d.New.Version = "26.5.1"
	d.New.Build = "22F84"
	d.Old.Webkit = "Webkit-26.5"
	d.New.Webkit = "Webkit-26.5.1"

	// Kexts: small map exercising NEW + Removed + Updated.
	d.Kexts = &mcmd.MachoDiff{
		New:     []string{"com.apple.KEXT.NewKext"},
		Removed: []string{"com.apple.KEXT.RemovedKext"},
		Updated: map[string]string{
			"/System/Library/Extensions/AppleKEXT.kext/AppleKEXT": "```diff\n- KEXT old line\n+ KEXT new line\n```",
		},
	}

	// KDKs string.
	d.KDKs = "```diff\n- KDK old struct\n+ KDK new struct\n```"
	d.Old.KDK = "KDK_14.0_23A344"
	d.New.KDK = "KDK_14.1_23B74"

	// Machos: multi-volume map (filesystem + SystemOS + AppOS).
	d.Machos = map[string]*mcmd.MachoDiff{
		"filesystem": {
			New:     []string{"/usr/bin/MACHO_filesystem_new"},
			Removed: []string{"/usr/bin/MACHO_filesystem_removed"},
			Updated: map[string]string{
				"/usr/bin/MACHO_filesystem_updated": "```diff\n- MACHO filesystem old\n+ MACHO filesystem new\n```",
			},
		},
		"SystemOS": {
			New:     []string{"/System/Library/MACHO_SystemOS_new"},
			Removed: []string{"/System/Library/MACHO_SystemOS_removed"},
			Updated: map[string]string{
				"/System/Library/MACHO_SystemOS_updated": "```diff\n- MACHO SystemOS old\n+ MACHO SystemOS new\n```",
			},
		},
		"AppOS": {
			New:     []string{"/System/Library/MACHO_AppOS_new"},
			Removed: []string{"/System/Library/MACHO_AppOS_removed"},
			Updated: map[string]string{
				"/System/Library/MACHO_AppOS_updated": "```diff\n- MACHO AppOS old\n+ MACHO AppOS new\n```",
			},
		},
	}

	// Localizations: multi-volume.
	d.Localizations = map[string]*PlistDiff{
		"filesystem": {
			New:     map[string]string{"/Localizations_filesystem_new.lproj/Localizable.strings": "LOC filesystem new content"},
			Removed: []string{"/Localizations_filesystem_removed.lproj/Localizable.strings"},
			Updated: map[string]string{
				"/Localizations_filesystem_updated.lproj/Localizable.strings": "```diff\n- LOC filesystem old\n+ LOC filesystem new\n```\n",
			},
		},
		"SystemOS": {
			New:     map[string]string{"/Localizations_SystemOS_new.lproj/Localizable.strings": "LOC SystemOS new content"},
			Removed: []string{"/Localizations_SystemOS_removed.lproj/Localizable.strings"},
			Updated: map[string]string{
				"/Localizations_SystemOS_updated.lproj/Localizable.strings": "```diff\n- LOC SystemOS old\n+ LOC SystemOS new\n```\n",
			},
		},
		"AppOS": {
			New:     map[string]string{"/Localizations_AppOS_new.lproj/Localizable.strings": "LOC AppOS new content"},
			Removed: []string{"/Localizations_AppOS_removed.lproj/Localizable.strings"},
			Updated: map[string]string{
				"/Localizations_AppOS_updated.lproj/Localizable.strings": "```diff\n- LOC AppOS old\n+ LOC AppOS new\n```\n",
			},
		},
	}

	// Features: multi-volume.
	d.Features = map[string]*PlistDiff{
		"filesystem": {
			New:     map[string]string{"/FeatureFlags_filesystem_new.plist": "<plist>FEATURES filesystem new</plist>"},
			Removed: []string{"/FeatureFlags_filesystem_removed.plist"},
			Updated: map[string]string{
				"/FeatureFlags_filesystem_updated.plist": "```diff\n- FEATURES filesystem old\n+ FEATURES filesystem new\n```\n",
			},
		},
		"SystemOS": {
			New:     map[string]string{"/FeatureFlags_SystemOS_new.plist": "<plist>FEATURES SystemOS new</plist>"},
			Removed: []string{"/FeatureFlags_SystemOS_removed.plist"},
			Updated: map[string]string{
				"/FeatureFlags_SystemOS_updated.plist": "```diff\n- FEATURES SystemOS old\n+ FEATURES SystemOS new\n```\n",
			},
		},
		"AppOS": {
			New:     map[string]string{"/FeatureFlags_AppOS_new.plist": "<plist>FEATURES AppOS new</plist>"},
			Removed: []string{"/FeatureFlags_AppOS_removed.plist"},
			Updated: map[string]string{
				"/FeatureFlags_AppOS_updated.plist": "```diff\n- FEATURES AppOS old\n+ FEATURES AppOS new\n```\n",
			},
		},
	}

	// Ents: multi-volume rendered diff strings.
	d.Ents = map[string]string{
		"filesystem": "```diff\n- ENTS filesystem old\n+ ENTS filesystem new\n```",
		"SystemOS":   "```diff\n- ENTS SystemOS old\n+ ENTS SystemOS new\n```",
		"AppOS":      "```diff\n- ENTS AppOS old\n+ ENTS AppOS new\n```",
	}

	// Sandbox: a rendered source/group/profile structure (the shape
	// renderSandboxProfileDiffMarkdown emits) so the per-profile side-car split
	// runs. Two sources exercise the source loop and slug rules; each group
	// stays at one profile, below every collapse/spill threshold.
	d.Sandbox = "### Sandbox Collection\n\n" +
		"#### New (1)\n\n" +
		"##### SANDBOX_collection_new\n\n" +
		"```scheme\n(version 1) ; SANDBOX collection new\n```\n\n" +
		"#### Removed (1)\n\n" +
		"##### SANDBOX_collection_removed\n\n" +
		"```scheme\n(version 1) ; SANDBOX collection removed\n```\n\n" +
		"#### Changed (1)\n\n" +
		"##### SANDBOX_collection_updated\n\n" +
		"```diff\n- SANDBOX collection old\n+ SANDBOX collection new\n```\n\n" +
		"### Platform Profile\n\n" +
		"#### Changed (1)\n\n" +
		"##### SANDBOX_platform_updated\n\n" +
		"```diff\n- SANDBOX platform old\n+ SANDBOX platform new\n```\n"

	// Firmwares: small set.
	d.Firmwares = &mcmd.MachoDiff{
		New:     []string{"FIRMWARE_new.im4p"},
		Removed: []string{"FIRMWARE_removed.im4p"},
		Updated: map[string]string{
			"FIRMWARE_updated.im4p": "```diff\n- FIRMWARE old\n+ FIRMWARE new\n```",
		},
	}

	// IBoot.
	d.IBoot = &IBootDiff{
		Versions: []string{"iBoot-IBOOT_old", "iBoot-IBOOT_new"},
		New: map[string][]string{
			"iBoot.IBOOT.section": {"IBOOT new string one of sufficient length"},
		},
		Removed: map[string][]string{
			"iBoot.IBOOT.section": {"IBOOT removed string one of sufficient length"},
		},
	}

	// Launchd string.
	d.Launchd = "```diff\n- LAUNCHD old\n+ LAUNCHD new\n```"

	// Files: filesystem + SystemOS + AppOS + IPSW + ExclaveOS.
	d.Files = &FileDiff{
		New: map[string][]string{
			"IPSW":       {"/FILES_IPSW_new"},
			"filesystem": {"/FILES_filesystem_new"},
			"SystemOS":   {"/FILES_SystemOS_new"},
			"AppOS":      {"/FILES_AppOS_new"},
		},
		Removed: map[string][]string{
			"IPSW":       {"/FILES_IPSW_removed"},
			"filesystem": {"/FILES_filesystem_removed"},
			"SystemOS":   {"/FILES_SystemOS_removed"},
			"AppOS":      {"/FILES_AppOS_removed"},
		},
	}

	// Dylibs.
	d.Dylibs = &mcmd.MachoDiff{
		New:     []string{"/usr/lib/DYLIBS_new.dylib"},
		Removed: []string{"/usr/lib/DYLIBS_removed.dylib"},
		Updated: map[string]string{
			"/usr/lib/DYLIBS_updated.dylib": "```diff\n- DYLIBS old\n+ DYLIBS new\n```",
		},
	}

	return d
}

// goldenUpdateEnabled reports whether GOLDEN_UPDATE=1 is set, in which case
// parity tests regenerate the golden files in place.
func goldenUpdateEnabled() bool {
	return os.Getenv("GOLDEN_UPDATE") == "1"
}

// parityGoldenDir is the directory holding the parity golden files.
func parityGoldenDir() string {
	return filepath.Join("testdata", "parity")
}

// compareOrWriteGolden writes got to goldenPath when GOLDEN_UPDATE=1, otherwise
// byte-compares got to the file contents on disk.
func compareOrWriteGolden(t *testing.T, goldenPath string, got []byte) {
	t.Helper()
	if goldenUpdateEnabled() {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", goldenPath, err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s (run with GOLDEN_UPDATE=1 to seed): %v", goldenPath, err)
	}
	if string(want) != string(got) {
		actual := goldenPath + ".actual"
		_ = os.WriteFile(actual, got, 0o644)
		t.Fatalf("output changed vs golden %s (wrote actual to %s)", goldenPath, actual)
	}
}

// TestMarkdownParity renders the fixture Diff with d.Markdown() and locks the
// resulting README.md byte-for-byte against the golden file.
func TestMarkdownParity(t *testing.T) {
	tmp := t.TempDir()
	d := testFixtureDiff(t, tmp)

	if err := d.Markdown(); err != nil {
		t.Fatalf("d.Markdown(): %v", err)
	}

	// d.Markdown() reassigns d.conf.Output to filepath.Join(Output, TitleToFilename())
	// before writing README.md.
	readme := filepath.Join(d.conf.Output, "README.md")
	got, err := os.ReadFile(readme)
	if err != nil {
		t.Fatalf("read rendered README.md: %v", err)
	}

	golden := filepath.Join(parityGoldenDir(), "README.md")
	compareOrWriteGolden(t, golden, got)
}

// TestHTMLParity renders the fixture Diff via the current renderHTML() path
// and locks the resulting HTML byte-for-byte against the golden file.
func TestHTMLParity(t *testing.T) {
	d := testFixtureDiff(t, t.TempDir())

	got, err := d.renderHTML()
	if err != nil {
		t.Fatalf("d.renderHTML(): %v", err)
	}

	golden := filepath.Join(parityGoldenDir(), "diff.html")
	compareOrWriteGolden(t, golden, []byte(got))
}

// TestJSONParity marshals the fixture Diff via [buildReport] -- the same
// stable DTO assembly the JSON output path uses -- and locks the result
// against the golden file at two layers:
//
//  1. raw byte-compare against testdata/parity/diff.json so silent shape
//     changes (field add/remove/rename, formatting) fail loudly; and
//  2. map round-trip equivalence (json.Unmarshal into map[string]any) so the
//     JSON keys/values are confirmed structurally equal regardless of any
//     future map-ordering subtleties.
func TestJSONParity(t *testing.T) {
	d := testFixtureDiff(t, t.TempDir())

	report, err := buildReport(d)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}

	golden := filepath.Join(parityGoldenDir(), "diff.json")
	compareOrWriteGolden(t, golden, got)

	// Structural round-trip check: even when bytes match, also confirm both
	// sides decode to the same map. If GOLDEN_UPDATE=1 we just wrote the
	// golden, so it will round-trip identically by construction.
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Fatalf("JSON structural mismatch between fixture output and golden round-trip")
	}

	// Phase-6 contract gate: the DTO's marshaled output must decode to the
	// same map as the legacy `json.Marshal(d, ...)` path. This locks the
	// `omitempty` equivalence guarantee for every key buildReport contributes
	// so a future renderer change cannot silently shift the top-level shape
	// (keys, nesting, empty-section skipping) away from what downstream
	// consumers parsed historically.
	legacy, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatalf("legacy json.MarshalIndent: %v", err)
	}
	var legacyMap map[string]any
	if err := json.Unmarshal(legacy, &legacyMap); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if !reflect.DeepEqual(gotMap, legacyMap) {
		t.Fatalf("buildReport DTO shape diverged from legacy struct marshaling")
	}
}
