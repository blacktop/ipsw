package diff

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-plist"
)

func TestDiffLocalizedResourcesReportsUpdatedLoctableKeys(t *testing.T) {
	path := "FileSystem/System/Library/PrivateFrameworks/CommunicationsFilter.framework/CommunicationsFilter.loctable"
	oldResources := map[string]string{
		path: `en.%d_ADDITIONAL_CONTACTS_BLOCKED_ALERT_TITLE.value.one = "%d other contact was unblocked."`,
	}
	newResources := map[string]string{
		path: strings.Join([]string{
			`en.%d_ADDITIONAL_CONTACTS_BLOCKED_ALERT_TITLE.value.one = "%d other contact was unblocked."`,
			`en.BLOCKLIST_LIMIT_ALERT_TITLE = "Blocked Contacts Limit Reached"`,
		}, "\n"),
	}
	out := &PlistDiff{
		New:     make(map[string]string),
		Updated: make(map[string]string),
	}

	if err := diffLocalizedResources(out, oldResources, newResources); err != nil {
		t.Fatalf("diffLocalizedResources returned error: %v", err)
	}

	got := out.Updated[path]
	if !strings.Contains(got, `+en.BLOCKLIST_LIMIT_ALERT_TITLE = "Blocked Contacts Limit Reached"`) {
		t.Fatalf("updated localization diff missing blocklist alert title:\n%s", got)
	}
}

func TestSideCarRelNamesMirrorsPathUnderVolumeFolder(t *testing.T) {
	keys := []string{
		"FileSystem/Applications/Phone.app/en.lproj/Localizable.strings",
		"FileSystem/System/Library/Frameworks/Test.framework/en.lproj/Localizable.strings",
	}
	rel := sideCarRelNames(keys, "SystemOS")

	// The real path is mirrored under the volume folder — no hash, can't collide.
	if got, want := rel[keys[0]], filepath.Join("SystemOS", keys[0]+".md"); got != want {
		t.Errorf("rel[%q] = %q, want %q", keys[0], got, want)
	}
	if got, want := rel[keys[1]], filepath.Join("SystemOS", keys[1]+".md"); got != want {
		t.Errorf("rel[%q] = %q, want %q", keys[1], got, want)
	}
}

func TestSideCarRelNamesHashesOnlyOnSanitizeCollision(t *testing.T) {
	// Distinct real paths never collide, even with the same bundle/basename.
	keys := []string{
		"FileSystem/A/ActionKit.framework/Localizable.loctable",
		"FileSystem/B/ActionKit.framework/Localizable.loctable",
	}
	rel := sideCarRelNames(keys, "")
	if rel[keys[0]] == rel[keys[1]] {
		t.Fatalf("distinct paths must not collide: %q", rel[keys[0]])
	}
	for _, k := range keys {
		if want := k + ".md"; rel[k] != want {
			t.Errorf("distinct path should stay clean (no hash): rel[%q] = %q, want %q", k, rel[k], want)
		}
	}

	// Two keys that only differ by a sanitized character DO collide → hash fallback.
	clash := []string{"dir a/Localizable.loctable", "dir_a/Localizable.loctable"}
	rc := sideCarRelNames(clash, "")
	if rc[clash[0]] == rc[clash[1]] {
		t.Fatalf("sanitization-colliding keys must get distinct names: %q", rc[clash[0]])
	}

	// A key already prefixed with its volume doesn't become volume/volume/... .
	vp := sideCarRelNames([]string{"SystemOS/usr/lib/foo.dylib"}, "SystemOS")
	if got, want := vp["SystemOS/usr/lib/foo.dylib"], filepath.Join("SystemOS", "usr/lib/foo.dylib.md"); got != want {
		t.Errorf("redundant volume prefix not stripped: got %q, want %q", got, want)
	}
}

func TestLocalizationDisplayNameUsesContainingBundle(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			path: "FileSystem/Applications/CarPlaySettings.app/Localizable.loctable",
			want: "CarPlaySettings",
		},
		{
			path: "FileSystem/System/Library/PrivateFrameworks/ActionKit.framework/Localizable.loctable",
			want: "ActionKit",
		},
		{
			path: "FileSystem/System/Library/PrivateFrameworks/NearFieldPrivateServices.framework/XPCServices/NFLocationService.xpc/InfoPlist.loctable",
			want: "NFLocationService",
		},
		{
			path: "FileSystem/System/Library/OnBoardingBundles/com.apple.onboarding.analyticsdevice.bundle/AnalyticsDevice.loctable",
			want: "com.apple.onboarding.analyticsdevice",
		},
		{
			path: "FileSystem/usr/share/Localizable.loctable",
			want: "Localizable",
		},
	}

	for _, tt := range tests {
		if got := localizationDisplayName(tt.path); got != tt.want {
			t.Fatalf("localizationDisplayName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestMarkdownUsesLocalizationDisplayName(t *testing.T) {
	path := "FileSystem/System/Library/PrivateFrameworks/ActionKit.framework/Localizable.loctable"
	output := t.TempDir()
	d := New(&Config{
		Title:   "Localization Test",
		IpswOld: "old.ipsw",
		IpswNew: "new.ipsw",
		Output:  output,
	})
	d.Localizations = map[string]*PlistDiff{
		"SystemOS": {
			New: map[string]string{
				path: `en.KEY = "value"`,
			},
		},
	}

	if err := d.Markdown(); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}

	readme, err := os.ReadFile(filepath.Join(output, d.TitleToFilename(), "README.md"))
	if err != nil {
		t.Fatalf("failed to read Markdown output: %v", err)
	}
	rendered := string(readme)
	if !strings.Contains(rendered, "##### ActionKit") {
		t.Fatalf("rendered Markdown should use localization owner name:\n%s", rendered)
	}
	if strings.Contains(rendered, "##### Localizable.loctable") {
		t.Fatalf("rendered Markdown should not use generic localization resource basename:\n%s", rendered)
	}
}

func TestMarkdownNewLocalizationOverflowFilesAreFenced(t *testing.T) {
	output := t.TempDir()
	d := New(&Config{
		Title:   "Localization Overflow Test",
		IpswOld: "old.ipsw",
		IpswNew: "new.ipsw",
		Output:  output,
	})

	// >= 20 new resources forces the overflow path that writes per-resource
	// Markdown files instead of inlining the content.
	volumeDiff := &PlistDiff{New: make(map[string]string)}
	for i := range 25 {
		path := fmt.Sprintf("FileSystem/System/Library/PrivateFrameworks/Frame%02d.framework/Localizable.loctable", i)
		volumeDiff.New[path] = fmt.Sprintf("en.KEY_A = \"value %d\"\nen.KEY_B = \"other %d\"", i, i)
	}
	d.Localizations = map[string]*PlistDiff{"SystemOS": volumeDiff}

	if err := d.Markdown(); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}

	// Per-resource files mirror the real path under the volume subfolder; find
	// one recursively and confirm its content is fenced.
	volDir := filepath.Join(output, d.TitleToFilename(), "LOCALIZATIONS", "SystemOS")
	var sample string
	_ = filepath.WalkDir(volDir, func(p string, dent fs.DirEntry, err error) error {
		if err == nil && sample == "" && !dent.IsDir() && strings.HasSuffix(dent.Name(), ".md") {
			sample = p
		}
		return nil
	})
	if sample == "" {
		t.Fatalf("expected overflow localization files under %s", volDir)
	}
	body, err := os.ReadFile(sample)
	if err != nil {
		t.Fatalf("failed to read overflow file: %v", err)
	}
	if !strings.Contains(string(body), "```text\n") {
		t.Fatalf("overflow localization file should fence flattened content as a code block:\n%s", body)
	}
}

func TestNormalizeLocalizedResourceFlattensLoctable(t *testing.T) {
	resource := map[string]any{
		"ar": map[string]any{
			"BLOCKLIST_LIMIT_ALERT_TITLE": "Arabic title",
		},
		"en": map[string]any{
			"BLOCKLIST_LIMIT_ALERT_TITLE": "Blocked Contacts Limit Reached",
			"%d_ADDITIONAL_CONTACTS_BLOCKED_ALERT_TITLE": map[string]any{
				"NSStringLocalizedFormatKey": "%#@value@",
				"value": map[string]any{
					"one":   "%d other contact who shares the same phone number or email address was unblocked.",
					"other": "%d other contacts who share the same phone number or email address were unblocked.",
				},
			},
		},
		"en_GB": map[string]any{
			"BLOCKLIST_LIMIT_ALERT_TITLE": "Blocked Contacts Limit Reached",
		},
	}

	data, err := plist.Marshal(resource, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("failed to marshal test plist: %v", err)
	}

	path := t.TempDir() + "/CommunicationsFilter.loctable"
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test loctable: %v", err)
	}

	normalized, err := normalizeLocalizedResource(path)
	if err != nil {
		t.Fatalf("normalizeLocalizedResource returned error: %v", err)
	}

	for _, needle := range []string{
		`en.BLOCKLIST_LIMIT_ALERT_TITLE = "Blocked Contacts Limit Reached"`,
		`en.%d_ADDITIONAL_CONTACTS_BLOCKED_ALERT_TITLE.value.one = "%d other contact who shares the same phone number or email address was unblocked."`,
	} {
		if !strings.Contains(normalized, needle) {
			t.Fatalf("normalized resource missing %q:\n%s", needle, normalized)
		}
	}
	for _, needle := range []string{`ar.`, `en_GB.`} {
		if strings.Contains(normalized, needle) {
			t.Fatalf("normalized resource should only include US English, found %q:\n%s", needle, normalized)
		}
	}
}

func TestNormalizeLocalizedResourceFallsBackToAvailableEnglishLoctable(t *testing.T) {
	resource := map[string]any{
		"en_AU": map[string]any{
			"CFBundleName": "NFLocationService",
		},
		"en_GB": map[string]any{
			"CFBundleName": "NFLocationService",
		},
		"fr": map[string]any{
			"CFBundleName": "Service NFC",
		},
		"LocProvenance": map[string]any{
			"en_AU": uint64(1),
		},
	}

	data, err := plist.Marshal(resource, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("failed to marshal test plist: %v", err)
	}

	path := t.TempDir() + "/InfoPlist.loctable"
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test loctable: %v", err)
	}

	normalized, err := normalizeLocalizedResource(path)
	if err != nil {
		t.Fatalf("normalizeLocalizedResource returned error: %v", err)
	}

	if !strings.Contains(normalized, `en.CFBundleName = "NFLocationService"`) {
		t.Fatalf("normalized resource missing fallback English locale:\n%s", normalized)
	}
	for _, needle := range []string{"en_AU.", "en_GB.", "fr.", "LocProvenance"} {
		if strings.Contains(normalized, needle) {
			t.Fatalf("normalized resource should include one English fallback, found %q:\n%s", needle, normalized)
		}
	}
}

func TestNormalizeLocalizedResourcePrefersUSEnglishLoctable(t *testing.T) {
	resource := map[string]any{
		"en": map[string]any{
			"BLOCKLIST_LIMIT_ALERT_TITLE": "Generic English title",
		},
		"en_US": map[string]any{
			"BLOCKLIST_LIMIT_ALERT_TITLE": "Blocked Contacts Limit Reached",
		},
		"en_GB": map[string]any{
			"BLOCKLIST_LIMIT_ALERT_TITLE": "Blocked Contacts Limit Reached",
		},
	}

	data, err := plist.Marshal(resource, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("failed to marshal test plist: %v", err)
	}

	path := t.TempDir() + "/CommunicationsFilter.loctable"
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("failed to write test loctable: %v", err)
	}

	normalized, err := normalizeLocalizedResource(path)
	if err != nil {
		t.Fatalf("normalizeLocalizedResource returned error: %v", err)
	}

	if !strings.Contains(normalized, `en.BLOCKLIST_LIMIT_ALERT_TITLE = "Blocked Contacts Limit Reached"`) {
		t.Fatalf("normalized resource should prefer US English:\n%s", normalized)
	}
	for _, needle := range []string{`Generic English title`, `en_US.`, `en_GB.`} {
		if strings.Contains(normalized, needle) {
			t.Fatalf("normalized resource should include one US English lane, found %q:\n%s", needle, normalized)
		}
	}
}

func TestUSEnglishLocalizedResourcePathFilter(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "System/Library/Foo.framework/en.lproj/Localizable.strings", want: true},
		{path: "System/Library/Foo.framework/en_US.lproj/Localizable.strings", want: true},
		{path: "System/Library/Foo.framework/en-US.lproj/Localizable.strings", want: true},
		{path: "System/Library/Foo.framework/Base.lproj/Localizable.strings", want: true},
		{path: "System/Library/Foo.framework/en_GB.lproj/Localizable.strings", want: false},
		{path: "System/Library/Foo.framework/fr.lproj/Localizable.strings", want: false},
		{path: "System/Library/Foo.framework/CommunicationsFilter.loctable", want: true},
	}

	for _, tt := range tests {
		if got := isUSEnglishLocalizedResourcePath(tt.path); got != tt.want {
			t.Fatalf("isUSEnglishLocalizedResourcePath(%q) = %t, want %t", tt.path, got, tt.want)
		}
	}
}
