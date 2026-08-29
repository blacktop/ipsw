package download

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWalkLocalAppleDBReturnsPathErrorBeforeVisit(t *testing.T) {
	t.Parallel()

	visited := false
	err := walkLocalAppleDB(filepath.Join(t.TempDir(), "missing"), func(string, os.FileInfo) error {
		visited = true
		return nil
	})
	if err == nil {
		t.Fatal("expected walk error for missing path")
	}
	if visited {
		t.Fatal("visitor called without valid file info")
	}
}

func TestOsFilesLatestSkipsHiddenLatestVersions(t *testing.T) {
	t.Parallel()

	fs := OsFiles{
		{
			OS:                     "iOS",
			Version:                "26.5 beta 2",
			Build:                  "23F5054d",
			Released:               mustReleasedDate(t, "2026-04-13"),
			Beta:                   true,
			HideFromLatestVersions: true,
		},
		{
			OS:       "iOS",
			Version:  "26.5 beta 2",
			Build:    "23F5054h",
			Released: mustReleasedDate(t, "2026-04-13"),
			Beta:     true,
		},
	}

	got := fs.Latest(&ADBQuery{
		OSes:   []string{"iOS"},
		IsBeta: true,
		Latest: true,
	})
	if got == nil {
		t.Fatal("expected latest osfile")
	}
	if got.Build != "23F5054h" {
		t.Fatalf("unexpected build: got %s want 23F5054h", got.Build)
	}
}

func TestOsFilesQueryLatestSkipsHiddenLatestVersions(t *testing.T) {
	t.Parallel()

	hiddenSource := OsFileSource{
		Type:      "ipsw",
		DeviceMap: []string{"iPhone99,1"},
	}
	visibleSource := OsFileSource{
		Type:      "ipsw",
		DeviceMap: []string{"iPhone12,1"},
	}

	fs := OsFiles{
		{
			OS:                     "iOS",
			Version:                "26.5 beta 2",
			Build:                  "23F5054d",
			Released:               mustReleasedDate(t, "2026-04-13"),
			Beta:                   true,
			HideFromLatestVersions: true,
			Sources:                []OsFileSource{hiddenSource},
		},
		{
			OS:       "iOS",
			Version:  "26.5 beta 2",
			Build:    "23F5054h",
			Released: mustReleasedDate(t, "2026-04-13"),
			Beta:     true,
			Sources:  []OsFileSource{visibleSource},
		},
	}

	got := fs.Query(&ADBQuery{
		OSes:   []string{"iOS"},
		Type:   "ipsw",
		IsBeta: true,
		Latest: true,
	})
	if len(got) != 1 {
		t.Fatalf("unexpected source count: got %d want 1", len(got))
	}
	if got[0].DeviceMap[0] != "iPhone12,1" {
		t.Fatalf("unexpected device map: got %v", got[0].DeviceMap)
	}
}

func TestOsFilesQueryLatestFallsBackToNewestVisibleDate(t *testing.T) {
	t.Parallel()

	fs := OsFiles{
		{
			OS:                     "iOS",
			Version:                "26.5 beta 2",
			Build:                  "23F5054d",
			Released:               mustReleasedDate(t, "2026-04-13"),
			Beta:                   true,
			HideFromLatestVersions: true,
			Sources: []OsFileSource{{
				Type:      "ipsw",
				DeviceMap: []string{"iPhone99,1"},
			}},
		},
		{
			OS:       "iOS",
			Version:  "26.5 beta",
			Build:    "23F5043g",
			Released: mustReleasedDate(t, "2026-04-01"),
			Beta:     true,
			Sources: []OsFileSource{{
				Type:      "ipsw",
				DeviceMap: []string{"iPhone12,1"},
			}},
		},
	}

	got := fs.Query(&ADBQuery{
		OSes:   []string{"iOS"},
		Type:   "ipsw",
		IsBeta: true,
		Latest: true,
	})
	if len(got) != 1 {
		t.Fatalf("unexpected source count: got %d want 1", len(got))
	}
	if got[0].DeviceMap[0] != "iPhone12,1" {
		t.Fatalf("unexpected device map: got %v", got[0].DeviceMap)
	}
}

func TestOsFilesQueryRetainsReleaseIdentityAndOTAFilters(t *testing.T) {
	t.Parallel()

	full := OsFileSource{
		Type:      "ota",
		DeviceMap: []string{"iPhone16,2", "iPhone15,4"},
	}
	delta := OsFileSource{
		Type:              "ota",
		PrerequisiteBuild: PrerequisiteBuilds{Builds: []string{"23A500"}},
		DeviceMap:         []string{"iPhone16,2"},
	}
	fs := OsFiles{{
		OS:       "iOS",
		Version:  "26.0 beta",
		Build:    "23A501",
		Released: mustReleasedDate(t, "2026-08-20"),
		Beta:     true,
		Sources:  []OsFileSource{delta, full},
	}}

	got := fs.Query(&ADBQuery{OSes: []string{"iOS"}, Type: "ota", Deltas: true})
	if len(got) != 2 {
		t.Fatalf("delta query returned %d records, want 2", len(got))
	}
	for _, record := range got {
		if record.OS != "iOS" || record.Version != "26.0 beta" || record.Build != "23A501" || record.Channel != "beta" {
			t.Fatalf("record lost release identity: %+v", record)
		}
	}
	if len(got[0].PrerequisiteBuild.Builds) != 0 {
		t.Fatalf("first deterministic record is not the full OTA: %+v", got[0])
	}
	if !reflect.DeepEqual(got[0].DeviceMap, []string{"iPhone15,4", "iPhone16,2"}) {
		t.Fatalf("devices are not canonical: %v", got[0].DeviceMap)
	}

	fullOnly := fs.Query(&ADBQuery{OSes: []string{"iOS"}, Type: "ota"})
	if len(fullOnly) != 1 || len(fullOnly[0].PrerequisiteBuild.Builds) != 0 {
		t.Fatalf("full OTA query = %+v, want only the source without prerequisites", fullOnly)
	}

	prereqOnly := fs.Query(&ADBQuery{OSes: []string{"iOS"}, Type: "ota", PrerequisiteBuild: "23A500"})
	if len(prereqOnly) != 1 || !reflect.DeepEqual(prereqOnly[0].PrerequisiteBuild.Builds, []string{"23A500"}) {
		t.Fatalf("prerequisite OTA query = %+v, want only matching delta", prereqOnly)
	}
}

func TestOsFilesQueryOrderIsDeterministic(t *testing.T) {
	t.Parallel()

	newer := AppleDbOsFile{
		OS:       "iOS",
		Version:  "26.0 beta",
		Build:    "23A501",
		Released: mustReleasedDate(t, "2026-08-20"),
		Beta:     true,
		Sources: []OsFileSource{
			{Type: "ota", DeviceMap: []string{"iPhone16,2"}, PrerequisiteBuild: PrerequisiteBuilds{Builds: []string{"23A500"}}},
			{Type: "ota", DeviceMap: []string{"iPhone15,4"}},
		},
	}
	older := AppleDbOsFile{
		OS:       "iOS",
		Version:  "25.6",
		Build:    "22G90",
		Released: mustReleasedDate(t, "2026-08-01"),
		Sources:  []OsFileSource{{Type: "ota", DeviceMap: []string{"iPhone14,7"}}},
	}
	query := &ADBQuery{OSes: []string{"iOS"}, Type: "ota", Deltas: true}

	forward := OsFiles{newer, older}.Query(query)
	newer.Sources[0], newer.Sources[1] = newer.Sources[1], newer.Sources[0]
	reversed := OsFiles{older, newer}.Query(query)
	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("query order depends on AppleDB traversal order:\nforward: %#v\nreverse: %#v", forward, reversed)
	}
}

func TestOsFilesLatestSkipsBuildsWithoutDownloadableSource(t *testing.T) {
	t.Parallel()

	// Mirrors macOS 15.7.8 RC 2 (24G809): an RC published OTA-only that is newer
	// than the latest build carrying a downloadable ipsw for the device. With
	// --type ipsw --device Mac14,3, Latest must skip the OTA-only RC and report
	// the build the download step can actually fetch; otherwise detect picks a
	// build the download then fails on ("no results found").
	otaOnlyRC := AppleDbOsFile{
		OS:       "macOS",
		Version:  "15.7.8 RC 2",
		Build:    "24G809",
		Released: mustReleasedDate(t, "2026-06-15"),
		RC:       true,
		Sources:  []OsFileSource{{Type: "ota", DeviceMap: []string{"Mac14,3"}}},
	}
	ipswRelease := AppleDbOsFile{
		OS:       "macOS",
		Version:  "15.6.1",
		Build:    "24G90",
		Released: mustReleasedDate(t, "2026-06-01"),
		Sources:  []OsFileSource{{Type: "ipsw", DeviceMap: []string{"Mac14,3"}}},
	}
	fs := OsFiles{otaOnlyRC, ipswRelease}

	got := fs.Latest(&ADBQuery{OSes: []string{"macOS"}, Type: "ipsw", Device: "Mac14,3", Latest: true})
	if got == nil {
		t.Fatal("expected a downloadable ipsw osfile")
	}
	if got.Build != "24G90" {
		t.Fatalf("Latest(--type ipsw) = %s; want 24G90 (OTA-only RC must be skipped)", got.Build)
	}

	// The same RC is still the latest when its actual source type is requested.
	got = fs.Latest(&ADBQuery{OSes: []string{"macOS"}, Type: "ota", Device: "Mac14,3", Latest: true})
	if got == nil || got.Build != "24G809" {
		t.Fatalf("Latest(--type ota) = %v; want 24G809", got)
	}
}

func TestOsFilesLatestAppliesOTASourceFilters(t *testing.T) {
	t.Parallel()

	// Newer build whose only device-matching OTA source is a delta (it carries a
	// prerequisite build); the older build offers a full OTA (no prerequisite).
	deltaOnly := AppleDbOsFile{
		OS:       "iOS",
		Version:  "26.6 beta 3",
		Build:    "23G5070",
		Released: mustReleasedDate(t, "2026-06-15"),
		Sources: []OsFileSource{{
			Type:              "ota",
			DeviceMap:         []string{"iPhone16,2"},
			PrerequisiteBuild: PrerequisiteBuilds{Builds: []string{"23G5060"}},
		}},
	}
	fullOTA := AppleDbOsFile{
		OS:       "iOS",
		Version:  "26.6 beta 2",
		Build:    "23G5043d",
		Released: mustReleasedDate(t, "2026-06-01"),
		Sources:  []OsFileSource{{Type: "ota", DeviceMap: []string{"iPhone16,2"}}},
	}
	fs := OsFiles{deltaOnly, fullOTA}

	// Default full-OTA query (no --deltas): the newer delta-only build is not
	// fetchable, so Latest must fall back to the full OTA.
	got := fs.Latest(&ADBQuery{OSes: []string{"iOS"}, Type: "ota", Device: "iPhone16,2", Latest: true})
	if got == nil || got.Build != "23G5043d" {
		t.Fatalf("Latest(full ota) = %v; want 23G5043d (delta-only build skipped)", got)
	}

	// --deltas: the newer delta build is now eligible.
	got = fs.Latest(&ADBQuery{OSes: []string{"iOS"}, Type: "ota", Device: "iPhone16,2", Deltas: true, Latest: true})
	if got == nil || got.Build != "23G5070" {
		t.Fatalf("Latest(delta ota) = %v; want 23G5070", got)
	}

	// --prereq-build matching the delta source selects the newer build.
	got = fs.Latest(&ADBQuery{OSes: []string{"iOS"}, Type: "ota", Device: "iPhone16,2", PrerequisiteBuild: "23G5060", Latest: true})
	if got == nil || got.Build != "23G5070" {
		t.Fatalf("Latest(prereq ota) = %v; want 23G5070", got)
	}

	// --prereq-build with no matching source falls back to none.
	got = fs.Latest(&ADBQuery{OSes: []string{"iOS"}, Type: "ota", Device: "iPhone16,2", PrerequisiteBuild: "23G9999", Latest: true})
	if got != nil {
		t.Fatalf("Latest(prereq ota miss) = %v; want nil", got)
	}
}

func mustReleasedDate(t *testing.T, value string) ReleasedDate {
	t.Helper()

	var released ReleasedDate
	if err := released.UnmarshalJSON([]byte(`"` + value + `"`)); err != nil {
		t.Fatalf("failed to parse release date %s: %v", value, err)
	}
	return released
}

func TestEnsureLocalAppleDBNoUpdate(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	repo := filepath.Join(configDir, "appledb")

	if _, err := ensureLocalAppleDB(configDir, true); err == nil {
		t.Fatal("missing checkout: expected error, not a clone or empty results")
	}

	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLocalAppleDB(configDir, true); err == nil {
		t.Fatal("empty checkout (no osFiles): expected error, not empty results")
	}

	if err := os.MkdirAll(filepath.Join(repo, "osFiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ensureLocalAppleDB(configDir, true)
	if err != nil {
		t.Fatalf("valid checkout with no-update: %v", err)
	}
	if got != repo {
		t.Fatalf("repo path = %s, want %s", got, repo)
	}
}

func TestLocalAppleDBQueryReturnsReleaseSourceRecords(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	releaseDir := filepath.Join(configDir, "appledb", "osFiles", "iOS", "23A501 - 26.0x")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := `{
		"osStr":"iOS",
		"version":"26.0 beta",
		"build":"23A501",
		"released":"2026-08-20",
		"beta":true,
		"sources":[{
			"type":"ota",
			"deviceMap":["iPhone16,2"],
			"links":[{"url":"https://example.com/full.zip","active":true}],
			"hashes":{"sha2-256":"sha256-value","sha1":"sha1-value"},
			"size":123456
		}]
	}`
	if err := os.WriteFile(filepath.Join(releaseDir, "23A501.json"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	records, err := LocalAppleDBQuery(&ADBQuery{
		OSes:      []string{"iOS"},
		Type:      "ota",
		IsBeta:    true,
		ConfigDir: configDir,
		NoUpdate:  true,
	})
	if err != nil {
		t.Fatalf("local query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("local query returned %d records, want 1", len(records))
	}
	record := records[0]
	if record.OS != "iOS" || record.Version != "26.0 beta" || record.Build != "23A501" || record.Channel != "beta" {
		t.Fatalf("local record lost release identity: %+v", record)
	}
	if record.Type != "ota" || record.Hashes.SHA256 != "sha256-value" || record.Size != 123456 {
		t.Fatalf("local record lost source identity: %+v", record)
	}
}
