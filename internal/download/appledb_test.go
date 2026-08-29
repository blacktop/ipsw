package download

import (
	"encoding/json"
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

func TestOsFilesQueryPinsNewestVersionForEqualReleaseDates(t *testing.T) {
	t.Parallel()

	released := mustReleasedDate(t, "2026-08-20")
	fs := OsFiles{
		{OS: "iOS", Version: "26.0", Build: "23A500", Released: released, Sources: []OsFileSource{{Type: "ipsw"}}},
		{OS: "iOS", Version: "26.1", Build: "23B500", Released: released, Sources: []OsFileSource{{Type: "ipsw"}}},
	}
	records := fs.Query(&ADBQuery{OSes: []string{"iOS"}, Type: "ipsw"})
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	if records[0].Version != "26.1" || records[1].Version != "26.0" {
		t.Fatalf("equal-date order = %s, %s; want 26.1, 26.0", records[0].Version, records[1].Version)
	}
}

func TestOsFilesQueryUsesCanonicalFamilyAndAuthoritativeMetadata(t *testing.T) {
	t.Parallel()

	var source OsFileSource
	if err := json.Unmarshal([]byte(`{
		"type":"ipsw",
		"links":[
			{"url":"https://example.com/first.ipsw","active":true},
			{"url":"https://example.com/second.ipsw","active":true}
		],
		"hashes":{"sha2-256":"sha256-value","sha1":"sha1-value"},
		"size":0
	}`), &source); err != nil {
		t.Fatalf("unmarshal source: %v", err)
	}
	fs := OsFiles{{
		OS:          "iPhone Software",
		canonicalOS: "iOS",
		Version:     "1.0",
		Build:       "1A1",
		Sources:     []OsFileSource{source},
	}}
	records := fs.Query(&ADBQuery{OSes: []string{"iOS"}, Type: "ipsw"})
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	record := records[0]
	if record.OS != "iOS" {
		t.Fatalf("canonical OS = %q, want iOS", record.OS)
	}
	if record.ActiveURL == nil || *record.ActiveURL != "https://example.com/first.ipsw" {
		t.Fatalf("active URL = %v, want first active link", record.ActiveURL)
	}
	if record.SHA256 == nil || *record.SHA256 != "sha256-value" || record.SHA1 == nil || *record.SHA1 != "sha1-value" {
		t.Fatalf("hash metadata = sha256:%v sha1:%v", record.SHA256, record.SHA1)
	}
	if record.Size == nil || *record.Size != 0 {
		t.Fatalf("explicit zero size = %v, want non-nil zero", record.Size)
	}
	if got := fs.Query(&ADBQuery{OSes: []string{"macOS"}, Type: "ipsw"}); len(got) != 0 {
		t.Fatalf("other-OS query returned %d records, want 0", len(got))
	}
}

func TestOsFileSourceUnmarshalResetsNullableMetadataPresence(t *testing.T) {
	t.Parallel()

	var source OsFileSource
	if err := json.Unmarshal([]byte(`{"type":"ipsw","hashes":{"sha2-256":"known"},"size":123}`), &source); err != nil {
		t.Fatalf("unmarshal known metadata: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"type":"ipsw"}`), &source); err != nil {
		t.Fatalf("unmarshal absent metadata: %v", err)
	}
	records := OsFiles{{OS: "iOS", Sources: []OsFileSource{source}}}.Query(&ADBQuery{OSes: []string{"iOS"}, Type: "ipsw"})
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	if records[0].SHA256 != nil || records[0].SHA1 != nil || records[0].Size != nil {
		t.Fatalf("reused source retained absent metadata: %+v", records[0])
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
	if record.Type != "ota" || record.SHA256 == nil || *record.SHA256 != "sha256-value" || record.Size == nil || *record.Size != 123456 {
		t.Fatalf("local record lost source identity: %+v", record)
	}
}

func TestLocalAppleDBRSRTraversalEmitsSourcesOnceAndSkipsInternal(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	releaseDir := filepath.Join(configDir, "appledb", "osFiles", "Rapid Security Responses", "iOS", "20x - 16.x")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	publicFixture := `{
		"osStr":"iPhone Software",
		"version":"16.4.1 (a)",
		"build":"20E772520a",
		"released":"2023-05-01",
		"sources":[
			{"type":"ota","prerequisiteBuild":"20E252","deviceMap":["iPhone10,1"]},
			{"type":"ota","prerequisiteBuild":"20E252","deviceMap":["iPhone10,2"]}
		]
	}`
	internalFixture := `{
		"osStr":"iOS",
		"version":"16.4.1 (internal)",
		"build":"20E999",
		"internal":true,
		"sources":[{"type":"ota","deviceMap":["iPhone99,1"]}]
	}`
	if err := os.WriteFile(filepath.Join(releaseDir, "20E772520a.json"), []byte(publicFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "20E999.json"), []byte(internalFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	records, err := LocalAppleDBQuery(&ADBQuery{
		OSes:      []string{"iOS"},
		Type:      "rsr",
		ConfigDir: configDir,
		NoUpdate:  true,
	})
	if err != nil {
		t.Fatalf("local RSR query: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("local RSR record count = %d, want exactly 2 sources once each", len(records))
	}
	for _, record := range records {
		if record.OS != "iOS" || record.Type != "rsr" || record.Build != "20E772520a" {
			t.Fatalf("unexpected local RSR record: %+v", record)
		}
	}
}

func TestAPIAppleDBRSRTraversalReadsFilesForAllOSesAndSkipsInternal(t *testing.T) {
	t.Parallel()

	listings := map[string][]GithubContentsResponse{
		"osFiles/Rapid Security Responses/iOS": {
			{Type: "dir", Name: "20x - 16.x", Path: "osFiles/Rapid Security Responses/iOS/20x - 16.x"},
		},
		"osFiles/Rapid Security Responses/iOS/20x - 16.x": {
			{Type: "file", Name: "20E1.json", Path: "osFiles/Rapid Security Responses/iOS/20x - 16.x/20E1.json"},
			{Type: "file", Name: "20E2.json", Path: "osFiles/Rapid Security Responses/iOS/20x - 16.x/20E2.json"},
			{Type: "dir", Name: "nested", Path: "osFiles/Rapid Security Responses/iOS/20x - 16.x/nested"},
		},
		"osFiles/Rapid Security Responses/macOS": {
			{Type: "dir", Name: "22x - 13.x", Path: "osFiles/Rapid Security Responses/macOS/22x - 13.x"},
		},
		"osFiles/Rapid Security Responses/macOS/22x - 13.x": {
			{Type: "file", Name: "22D1.json", Path: "osFiles/Rapid Security Responses/macOS/22x - 13.x/22D1.json"},
		},
	}
	files := map[string]AppleDbOsFile{
		"osFiles/Rapid Security Responses/iOS/20x - 16.x/20E1.json": {
			OS: "iPhone Software", Version: "16.4.1 (a)", Build: "20E1", Sources: []OsFileSource{{Type: "ota"}},
		},
		"osFiles/Rapid Security Responses/iOS/20x - 16.x/20E2.json": {
			OS: "iOS", Version: "16.4.1 (internal)", Build: "20E2", Internal: true, Sources: []OsFileSource{{Type: "ota"}},
		},
		"osFiles/Rapid Security Responses/macOS/22x - 13.x/22D1.json": {
			OS: "Mac OS X", Version: "13.2.1 (a)", Build: "22D1", Sources: []OsFileSource{{Type: "ota"}},
		},
	}
	var readPaths []string
	records, err := queryAppleDBAPI(
		&ADBQuery{OSes: []string{"iOS", "macOS"}, Type: "rsr"},
		func(path string) ([]GithubContentsResponse, error) {
			return listings[path], nil
		},
		func(path string) (*AppleDbOsFile, error) {
			readPaths = append(readPaths, path)
			file := files[path]
			return &file, nil
		},
	)
	if err != nil {
		t.Fatalf("API RSR query: %v", err)
	}
	if len(readPaths) != 3 {
		t.Fatalf("API read paths = %v, want exactly the three JSON files", readPaths)
	}
	if len(records) != 2 {
		t.Fatalf("API RSR record count = %d, want two public releases", len(records))
	}
	gotOSes := []string{records[0].OS, records[1].OS}
	if !reflect.DeepEqual(gotOSes, []string{"iOS", "macOS"}) {
		t.Fatalf("API RSR OSes = %v, want all requested canonical families", gotOSes)
	}
	for _, record := range records {
		if record.Type != "rsr" {
			t.Fatalf("API RSR source type = %q, want rsr", record.Type)
		}
	}
}

func TestLocalAndAPISelectionEquivalentForFullOTAAndRSR(t *testing.T) {
	tests := []struct {
		name       string
		sourceType string
		folder     string
		fixture    string
		want       int
	}{
		{
			name:       "full OTA",
			sourceType: "ota",
			folder:     "23x - 26.x",
			want:       1,
			fixture: `{
				"osStr":"iPhone Software",
				"version":"26.0",
				"build":"23A500",
				"released":"2026-08-20",
				"sources":[
					{"type":"ota","deviceMap":["iPhone15,4"],"links":[{"url":"https://example.com/full.zip","active":true}]},
					{"type":"ota","prerequisiteBuild":"23A499","deviceMap":["iPhone15,4"],"links":[{"url":"https://example.com/delta.zip","active":true}]}
				]
			}`,
		},
		{
			name:       "RSR",
			sourceType: "rsr",
			folder:     "20x - 16.x",
			want:       2,
			fixture: `{
				"osStr":"iPhone Software",
				"version":"16.4.1 (a)",
				"build":"20E1",
				"released":"2023-05-01",
				"sources":[
					{"type":"ota","prerequisiteBuild":"20E0","deviceMap":["iPhone10,1"]},
					{"type":"ota","prerequisiteBuild":"20E0","deviceMap":["iPhone10,2"]}
				]
			}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configDir := t.TempDir()
			rootParts := []string{configDir, "appledb", "osFiles"}
			apiRoot := "osFiles/iOS"
			if tt.sourceType == "rsr" {
				rootParts = append(rootParts, "Rapid Security Responses")
				apiRoot = "osFiles/Rapid Security Responses/iOS"
			}
			rootParts = append(rootParts, "iOS", tt.folder)
			releaseDir := filepath.Join(rootParts...)
			if err := os.MkdirAll(releaseDir, 0o755); err != nil {
				t.Fatal(err)
			}
			fileName := "fixture.json"
			if err := os.WriteFile(filepath.Join(releaseDir, fileName), []byte(tt.fixture), 0o644); err != nil {
				t.Fatal(err)
			}

			query := &ADBQuery{OSes: []string{"iOS"}, Type: tt.sourceType, ConfigDir: configDir, NoUpdate: true}
			localRecords, err := LocalAppleDBQuery(query)
			if err != nil {
				t.Fatalf("local query: %v", err)
			}
			folderPath := apiRoot + "/" + tt.folder
			filePath := folderPath + "/" + fileName
			apiRecords, err := queryAppleDBAPI(
				query,
				func(path string) ([]GithubContentsResponse, error) {
					switch path {
					case apiRoot:
						return []GithubContentsResponse{{Type: "dir", Name: tt.folder, Path: folderPath}}, nil
					case folderPath:
						return []GithubContentsResponse{{Type: "file", Name: fileName, Path: filePath}}, nil
					default:
						return nil, nil
					}
				},
				func(path string) (*AppleDbOsFile, error) {
					if path != filePath {
						t.Fatalf("API attempted to read %q, want %q", path, filePath)
					}
					var osfile AppleDbOsFile
					if err := json.Unmarshal([]byte(tt.fixture), &osfile); err != nil {
						return nil, err
					}
					return &osfile, nil
				},
			)
			if err != nil {
				t.Fatalf("API query: %v", err)
			}
			if len(localRecords) != tt.want {
				t.Fatalf("local record count = %d, want %d", len(localRecords), tt.want)
			}
			if !reflect.DeepEqual(localRecords, apiRecords) {
				t.Fatalf("local/API selection differs:\nlocal: %#v\n  API: %#v", localRecords, apiRecords)
			}
		})
	}
}
