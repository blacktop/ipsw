package download

import "testing"

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
