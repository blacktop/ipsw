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

func mustReleasedDate(t *testing.T, value string) ReleasedDate {
	t.Helper()

	var released ReleasedDate
	if err := released.UnmarshalJSON([]byte(`"` + value + `"`)); err != nil {
		t.Fatalf("failed to parse release date %s: %v", value, err)
	}
	return released
}
