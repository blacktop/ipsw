package watch

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/download/pcc"
)

func TestCheckPCCVPhoneSnapshotBaselinesExistingAssets(t *testing.T) {
	t.Parallel()

	snapshot := &download.PCCLogSnapshot{
		TreeID:    7,
		HeadIndex: 42,
		Releases: []*download.PCCRelease{
			testPCCRelease(10, "old-a"),
			testPCCRelease(20, "old-b"),
		},
	}

	var resolveCalled bool
	check := CheckPCCVPhoneSnapshot(
		PCCVPhoneState{},
		snapshot,
		false,
		func([]*download.PCCRelease) { resolveCalled = true },
	)

	if resolveCalled {
		t.Fatal("baseline unexpectedly resolved existing OS assets")
	}
	if !check.Baselined ||
		!check.State.Initialized ||
		check.State.Version != pccVPhoneStateVersion {
		t.Fatalf("expected initialized baseline, got %#v", check)
	}
	if check.State.TreeID != 7 || check.State.HeadIndex != 42 {
		t.Fatalf("unexpected baseline cursor: %#v", check.State)
	}
	if got, want := check.State.KnownOSDigests, []string{"old-a", "old-b"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected known digests: got %v want %v", got, want)
	}
	if len(check.NewReleases) != 0 {
		t.Fatalf("baseline unexpectedly produced notifications: %#v", check.NewReleases)
	}
}

func TestCheckPCCVPhoneSnapshotUsesLogHeadInsteadOfReleaseDate(t *testing.T) {
	t.Parallel()

	oldRelease := testPCCRelease(50, "old")
	newRelease := testPCCRelease(120, "backfilled")
	state := PCCVPhoneState{
		Version:        pccVPhoneStateVersion,
		Initialized:    true,
		TreeID:         7,
		HeadIndex:      100,
		KnownOSDigests: []string{"old"},
	}
	snapshot := &download.PCCLogSnapshot{
		TreeID:    7,
		HeadIndex: 121,
		Releases:  []*download.PCCRelease{oldRelease, newRelease},
	}

	check := CheckPCCVPhoneSnapshot(
		state,
		snapshot,
		false,
		func(releases []*download.PCCRelease) {
			if len(releases) != 1 || releases[0].Index != 120 {
				t.Fatalf("unexpected releases selected for resolution: %#v", releases)
			}
			releases[0].VPhone = &download.VPhoneFirmware{Present: true, Count: 4}
		},
	)

	if len(check.NewReleases) != 1 || check.NewReleases[0].Index != 120 {
		t.Fatalf("expected backfilled release notification, got %#v", check.NewReleases)
	}
	if check.State.HeadIndex != 121 {
		t.Fatalf("expected cursor 121, got %d", check.State.HeadIndex)
	}
}

func TestCheckPCCVPhoneSnapshotRetriesUnresolvedAssets(t *testing.T) {
	t.Parallel()

	state := PCCVPhoneState{
		Version:     pccVPhoneStateVersion,
		Initialized: true,
		TreeID:      7,
		HeadIndex:   10,
	}
	release := testPCCRelease(10, "pending")
	snapshot := &download.PCCLogSnapshot{
		TreeID:    7,
		HeadIndex: 11,
		Releases:  []*download.PCCRelease{release},
	}

	first := CheckPCCVPhoneSnapshot(state, snapshot, false, func([]*download.PCCRelease) {})
	if first.Pending != 1 || first.State.HeadIndex != 10 {
		t.Fatalf("unresolved asset advanced cursor: %#v", first)
	}
	if slices.Contains(first.State.KnownOSDigests, "pending") {
		t.Fatalf("unresolved asset was marked known: %#v", first.State.KnownOSDigests)
	}

	second := CheckPCCVPhoneSnapshot(
		first.State,
		snapshot,
		false,
		func(releases []*download.PCCRelease) {
			releases[0].VPhone = &download.VPhoneFirmware{Present: false}
		},
	)
	if second.Pending != 0 || second.State.HeadIndex != 11 {
		t.Fatalf("resolved absence did not advance cursor: %#v", second)
	}
	if !slices.Contains(second.State.KnownOSDigests, "pending") {
		t.Fatalf("resolved absence was not marked known: %#v", second.State.KnownOSDigests)
	}
	if len(second.NewReleases) != 0 {
		t.Fatalf("resolved absence produced notification: %#v", second.NewReleases)
	}
}

func TestCheckPCCVPhoneSnapshotHandlesTreeRotation(t *testing.T) {
	t.Parallel()

	state := PCCVPhoneState{
		Version:        pccVPhoneStateVersion,
		Initialized:    true,
		TreeID:         7,
		HeadIndex:      200,
		KnownOSDigests: []string{"existing"},
	}
	snapshot := &download.PCCLogSnapshot{
		TreeID:    8,
		HeadIndex: 50,
		Releases: []*download.PCCRelease{
			testPCCRelease(20, "existing"),
			testPCCRelease(30, "new"),
		},
	}

	check := CheckPCCVPhoneSnapshot(
		state,
		snapshot,
		false,
		func(releases []*download.PCCRelease) {
			if len(releases) != 1 || releases[0].OSAssetDigest() != "new" {
				t.Fatalf("tree rotation selected duplicate assets: %#v", releases)
			}
			releases[0].VPhone = &download.VPhoneFirmware{Present: true}
		},
	)

	if check.State.TreeID != 8 || check.State.HeadIndex != 50 {
		t.Fatalf("unexpected rotated cursor: %#v", check.State)
	}
	if len(check.NewReleases) != 1 || check.NewReleases[0].OSAssetDigest() != "new" {
		t.Fatalf("unexpected tree-rotation notifications: %#v", check.NewReleases)
	}
}

func TestPCCVPhoneStateRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "watch", "pcc.json")
	want := PCCVPhoneState{
		Initialized:    true,
		TreeID:         9,
		HeadIndex:      123,
		KnownOSDigests: []string{"b", "a"},
	}
	if err := SavePCCVPhoneState(path, want); err != nil {
		t.Fatalf("SavePCCVPhoneState() error: %v", err)
	}

	got, err := LoadPCCVPhoneState(path)
	if err != nil {
		t.Fatalf("LoadPCCVPhoneState() error: %v", err)
	}
	if got.Version != pccVPhoneStateVersion ||
		!got.Initialized ||
		got.TreeID != want.TreeID ||
		got.HeadIndex != want.HeadIndex ||
		!slices.Equal(got.KnownOSDigests, []string{"a", "b"}) {
		t.Fatalf("unexpected round trip: %#v", got)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat state: %v", err)
		}
		if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("unexpected state permissions: got %o want %o", got, want)
		}
	}
}

func testPCCRelease(index uint64, digest string) *download.PCCRelease {
	return &download.PCCRelease{
		Index: index,
		ReleaseMetadata: pcc.ReleaseMetadata{
			Assets: []*pcc.ReleaseMetadata_Asset{{
				Type: pcc.ReleaseMetadata_ASSET_TYPE_OS,
				Url:  "https://example.test/pcc/" + digest,
			}},
		},
	}
}
