package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newLocsJobWithInfo builds a locsJob whose old/new Info are inserted for
// InputHash resolution.
func newLocsJobWithInfo(oldInfo, newInfo *info.Info) *locsJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newLocalizationsJob(d)
}

func TestLocsOptionsHashStable(t *testing.T) {
	a := newLocsJobWithInfo(nil, nil)
	b := newLocsJobWithInfo(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for a job with no options:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

// TestLocsOptionsHashDistinctFromFeatures asserts the two no-option jobs do not
// collide on a shared constant tag; each folds its own task label.
func TestLocsOptionsHashDistinctFromFeatures(t *testing.T) {
	locs := newLocsJobWithInfo(nil, nil).OptionsHash()
	features := newFeaturesJobWithInfo(nil, nil).OptionsHash()
	if locs == features {
		t.Fatalf("locs and features OptionsHash collide: %s", locs)
	}
}

func TestLocsInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	a := newLocsJobWithInfo(oldInfo, newInfo).InputHash()
	b := newLocsJobWithInfo(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	c := newLocsJobWithInfo(oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a volume DMG digest changed")
	}
}

// TestLocsInputHashMatchesSharedHelper asserts locsJob fingerprints the same
// four OS volumes as the shared helper and the sibling OS-volume jobs.
func TestLocsInputHashMatchesSharedHelper(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	got := newLocsJobWithInfo(oldInfo, newInfo).InputHash()
	want := volumeDMGInputHash(oldInfo, newInfo)
	if got != want {
		t.Fatalf("InputHash does not match volumeDMGInputHash:\n got=%s\n want=%s", got, want)
	}
	if features := newFeaturesJobWithInfo(oldInfo, newInfo).InputHash(); got != features {
		t.Fatalf("locs and features InputHash differ for identical volumes:\n locs=%s\n features=%s", got, features)
	}
}

func TestLocsCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newLocsJobWithInfo(oldInfo, newInfo)
	src.d.Localizations = map[string]*PlistDiff{
		volumeListDMGLabel("fs"): {
			New:     map[string]string{"/System/Library/.../en.lproj/Localizable.strings": "added"},
			Removed: []string{"/System/Library/.../fr.lproj/Localizable.strings"},
			Updated: map[string]string{"/System/Library/.../de.lproj/Localizable.strings": "```diff\n+x\n```"},
		},
		volumeListDMGLabel("sys"): {
			New: map[string]string{"/System/Library/.../es.lproj/Root.strings": "added"},
		},
	}

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newLocsJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if len(dst.d.Localizations) != len(src.d.Localizations) {
		t.Fatalf("round-trip volume count = %d, want %d", len(dst.d.Localizations), len(src.d.Localizations))
	}
	for label, want := range src.d.Localizations {
		got, ok := dst.d.Localizations[label]
		if !ok {
			t.Fatalf("round-trip missing volume %q", label)
		}
		if !plistDiffEqual(got, want) {
			t.Errorf("round-trip mismatch for %q:\n got=%+v\n want=%+v", label, got, want)
		}
	}
}

// TestLocsEmptyResultHydratesNonNil asserts the empty-result contract: an
// all-empty fresh run persists zero rows, and a later hydrate of zero rows
// yields a non-nil empty map so Finalize publishes the empty result via the
// hydrate branch.
func TestLocsEmptyResultHydratesNonNil(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newLocsJobWithInfo(oldInfo, newInfo)
	src.d.Localizations = map[string]*PlistDiff{} // all-empty fresh run

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newLocsJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate of zero rows left j.hydrated nil; Finalize would re-fold instead of publishing")
	}
	if len(dst.hydrated) != 0 {
		t.Fatalf("Hydrate of zero rows produced %d volumes, want 0", len(dst.hydrated))
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize on empty hydrate path: %v", err)
	}
	if dst.d.Localizations == nil {
		t.Fatal("Finalize published nil Localizations on the hydrate branch")
	}
	if len(dst.d.Localizations) != 0 {
		t.Fatalf("Finalize published %d volumes, want 0", len(dst.d.Localizations))
	}
}
