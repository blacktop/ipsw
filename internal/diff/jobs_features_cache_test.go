package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newFeaturesJobWithInfo builds a featuresJob whose old/new Info are inserted
// for InputHash resolution.
func newFeaturesJobWithInfo(oldInfo, newInfo *info.Info) *featuresJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newFeaturesJob(d)
}

func TestFeaturesOptionsHashStable(t *testing.T) {
	a := newFeaturesJobWithInfo(nil, nil)
	b := newFeaturesJobWithInfo(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for a job with no options:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestFeaturesInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	a := newFeaturesJobWithInfo(oldInfo, newInfo).InputHash()
	b := newFeaturesJobWithInfo(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	c := newFeaturesJobWithInfo(oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a volume DMG digest changed")
	}
}

// TestFeaturesInputHashMatchesSharedHelper asserts featuresJob fingerprints the
// same four OS volumes as the shared helper and the sibling OS-volume jobs.
func TestFeaturesInputHashMatchesSharedHelper(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	got := newFeaturesJobWithInfo(oldInfo, newInfo).InputHash()
	want := volumeDMGInputHash(oldInfo, newInfo)
	if got != want {
		t.Fatalf("InputHash does not match volumeDMGInputHash:\n got=%s\n want=%s", got, want)
	}
	if ents := newEntsJobWithInfo(oldInfo, newInfo).InputHash(); got != ents {
		t.Fatalf("features and ents InputHash differ for identical volumes:\n features=%s\n ents=%s", got, ents)
	}
}

func TestFeaturesCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newFeaturesJobWithInfo(oldInfo, newInfo)
	src.d.Features = map[string]*PlistDiff{
		volumeLabel("fs"): {
			New:     map[string]string{"/System/Library/FeatureFlags/new.plist": "added"},
			Removed: []string{"/System/Library/FeatureFlags/gone.plist"},
			Updated: map[string]string{"/System/Library/FeatureFlags/changed.plist": "```diff\n+x\n```"},
		},
		volumeLabel("sys"): {
			New: map[string]string{"/System/Library/FeatureFlags/sys.plist": "added"},
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

	dst := newFeaturesJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if len(dst.d.Features) != len(src.d.Features) {
		t.Fatalf("round-trip volume count = %d, want %d", len(dst.d.Features), len(src.d.Features))
	}
	for label, want := range src.d.Features {
		got, ok := dst.d.Features[label]
		if !ok {
			t.Fatalf("round-trip missing volume %q", label)
		}
		if !plistDiffEqual(got, want) {
			t.Errorf("round-trip mismatch for %q:\n got=%+v\n want=%+v", label, got, want)
		}
	}
}

// TestFeaturesEmptyResultHydratesNonNil asserts the empty-result contract: a
// fresh run that produced no content-bearing volumes persists zero rows, and a
// later hydrate of zero rows yields a non-nil empty map so Finalize takes the
// hydrate branch and publishes the empty result rather than re-folding empty
// scan buckets.
func TestFeaturesEmptyResultHydratesNonNil(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newFeaturesJobWithInfo(oldInfo, newInfo)
	src.d.Features = map[string]*PlistDiff{} // all-empty fresh run

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newFeaturesJobWithInfo(oldInfo, newInfo)
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
	if dst.d.Features == nil {
		t.Fatal("Finalize published nil Features on the hydrate branch")
	}
	if len(dst.d.Features) != 0 {
		t.Fatalf("Finalize published %d volumes, want 0", len(dst.d.Features))
	}
}

// plistDiffEqual reports whether two PlistDiffs hold the same New/Removed/
// Updated entries.
func plistDiffEqual(a, b *PlistDiff) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.New) != len(b.New) || len(a.Removed) != len(b.Removed) || len(a.Updated) != len(b.Updated) {
		return false
	}
	for k, v := range a.New {
		if b.New[k] != v {
			return false
		}
	}
	for i := range a.Removed {
		if a.Removed[i] != b.Removed[i] {
			return false
		}
	}
	for k, v := range a.Updated {
		if b.Updated[k] != v {
			return false
		}
	}
	return true
}
