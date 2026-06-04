package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newLaunchdJobWithInfo builds a launchdJob whose old/new Info are inserted for
// InputHash resolution.
func newLaunchdJobWithInfo(oldInfo, newInfo *info.Info) *launchdJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newLaunchdJob(d)
}

func TestLaunchdOptionsHashStable(t *testing.T) {
	a := newLaunchdJobWithInfo(nil, nil)
	b := newLaunchdJobWithInfo(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for a job with no options:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

// TestLaunchdOptionsHashDistinctFromFeatures asserts the no-option jobs do not
// collide on a shared constant tag; each folds its own task label.
func TestLaunchdOptionsHashDistinctFromFeatures(t *testing.T) {
	launchd := newLaunchdJobWithInfo(nil, nil).OptionsHash()
	features := newFeaturesJobWithInfo(nil, nil).OptionsHash()
	if launchd == features {
		t.Fatalf("launchd and features OptionsHash collide: %s", launchd)
	}
}

func TestLaunchdInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	a := newLaunchdJobWithInfo(oldInfo, newInfo).InputHash()
	b := newLaunchdJobWithInfo(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	c := newLaunchdJobWithInfo(oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when the fs DMG digest changed")
	}
}

// TestLaunchdInputHashIgnoresOtherVolumes is the fs-only invariant: launchd
// reads /sbin/launchd from the FileSystem DMG alone, so its InputHash must NOT
// move when sys/app/exc digests change. A SystemOS-only rebuild has to keep
// serving the cached launchd diff.
func TestLaunchdInputHashIgnoresOtherVolumes(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	base := newLaunchdJobWithInfo(oldInfo, testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})).InputHash()

	for _, key := range []string{"Cryptex1,SystemOS", "Cryptex1,AppOS", "Ap,ExclaveOS"} {
		newInfo := testIPSWInfo(map[string]testManifestEntry{
			"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
			key:  {path: "added.dmg", digest: []byte{0xff}},
		})
		if got := newLaunchdJobWithInfo(oldInfo, newInfo).InputHash(); got != base {
			t.Fatalf("InputHash moved when %s changed; launchd must ignore non-fs volumes:\n base=%s\n got=%s", key, base, got)
		}
	}

	// Differs from the all-four-volume helper (which the sibling OS jobs use):
	// folding only "fs" must NOT equal folding fs+sys+app+exc.
	if base == volumeDMGInputHash(oldInfo, testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})) {
		t.Fatal("launchd fs-only InputHash collides with the all-four-volume helper")
	}
}

func TestLaunchdCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newLaunchdJobWithInfo(oldInfo, newInfo)
	src.d.Launchd = "```diff\n+com.apple.launchd.example\n```"

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newLaunchdJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if dst.d.Launchd != src.d.Launchd {
		t.Fatalf("round-trip mismatch:\n got=%q\n want=%q", dst.d.Launchd, src.d.Launchd)
	}
}

// TestLaunchdEmptyResultHydratesNonNil asserts the empty-result contract: an
// empty fresh run (no launchd diff) persists zero rows, and a later zero-row
// hydrate yields a non-nil pointer to "" so Finalize publishes the empty result
// via the hydrate branch.
func TestLaunchdEmptyResultHydratesNonNil(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newLaunchdJobWithInfo(oldInfo, newInfo) // d.Launchd == "" (no diff)

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newLaunchdJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate of zero rows left j.hydrated nil; Finalize would not take the hydrate branch")
	}
	if *dst.hydrated != "" {
		t.Fatalf("Hydrate of zero rows produced %q, want empty", *dst.hydrated)
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize on empty hydrate path: %v", err)
	}
	if dst.d.Launchd != "" {
		t.Fatalf("Finalize published %q on the empty hydrate branch, want empty", dst.d.Launchd)
	}
}
