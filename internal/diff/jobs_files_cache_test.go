package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newFilesJobWithInfo builds a filesJob whose old/new Info and IPSW paths are
// inserted for InputHash resolution.
func newFilesJobWithInfo(oldInfo, newInfo *info.Info, oldPath, newPath string) *filesJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	d.Old.IPSWPath = oldPath
	d.New.IPSWPath = newPath
	return newFilesJob(d)
}

// stubZipListings installs a fake readZipCentralDirectory keyed by IPSW path so
// the files InputHash can be exercised without writing real zips. It restores
// the original on test cleanup.
func stubZipListings(t *testing.T, listings map[string][]zipMember) {
	t.Helper()
	orig := readZipCentralDirectory
	t.Cleanup(func() { readZipCentralDirectory = orig })
	readZipCentralDirectory = func(ipswPath string) ([]zipMember, error) {
		return listings[ipswPath], nil
	}
}

func TestFilesOptionsHashStable(t *testing.T) {
	a := newFilesJobWithInfo(nil, nil, "", "")
	b := newFilesJobWithInfo(nil, nil, "", "")
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for a job with no options:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

// TestFilesOptionsHashDistinctFromFeatures asserts the no-option jobs do not
// collide on a shared constant tag; each folds its own task label.
func TestFilesOptionsHashDistinctFromFeatures(t *testing.T) {
	files := newFilesJobWithInfo(nil, nil, "", "").OptionsHash()
	features := newFeaturesJobWithInfo(nil, nil).OptionsHash()
	if files == features {
		t.Fatalf("files and features OptionsHash collide: %s", files)
	}
}

func TestFilesInputHashStableAndDMGSensitive(t *testing.T) {
	stubZipListings(t, map[string][]zipMember{
		"old.ipsw": {{name: "BuildManifest.plist", crc: 0x1, size: 10}},
		"new.ipsw": {{name: "BuildManifest.plist", crc: 0x2, size: 11}},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	a := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw").InputHash()
	b := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw").InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	c := newFilesJobWithInfo(oldInfo, newInfo2, "old.ipsw", "new.ipsw").InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a volume DMG digest changed")
	}
}

// TestFilesInputHashChangesWhenZipListingChanges is the core invariant: a loose
// zip member added/removed/changed at the zip root moves no DMG digest, but
// filesJob — which scans the zip itself — must still detect it. The two infos
// share identical DMG digests; only the zip listing differs.
func TestFilesInputHashChangesWhenZipListingChanges(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "fs.dmg", digest: []byte{0x01}},
	})

	base := map[string][]zipMember{
		"old.ipsw": {{name: "Restore.plist", crc: 0xaa, size: 100}},
		"new.ipsw": {{name: "Restore.plist", crc: 0xaa, size: 100}},
	}
	stubZipListings(t, base)
	identical := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw").InputHash()

	cases := map[string][]zipMember{
		"member added": {
			{name: "Restore.plist", crc: 0xaa, size: 100},
			{name: "loose.txt", crc: 0xbb, size: 5},
		},
		"member CRC changed": {
			{name: "Restore.plist", crc: 0xcc, size: 100},
		},
		"member size changed": {
			{name: "Restore.plist", crc: 0xaa, size: 200},
		},
		"member renamed": {
			{name: "Restore2.plist", crc: 0xaa, size: 100},
		},
	}
	for name, newListing := range cases {
		stubZipListings(t, map[string][]zipMember{
			"old.ipsw": base["old.ipsw"],
			"new.ipsw": newListing,
		})
		got := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw").InputHash()
		if got == identical {
			t.Fatalf("%s: InputHash did not change when the zip listing changed (DMG digests constant)", name)
		}
	}
}

// TestFilesInputHashZipListingOrderIndependent asserts the central-directory
// sort makes the digest independent of enumeration order.
func TestFilesInputHashZipListingOrderIndependent(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "fs.dmg", digest: []byte{0x02}},
	})

	forward := []zipMember{
		{name: "a.plist", crc: 0x1, size: 1},
		{name: "b.plist", crc: 0x2, size: 2},
	}
	reversed := []zipMember{
		{name: "b.plist", crc: 0x2, size: 2},
		{name: "a.plist", crc: 0x1, size: 1},
	}
	stubZipListings(t, map[string][]zipMember{"old.ipsw": forward, "new.ipsw": forward})
	a := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw").InputHash()
	stubZipListings(t, map[string][]zipMember{"old.ipsw": reversed, "new.ipsw": reversed})
	b := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw").InputHash()
	if a != b {
		t.Fatalf("InputHash depends on central-directory order:\n a=%s\n b=%s", a, b)
	}
}

func TestFilesCacheRoundTrip(t *testing.T) {
	stubZipListings(t, map[string][]zipMember{
		"old.ipsw": {{name: "x", crc: 1, size: 1}},
		"new.ipsw": {{name: "x", crc: 2, size: 1}},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw")
	src.d.Files = &FileDiff{
		New: map[string][]string{
			"IPSW":       {"loose-new.txt"},
			"filesystem": {"/System/added"},
		},
		Removed: map[string][]string{
			"SystemOS": {"/System/removed"},
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

	dst := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw")
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	assertFileSeen(t, dst.d.Files.New, "IPSW", "loose-new.txt")
	assertFileSeen(t, dst.d.Files.New, "filesystem", "/System/added")
	assertFileSeen(t, dst.d.Files.Removed, "SystemOS", "/System/removed")
}

// TestFilesHydrateIgnoresSetupBuckets asserts the hydrate branch publishes the
// cached FileDiff and discards the partial Setup state. Setup runs even on a
// cache hit (it precedes the hydration decision), so j.prev/j.next["IPSW"] may
// hold a zip scan; that must NOT leak into the published result.
func TestFilesHydrateIgnoresSetupBuckets(t *testing.T) {
	j := newFilesJobWithInfo(nil, nil, "", "")
	// Simulate Setup having scanned the zip into the IPSW pseudo-bucket.
	j.prev["IPSW"] = []string{"setup-old.txt"}
	j.next["IPSW"] = []string{"setup-old.txt", "setup-leaked.txt"}

	j.hydrated = &FileDiff{
		New:     map[string][]string{"filesystem": {"/System/cached-new"}},
		Removed: map[string][]string{},
	}
	if err := j.Finalize(); err != nil {
		t.Fatalf("Finalize on hydrate path: %v", err)
	}
	if j.d.Files != j.hydrated {
		t.Fatal("Finalize did not publish the hydrated FileDiff verbatim")
	}
	if len(j.d.Files.New["IPSW"]) != 0 {
		t.Fatalf("Setup-populated IPSW bucket leaked into the hydrated result: %v", j.d.Files.New["IPSW"])
	}
	assertFileSeen(t, j.d.Files.New, "filesystem", "/System/cached-new")
}

// TestFilesEmptyResultHydratesNonNil asserts the empty-result contract: an
// all-empty fresh run persists zero rows, and a later zero-row hydrate yields a
// non-nil *FileDiff with empty maps so Finalize publishes via the hydrate
// branch.
func TestFilesEmptyResultHydratesNonNil(t *testing.T) {
	stubZipListings(t, map[string][]zipMember{
		"old.ipsw": {{name: "x", crc: 1, size: 1}},
		"new.ipsw": {{name: "x", crc: 1, size: 1}},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw")
	src.d.Files = &FileDiff{New: map[string][]string{}, Removed: map[string][]string{}} // all-empty

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newFilesJobWithInfo(oldInfo, newInfo, "old.ipsw", "new.ipsw")
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate of zero rows left j.hydrated nil; Finalize would re-fold instead of publishing")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize on empty hydrate path: %v", err)
	}
	if dst.d.Files == nil {
		t.Fatal("Finalize published nil Files on the hydrate branch")
	}
	if fileDiffHasContent(dst.d.Files) {
		t.Fatalf("Finalize published content on the empty hydrate branch: %+v", dst.d.Files)
	}
}
