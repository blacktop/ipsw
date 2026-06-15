package diff

import (
	"path/filepath"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newDSCJobWithInfo builds a dscJob whose old/new Info are inserted for
// InputHash resolution. conf is left at the machoDiffConfig default unless a
// caller overrides it (the AllowList/etc. flow through d.conf).
func newDSCJobWithInfo(oldInfo, newInfo *info.Info) *dscJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newDSCJob(d)
}

func TestDSCOptionsHashStable(t *testing.T) {
	a := newDSCJobWithInfo(nil, nil)
	b := newDSCJobWithInfo(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestDSCJobIgnoresLoadCommands(t *testing.T) {
	j := newDSCJobWithInfo(nil, nil)
	if j.conf == nil {
		t.Fatal("dscJob config is nil")
	}
	if !j.conf.IgnoreLoadCommands {
		t.Fatal("dscJob should ignore load-command hashes")
	}
}

// TestDSCOptionsHashFoldsDiffConfig asserts the DSC OptionsHash tracks the same
// output-affecting DiffConfig knobs the diff actually uses (allow/block lists,
// cstrings, func-starts, verbose), all sourced from d.conf.
func TestDSCOptionsHashFoldsDiffConfig(t *testing.T) {
	base := newDSCJobWithInfo(nil, nil).OptionsHash()

	mutations := map[string]func(*Config){
		"AllowList":  func(c *Config) { c.AllowList = []string{"/usr/lib/foo.dylib"} },
		"BlockList":  func(c *Config) { c.BlockList = []string{"/usr/lib/bar.dylib"} },
		"CStrings":   func(c *Config) { c.CStrings = true },
		"FuncStarts": func(c *Config) { c.FuncStarts = true },
		"Verbose":    func(c *Config) { c.Verbose = true },
	}
	for field, mutate := range mutations {
		d := &Diff{conf: &Config{}}
		mutate(d.conf)
		got := newDSCJob(d).OptionsHash()
		if got == base {
			t.Errorf("OptionsHash did not change when %s changed", field)
		}
	}
}

// TestDSCOptionsHashAllowBlockListOrderIndependent asserts the allow/block list
// fold is order-independent, matching machosJob.
func TestDSCOptionsHashAllowBlockListOrderIndependent(t *testing.T) {
	d1 := &Diff{conf: &Config{AllowList: []string{"/a", "/b", "/c"}, BlockList: []string{"/x", "/y"}}}
	d2 := &Diff{conf: &Config{AllowList: []string{"/c", "/a", "/b"}, BlockList: []string{"/y", "/x"}}}
	if newDSCJob(d1).OptionsHash() != newDSCJob(d2).OptionsHash() {
		t.Fatal("OptionsHash should be order-independent for allow/block lists")
	}
}

// TestDSCOptionsHashDistinctFromMachos asserts the DSC task does not share a
// cache scope with machos even when the folded DiffConfig is byte-identical
// (both derive from machoDiffConfig).
func TestDSCOptionsHashDistinctFromMachos(t *testing.T) {
	d := &Diff{conf: &Config{}}
	dsc := newDSCJob(d).OptionsHash()
	machos := newMachosJob(d).OptionsHash()
	if dsc == machos {
		t.Fatalf("dsc and machos OptionsHash collide: %s", dsc)
	}
}

// TestDSCInputHashUsesSysWhenPresent asserts the InputHash hashes the SystemOS
// cryptex DMG digest when either side carries a distinct one, and that it moves
// when that digest moves.
func TestDSCInputHashUsesSysWhenPresent(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	a := newDSCJobWithInfo(oldInfo, newInfo).InputHash()
	b := newDSCJobWithInfo(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}
	if got := dscVolumeFor(newInfo); got != "sys" {
		t.Fatalf("dscVolumeFor = %q, want sys when a SystemOS cryptex is present", got)
	}

	// Changing the resolved (sys) digest must change the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x30}},
	})
	if newDSCJobWithInfo(oldInfo, newInfo2).InputHash() == a {
		t.Fatal("InputHash did not change when the resolved (sys) DMG digest changed")
	}
}

// TestDSCInputHashFallsBackToFS asserts the pre-cryptex fallback: when NEITHER
// side carries a distinct SystemOS cryptex, the InputHash hashes the filesystem
// (fs) DMG digest, and moving that digest moves the hash.
func TestDSCInputHashFallsBackToFS(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	if got := dscVolumeFor(oldInfo); got != "fs" {
		t.Fatalf("dscVolumeFor = %q, want fs when no SystemOS cryptex exists", got)
	}
	a := newDSCJobWithInfo(oldInfo, newInfo).InputHash()

	// Changing the fs digest must change the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	if newDSCJobWithInfo(oldInfo, newInfo2).InputHash() == a {
		t.Fatal("InputHash did not change when the resolved (fs) DMG digest changed on the fallback path")
	}
}

// TestDSCInputHashSysVsFSDistinct asserts the sys-resolved and fs-resolved
// hashes differ even when the same digest bytes back each volume: the resolved
// volume type itself is part of the fingerprint (volumeDMGInputHashFor folds the
// volume label), so a sys hit can never be served fs bytes or vice versa.
func TestDSCInputHashSysVsFSDistinct(t *testing.T) {
	sysInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "v.dmg", digest: []byte{0xAB}},
	})
	fsInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "v.dmg", digest: []byte{0xAB}},
	})
	sysHash := newDSCJobWithInfo(sysInfo, sysInfo).InputHash()
	fsHash := newDSCJobWithInfo(fsInfo, fsInfo).InputHash()
	if sysHash == fsHash {
		t.Fatal("sys-resolved and fs-resolved InputHash collide; the resolved volume label must be folded")
	}
}

// TestDSCCacheRoundTrip asserts persist->hydrate reproduces all three outputs.
func TestDSCCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	src := newDSCJobWithInfo(oldInfo, newInfo)
	src.d.Dylibs = &mcmd.MachoDiff{
		New:     []string{"/usr/lib/new.dylib"},
		Removed: []string{"/usr/lib/gone.dylib"},
		Updated: map[string]string{"/usr/lib/changed.dylib": "```diff\n+x\n```"},
	}
	src.d.Old.Webkit = "623.2.7.10.4"
	src.d.New.Webkit = "623.2.7.110.1"

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newDSCJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if !machoDiffEqual(dst.d.Dylibs, src.d.Dylibs) {
		t.Errorf("round-trip Dylibs mismatch:\n got=%+v\n want=%+v", dst.d.Dylibs, src.d.Dylibs)
	}
	if dst.d.Old.Webkit != src.d.Old.Webkit {
		t.Errorf("round-trip Old.Webkit = %q, want %q", dst.d.Old.Webkit, src.d.Old.Webkit)
	}
	if dst.d.New.Webkit != src.d.New.Webkit {
		t.Errorf("round-trip New.Webkit = %q, want %q", dst.d.New.Webkit, src.d.New.Webkit)
	}
}

// TestDSCDylibsPersistSplitsPerEntry asserts the dylib MachoDiff is stored as
// one "dylibs-meta" row plus one "dylib:<name>" row per Updated entry, never a
// single combined blob. The combined blob routinely exceeded SQLite's
// SQLITE_MAX_LENGTH (the iOS 26.x DSC diff sums to over a gigabyte) and failed
// the write with SQLITE_TOOBIG; the per-entry split keeps every row small.
func TestDSCDylibsPersistSplitsPerEntry(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	src := newDSCJobWithInfo(oldInfo, newInfo)
	src.d.Dylibs = &mcmd.MachoDiff{
		New:     []string{"/usr/lib/new.dylib"},
		Removed: []string{"/usr/lib/gone.dylib"},
		Updated: map[string]string{
			"/usr/lib/a.dylib": "diff-a",
			"/usr/lib/b.dylib": "diff-b",
		},
	}

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	keys := make(map[string]bool)
	if err := store.Iter(scope, func(key string, _ func(v any) error) error {
		keys[key] = true
		return nil
	}); err != nil {
		t.Fatalf("Iter: %v", err)
	}

	want := []string{
		dscRowDylibsMeta,
		dscRowDylibPrefix + "/usr/lib/a.dylib",
		dscRowDylibPrefix + "/usr/lib/b.dylib",
	}
	for _, k := range want {
		if !keys[k] {
			t.Errorf("missing expected row %q", k)
		}
	}
	if len(keys) != len(want) {
		t.Errorf("persistTo wrote %d rows, want %d (one meta + one per Updated entry): %v", len(keys), len(want), keys)
	}
}

// TestDSCDylibsSplitRoundTripSQLite exercises the split-row layout through the
// persistent SQLite store, not just MemoryStore's compatible gob behavior.
func TestDSCDylibsSplitRoundTripSQLite(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	src := newDSCJobWithInfo(oldInfo, newInfo)
	src.d.Dylibs = &mcmd.MachoDiff{
		New:     []string{"/usr/lib/new.dylib"},
		Removed: []string{"/usr/lib/gone.dylib"},
		Updated: map[string]string{
			"/usr/lib/a.dylib": "diff-a",
			"/usr/lib/b.dylib": "diff-b",
		},
	}
	src.d.Old.Webkit = "623.2.7.10.4"
	src.d.New.Webkit = "623.2.7.110.1"

	store, err := storage.NewSQLiteStore(filepath.Join(t.TempDir(), "diff.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newDSCJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !machoDiffEqual(dst.d.Dylibs, src.d.Dylibs) {
		t.Errorf("round-trip Dylibs mismatch:\n got=%+v\n want=%+v", dst.d.Dylibs, src.d.Dylibs)
	}
	if dst.d.Old.Webkit != src.d.Old.Webkit || dst.d.New.Webkit != src.d.New.Webkit {
		t.Fatalf("WebKit lost on SQLite round-trip: old=%q new=%q", dst.d.Old.Webkit, dst.d.New.Webkit)
	}
}

// TestDSCEmptyDylibsNonEmptyWebkit asserts per-output empty handling: an empty
// Dylibs writes no dylib rows, but the WebKit strings still round-trip. The
// hydrated Dylibs defaults to a non-nil empty *MachoDiff so the published
// d.Dylibs is byte-identical to a fresh empty run (buildReport keeps the key).
func TestDSCEmptyDylibsNonEmptyWebkit(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	src := newDSCJobWithInfo(oldInfo, newInfo)
	src.d.Dylibs = &mcmd.MachoDiff{Updated: make(map[string]string)} // empty (matches dcmd.Diff)
	src.d.Old.Webkit = "1.2.3"
	src.d.New.Webkit = "1.2.4"

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newDSCJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if dst.d.Dylibs == nil {
		t.Fatal("empty Dylibs hydrated to nil; buildReport would drop the 'dylibs' key (fresh run keeps it)")
	}
	if machoDiffHasContent(dst.d.Dylibs) {
		t.Fatalf("empty Dylibs hydrated with content: %+v", dst.d.Dylibs)
	}
	if dst.d.Old.Webkit != "1.2.3" || dst.d.New.Webkit != "1.2.4" {
		t.Fatalf("WebKit lost on empty-Dylibs round-trip: old=%q new=%q", dst.d.Old.Webkit, dst.d.New.Webkit)
	}
}

// TestDSCNonEmptyDylibsEmptyWebkit asserts the inverse: a non-empty Dylibs
// round-trips while empty WebKit strings write no row and hydrate back to empty.
func TestDSCNonEmptyDylibsEmptyWebkit(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	src := newDSCJobWithInfo(oldInfo, newInfo)
	src.d.Dylibs = &mcmd.MachoDiff{New: []string{"/usr/lib/new.dylib"}, Updated: make(map[string]string)}
	src.d.Old.Webkit = ""
	src.d.New.Webkit = ""

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newDSCJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !machoDiffEqual(dst.d.Dylibs, src.d.Dylibs) {
		t.Errorf("round-trip Dylibs mismatch:\n got=%+v\n want=%+v", dst.d.Dylibs, src.d.Dylibs)
	}
	if dst.d.Old.Webkit != "" || dst.d.New.Webkit != "" {
		t.Fatalf("empty WebKit hydrated non-empty: old=%q new=%q", dst.d.Old.Webkit, dst.d.New.Webkit)
	}
}

// TestDSCHydrateBranchPublishesWithoutProcessVolume asserts the hydrate branch
// publishes the three outputs without ProcessVolume ever running. The
// orchestrator excludes a hydrated dscJob from the volume walk, so Finalize is
// the only place the result is published.
func TestDSCHydrateBranchPublishesWithoutProcessVolume(t *testing.T) {
	j := newDSCJobWithInfo(nil, nil)
	j.hydrated = &dscHydrated{
		Dylibs:    &mcmd.MachoDiff{New: []string{"/usr/lib/cached.dylib"}, Updated: make(map[string]string)},
		OldWebkit: "old-wk",
		NewWebkit: "new-wk",
	}
	if err := j.Finalize(); err != nil {
		t.Fatalf("Finalize on hydrate path: %v", err)
	}
	if j.d.Dylibs != j.hydrated.Dylibs {
		t.Fatal("Finalize did not publish the hydrated Dylibs verbatim")
	}
	if j.d.Old.Webkit != "old-wk" || j.d.New.Webkit != "new-wk" {
		t.Fatalf("Finalize did not publish hydrated WebKit: old=%q new=%q", j.d.Old.Webkit, j.d.New.Webkit)
	}
}

// TestDSCInputHashMixedPairUsesPerSideVolumes covers the mixed
// pre-cryptex-vs-cryptex case: the old side's DSC input is its filesystem
// DMG, the new side's is its SystemOS cryptex, and changing EITHER side's
// resolved digest must move the hash. Under the old single-typ composition
// the absent old sys digest folded an absent marker, so an old-fs change was
// invisible to the task-scope hash.
func TestDSCInputHashMixedPairUsesPerSideVolumes(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "new-fs.dmg", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x03}},
	})

	if got := dscVolumeFor(oldInfo); got != "fs" {
		t.Fatalf("dscVolumeFor(old) = %q, want fs for the pre-cryptex side", got)
	}
	if got := dscVolumeFor(newInfo); got != "sys" {
		t.Fatalf("dscVolumeFor(new) = %q, want sys for the cryptex side", got)
	}

	base := newDSCJobWithInfo(oldInfo, newInfo).InputHash()

	// Changing the OLD side's fs digest must move the hash.
	oldInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x11}},
	})
	if newDSCJobWithInfo(oldInfo2, newInfo).InputHash() == base {
		t.Fatal("InputHash did not change when the old side's fs DMG digest changed")
	}

	// Changing the NEW side's sys digest must move the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "new-fs.dmg", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x13}},
	})
	if newDSCJobWithInfo(oldInfo, newInfo2).InputHash() == base {
		t.Fatal("InputHash did not change when the new side's sys DMG digest changed")
	}
}
