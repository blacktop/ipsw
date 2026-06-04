package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newKDKsTaskWith builds a kdksTask whose old/new Info and external KDK paths
// are inserted for InputHash resolution.
func newKDKsTaskWith(oldInfo, newInfo *info.Info, oldKDK, newKDK string) *kdksTask {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	d.Old.KDK = oldKDK
	d.New.KDK = newKDK
	return newKDKsTask(d)
}

// kdkIdentityEntry is one fake (size, mtime) identity keyed by KDK path.
type kdkIdentityEntry struct {
	size    int64
	modTime int64
	ok      bool
}

// stubKDKIdentities installs a fake kdkFileIdentity keyed by KDK path so the
// kdks InputHash can be exercised without writing real (multi-GB) KDK files. It
// restores the original on test cleanup.
func stubKDKIdentities(t *testing.T, ids map[string]kdkIdentityEntry) {
	t.Helper()
	orig := kdkFileIdentity
	t.Cleanup(func() { kdkFileIdentity = orig })
	kdkFileIdentity = func(path string) (int64, int64, bool) {
		e, ok := ids[path]
		if !ok {
			return 0, 0, false
		}
		return e.size, e.modTime, e.ok
	}
}

func TestKDKsOptionsHashStable(t *testing.T) {
	a := newKDKsTaskWith(nil, nil, "", "")
	b := newKDKsTaskWith(nil, nil, "", "")
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

// TestKDKsOptionsHashDistinctFromIBoot asserts the no-option top-level tasks do
// not collide on a shared constant tag; each folds its own task label.
func TestKDKsOptionsHashDistinctFromIBoot(t *testing.T) {
	kdks := newKDKsTaskWith(nil, nil, "", "").OptionsHash()
	iboot := newIBootTaskWith(nil, nil).OptionsHash()
	if kdks == iboot {
		t.Fatalf("kdks and iboot OptionsHash collide: %s", kdks)
	}
}

// dsym resolves a raw --kdk path to the dSYM DWARF binary path that InputHash
// stats (via kdkDwarfPath), so fake identities are keyed on the file the diff
// actually reads, not the stub.
func dsym(path string) string { return kdkDwarfPath(path) }

// TestKDKsInputHashStatsDwarfNotStub is the regression for the
// stub-vs-dSYM staleness hole: InputHash must fingerprint the dSYM DWARF binary
// dwarf.DiffStructures reads, NOT the raw --kdk stub path. A fake identity keyed
// on the stub path must be IGNORED (treated as absent), and a change to the dSYM
// identity must move the hash even when the stub identity is held constant.
func TestKDKsInputHashStatsDwarfNotStub(t *testing.T) {
	const raw = "/Library/Developer/KDKs/24A1.kdk/System/Library/Kernels/kernel.release.t6000"
	// Only the stub path has an identity; the dSYM path does not. InputHash must
	// resolve the dSYM, find no identity, and fold an absent marker — proving it
	// does NOT read the stub identity.
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		raw: {size: 16, modTime: 1000, ok: true},
	})
	stubOnly := newKDKsTaskWith(nil, nil, raw, "").InputHash()

	// Now give the dSYM path an identity. The hash MUST change, proving InputHash
	// keys off the dSYM, not the stub.
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		raw:       {size: 16, modTime: 1000, ok: true},
		dsym(raw): {size: 75, modTime: 2000, ok: true},
	})
	withDwarf := newKDKsTaskWith(nil, nil, raw, "").InputHash()
	if withDwarf == stubOnly {
		t.Fatal("InputHash did not change when the dSYM DWARF identity appeared; it is statting the stub, not the dSYM")
	}

	// A dSYM debug-info change (size moves) with the stub identity held constant
	// MUST move the hash. This is the exact staleness the audit flagged.
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		raw:       {size: 16, modTime: 1000, ok: true},
		dsym(raw): {size: 999, modTime: 2000, ok: true},
	})
	dwarfChanged := newKDKsTaskWith(nil, nil, raw, "").InputHash()
	if dwarfChanged == withDwarf {
		t.Fatal("InputHash did not change when the dSYM DWARF content changed but the stub stayed put")
	}
}

// TestKDKsInputHashTracksExternalFileIdentity is the external-input invariant:
// the InputHash is keyed off the user-passed KDK paths and each file's cheap
// (size + mtime) identity, NOT off any IPSW manifest digest.
func TestKDKsInputHashTracksExternalFileIdentity(t *testing.T) {
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
		dsym("/Library/Developer/KDKs/24B2.kdk"): {size: 200, modTime: 2000, ok: true},
	})

	a := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24B2.kdk").InputHash()
	b := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24B2.kdk").InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	// Changing the new-side KDK file size (a content change) must move the hash.
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
		dsym("/Library/Developer/KDKs/24B2.kdk"): {size: 999, modTime: 2000, ok: true},
	})
	c := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24B2.kdk").InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a KDK file size changed")
	}

	// Changing the new-side KDK file mtime (an in-place reinstall) must move the
	// hash.
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
		dsym("/Library/Developer/KDKs/24B2.kdk"): {size: 200, modTime: 9999, ok: true},
	})
	d := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24B2.kdk").InputHash()
	if d == a {
		t.Fatal("InputHash did not change when a KDK file mtime changed")
	}
}

// TestKDKsInputHashTracksPath asserts the path itself is folded: pointing at a
// different KDK version (different path) moves the hash even if the stub returns
// the same size/mtime.
func TestKDKsInputHashTracksPath(t *testing.T) {
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
		dsym("/Library/Developer/KDKs/24A2.kdk"): {size: 100, modTime: 1000, ok: true},
	})
	a := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24A1.kdk").InputHash()
	b := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24A2.kdk").InputHash()
	if a == b {
		t.Fatal("InputHash did not change when the new-side KDK path changed")
	}
}

// TestKDKsInputHashInertWhenNoKDK asserts the empty-path (no --kdk) case is
// stable/deterministic and never stats: kdkFileIdentity must NOT be called for an
// empty path.
func TestKDKsInputHashInertWhenNoKDK(t *testing.T) {
	called := false
	orig := kdkFileIdentity
	t.Cleanup(func() { kdkFileIdentity = orig })
	kdkFileIdentity = func(path string) (int64, int64, bool) {
		called = true
		return 0, 0, false
	}

	a := newKDKsTaskWith(nil, nil, "", "").InputHash()
	b := newKDKsTaskWith(nil, nil, "", "").InputHash()
	if a != b {
		t.Fatalf("InputHash not deterministic for the inert (no --kdk) case:\n a=%s\n b=%s", a, b)
	}
	if called {
		t.Fatal("kdkFileIdentity was stat'd for an empty KDK path; the inert case must not touch the filesystem")
	}

	// A present KDK on one side must differ from the inert (both-empty) case.
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
	})
	withKDK := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/24A1.kdk", "").InputHash()
	if withKDK == a {
		t.Fatal("InputHash did not distinguish a present KDK from the inert no-KDK case")
	}
}

// TestKDKsInputHashUnresolvableFile asserts an unresolvable KDK file folds the
// same absent marker as the empty-path case for that side, so it stays stable.
func TestKDKsInputHashUnresolvableFile(t *testing.T) {
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		// "missing" path is intentionally absent from the map -> ok=false.
	})
	a := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/missing.kdk", "").InputHash()
	b := newKDKsTaskWith(nil, nil, "/Library/Developer/KDKs/missing.kdk", "").InputHash()
	if a != b {
		t.Fatalf("InputHash not deterministic for an unresolvable KDK file:\n a=%s\n b=%s", a, b)
	}
}

func TestKDKsCacheRoundTrip(t *testing.T) {
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
		dsym("/Library/Developer/KDKs/24B2.kdk"): {size: 200, modTime: 2000, ok: true},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	src := newKDKsTaskWith(oldInfo, newInfo, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24B2.kdk")
	src.d.KDKs = "## KDK struct diff\n```diff\n+ struct foo { int x; };\n```\n"

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newKDKsTaskWith(oldInfo, newInfo, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24B2.kdk")
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.d.KDKs != src.d.KDKs {
		t.Errorf("round-trip KDKs mismatch:\n got=%q\n want=%q", dst.d.KDKs, src.d.KDKs)
	}
}

// TestKDKsCacheEmptyResultRoundTrip exercises the empty-result contract:
// persistTo writes zero rows for an empty KDK diff; a later zero-row Hydrate
// leaves d.KDKs the empty string so the hit path renders byte-identically to a
// fresh empty run.
func TestKDKsCacheEmptyResultRoundTrip(t *testing.T) {
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym("/Library/Developer/KDKs/24A1.kdk"): {size: 100, modTime: 1000, ok: true},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})

	src := newKDKsTaskWith(oldInfo, newInfo, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24A1.kdk")
	if !src.Empty() {
		t.Fatal("test setup: expected an empty KDKs")
	}

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo (empty): %v", err)
	}

	dst := newKDKsTaskWith(oldInfo, newInfo, "/Library/Developer/KDKs/24A1.kdk", "/Library/Developer/KDKs/24A1.kdk")
	dst.d.KDKs = "stale" // ensure Hydrate publishes the cached (empty) value
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate (empty): %v", err)
	}
	if dst.d.KDKs != "" {
		t.Fatalf("empty Hydrate did not render empty: got=%q", dst.d.KDKs)
	}
	if !dst.Empty() {
		t.Fatal("empty Hydrate did not render empty")
	}
}

// TestKDKDisplayPathNormalization pins the display form parseKDKs publishes
// and that kdkDisplayPath is idempotent (safe on raw CLI paths and on
// already-normalized values, which a double-Hydrate or test rerun can hit).
func TestKDKDisplayPathNormalization(t *testing.T) {
	raw := "/Library/Developer/KDKs/KDK_26.0_25A5279m.kdk/System/Library/Kernels/kernel.release.t6000"
	want := "KDK_26.0_25A5279m.kdk/System/Library/Kernels/kernel.release.t6000"
	if got := kdkDisplayPath(raw); got != want {
		t.Fatalf("kdkDisplayPath(raw) = %q, want %q", got, want)
	}
	if got := kdkDisplayPath(want); got != want {
		t.Fatalf("kdkDisplayPath not idempotent: %q -> %q", want, got)
	}
	if got := kdkDisplayPath(""); got != "" {
		t.Fatalf("kdkDisplayPath(\"\") = %q, want empty", got)
	}
}

// TestKDKsHydrateNormalizesDisplayPaths is the regression for the warm-run
// KDK.md divergence: a cache hit skips parseKDKs (which normalizes
// d.Old.KDK/d.New.KDK as a side effect), so Hydrate must apply the same
// normalization or the cached run embeds raw CLI paths in KDK.md.
func TestKDKsHydrateNormalizesDisplayPaths(t *testing.T) {
	src := &Diff{conf: &Config{}}
	src.Old.KDK = "/Library/Developer/KDKs/KDK_26.0_25A5279m.kdk/System/Library/Kernels/kernel.release.t6000"
	src.New.KDK = "/Library/Developer/KDKs/KDK_26.0_25A5295e.kdk/System/Library/Kernels/kernel.release.t6000"
	src.KDKs = "```diff\n-old\n+new\n```"

	store := storage.NewMemoryStore()
	scope := storage.Scope{IpswOld: "o", IpswNew: "n", Task: "kdks", TaskVersion: kdksCacheVersion}
	if err := newKDKsTask(src).persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := &Diff{conf: &Config{}}
	dst.Old.KDK = src.Old.KDK // raw CLI paths, as a warm run sees them
	dst.New.KDK = src.New.KDK
	if err := newKDKsTask(dst).Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.KDKs != src.KDKs {
		t.Fatalf("hydrated KDKs = %q, want %q", dst.KDKs, src.KDKs)
	}
	if want := "KDK_26.0_25A5279m.kdk/System/Library/Kernels/kernel.release.t6000"; dst.Old.KDK != want {
		t.Fatalf("hydrated Old.KDK = %q, want normalized %q", dst.Old.KDK, want)
	}
	if want := "KDK_26.0_25A5295e.kdk/System/Library/Kernels/kernel.release.t6000"; dst.New.KDK != want {
		t.Fatalf("hydrated New.KDK = %q, want normalized %q", dst.New.KDK, want)
	}
}
