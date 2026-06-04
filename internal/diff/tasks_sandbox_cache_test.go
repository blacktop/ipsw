package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newSandboxTaskWith builds a sandboxTask whose old/new Info are inserted for
// InputHash resolution.
func newSandboxTaskWith(oldInfo, newInfo *info.Info) *sandboxTask {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newSandboxTask(d)
}

func TestSandboxOptionsHashStable(t *testing.T) {
	a := newSandboxTaskWith(nil, nil)
	b := newSandboxTaskWith(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

// TestSandboxOptionsHashDistinctFromIBoot asserts the no-option top-level tasks
// do not collide on a shared constant tag; each folds its own task label.
func TestSandboxOptionsHashDistinctFromIBoot(t *testing.T) {
	sandbox := newSandboxTaskWith(nil, nil).OptionsHash()
	iboot := newIBootTaskWith(nil, nil).OptionsHash()
	if sandbox == iboot {
		t.Fatalf("sandbox and iboot OptionsHash collide: %s", sandbox)
	}
}

// TestSandboxOptionsHashFoldsBuildTag is the regression for the cross-binary
// build-tag staleness hole: the sandbox OptionsHash must fold sandboxBuildTag so a
// stub build (which returns ErrSandboxDiffUnavailable and can never produce
// sandbox output) and a sandbox build land on DISJOINT cache scopes. It pins the
// exact hash construction so swapping the build tag (the only thing that differs
// between the two binaries) is guaranteed to move the scope; if a future refactor
// drops the build-tag fold, the recomputed expectation no longer matches.
func TestSandboxOptionsHashFoldsBuildTag(t *testing.T) {
	got := newSandboxTaskWith(nil, nil).OptionsHash()

	h := sha256.New()
	_, _ = h.Write([]byte("sandbox-options-v"))
	_, _ = h.Write([]byte{byte(sandboxCacheVersion)})
	_, _ = h.Write([]byte(sandboxBuildTag))
	_, _ = h.Write([]byte{0})
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Fatalf("OptionsHash does not fold sandboxBuildTag as expected:\n got=%s\n want=%s", got, want)
	}

	// A hash computed WITHOUT the build-tag fold (the pre-fix construction) must
	// differ, proving the fold is load-bearing: the two builds cannot collide.
	h2 := sha256.New()
	_, _ = h2.Write([]byte("sandbox-options-v"))
	_, _ = h2.Write([]byte{byte(sandboxCacheVersion)})
	noTag := hex.EncodeToString(h2.Sum(nil))
	if got == noTag {
		t.Fatal("OptionsHash matches the no-build-tag construction; the build-tag discriminator is missing")
	}
}

// TestSandboxInputHashTracksKernelcache asserts the sandbox InputHash is keyed
// off the kernelcache manifest digest (sandbox profiles are read from the
// kernelcache), so a kernelcache change moves the hash.
func TestSandboxInputHashTracksKernelcache(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	a := newSandboxTaskWith(oldInfo, newInfo).InputHash()
	b := newSandboxTaskWith(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	// Changing the new-side kernelcache digest must change the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x03}},
	})
	c := newSandboxTaskWith(oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a kernelcache digest changed")
	}
}

// TestSandboxInputHashMatchesKexts pins the shared-source contract: sandbox and
// kexts both fingerprint the SAME kernelcache digest pair, so for the same
// inputs they must compute the same InputHash.
func TestSandboxInputHashMatchesKexts(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	sb := newSandboxTaskWith(oldInfo, newInfo).InputHash()
	kx := newKextsTaskWithConf(&Config{}, oldInfo, newInfo).InputHash()
	if sb != kx {
		t.Fatalf("sandbox and kexts InputHash diverge despite a shared kernelcache source:\n sb=%s\n kx=%s", sb, kx)
	}
}

func TestSandboxCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	src := newSandboxTaskWith(oldInfo, newInfo)
	src.d.Sandbox = "## platform\n```diff\n+ (allow file-read*)\n```\n"

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newSandboxTaskWith(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.d.Sandbox != src.d.Sandbox {
		t.Errorf("round-trip Sandbox mismatch:\n got=%q\n want=%q", dst.d.Sandbox, src.d.Sandbox)
	}
}

// TestSandboxCacheEmptyResultRoundTrip exercises the empty-result contract:
// persistTo writes zero rows for an empty sandbox diff; a later zero-row Hydrate
// leaves d.Sandbox the empty string so the hit path renders byte-identically to a
// fresh empty run.
func TestSandboxCacheEmptyResultRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})

	src := newSandboxTaskWith(oldInfo, newInfo)
	if !src.Empty() {
		t.Fatal("test setup: expected an empty Sandbox")
	}

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo (empty): %v", err)
	}

	dst := newSandboxTaskWith(oldInfo, newInfo)
	dst.d.Sandbox = "stale" // ensure Hydrate publishes the cached (empty) value
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate (empty): %v", err)
	}
	if dst.d.Sandbox != "" {
		t.Fatalf("empty Hydrate did not render empty: got=%q", dst.d.Sandbox)
	}
	if !dst.Empty() {
		t.Fatal("empty Hydrate did not render empty")
	}
}
