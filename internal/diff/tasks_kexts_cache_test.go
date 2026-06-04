package diff

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

// newKextsTaskWithConf builds a kextsTask whose render config is conf and whose
// old/new Info are inserted for InputHash resolution.
func newKextsTaskWithConf(conf *Config, oldInfo, newInfo *info.Info) *kextsTask {
	d := &Diff{conf: conf}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newKextsTask(d)
}

func TestKextsOptionsHashStableForEqualConfig(t *testing.T) {
	a := newKextsTaskWithConf(&Config{}, nil, nil)
	b := newKextsTaskWithConf(&Config{}, nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestKextsOptionsHashAllowBlockListOrderIndependent(t *testing.T) {
	c1 := &Config{AllowList: []string{"/a", "/b", "/c"}, BlockList: []string{"/x", "/y"}}
	c2 := &Config{AllowList: []string{"/c", "/a", "/b"}, BlockList: []string{"/y", "/x"}}
	a := newKextsTaskWithConf(c1, nil, nil)
	b := newKextsTaskWithConf(c2, nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash should be order-independent for allow/block lists:\n a=%s\n b=%s",
			a.OptionsHash(), b.OptionsHash())
	}
}

func TestKextsOptionsHashChangesPerField(t *testing.T) {
	base := newKextsTaskWithConf(&Config{}, nil, nil).OptionsHash()

	mutations := map[string]func(*Config){
		"AllowList":  func(c *Config) { c.AllowList = []string{"/usr/bin/foo"} },
		"BlockList":  func(c *Config) { c.BlockList = []string{"/usr/bin/bar"} },
		"CStrings":   func(c *Config) { c.CStrings = true },
		"FuncStarts": func(c *Config) { c.FuncStarts = true },
		"Verbose":    func(c *Config) { c.Verbose = true },
		"Signatures": func(c *Config) { c.Signatures = "/tmp/sigs" },
	}

	for field, mutate := range mutations {
		conf := &Config{}
		mutate(conf)
		got := newKextsTaskWithConf(conf, nil, nil).OptionsHash()
		if got == base {
			t.Errorf("OptionsHash did not change when %s changed", field)
		}
	}
}

func TestKextsInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	a := newKextsTaskWithConf(&Config{}, oldInfo, newInfo).InputHash()
	b := newKextsTaskWithConf(&Config{}, oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	// Changing the new-side kernelcache digest must change the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x03}},
	})
	c := newKextsTaskWithConf(&Config{}, oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a kernelcache digest changed")
	}
}

func TestKextsInputHashDistinguishesPresence(t *testing.T) {
	both := newKextsTaskWithConf(&Config{},
		testIPSWInfo(map[string]testManifestEntry{"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}}}),
		testIPSWInfo(map[string]testManifestEntry{"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}}}),
	).InputHash()

	// New side has no BuildManifest: the absent marker must differ from a
	// present digest.
	oldOnly := newKextsTaskWithConf(&Config{},
		testIPSWInfo(map[string]testManifestEntry{"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}}}),
		&info.Info{},
	).InputHash()

	if both == oldOnly {
		t.Fatal("InputHash did not distinguish a missing new-side kernelcache from a present one")
	}
}

func TestKextsCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	src := newKextsTaskWithConf(&Config{}, oldInfo, newInfo)
	src.d.Kexts = &mcmd.MachoDiff{
		New:     []string{"/System/Library/Extensions/New.kext"},
		Removed: []string{"/System/Library/Extensions/Gone.kext"},
		Updated: map[string]string{"/System/Library/Extensions/Changed.kext": "```diff\n+x\n```"},
	}
	oldVer := &kernelcache.Version{}
	oldVer.KernelVersion.Darwin = "24.0.0"
	oldVer.KernelVersion.XNU = "11215.0.0"
	oldVer.KernelVersion.Date = time.Date(2025, 5, 1, 0, 0, 0, 0, time.FixedZone("PDT", -7*60*60))
	newVer := &kernelcache.Version{}
	newVer.KernelVersion.Darwin = "24.1.0"
	newVer.KernelVersion.XNU = "11216.0.0"
	newVer.KernelVersion.Date = time.Date(2025, 6, 1, 0, 0, 0, 0, time.FixedZone("PDT", -7*60*60))
	src.d.Old.Kernel.Version = oldVer
	src.d.New.Kernel.Version = newVer
	src.d.sameKernel = true

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newKextsTaskWithConf(&Config{}, oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}

	if !machoDiffEqual(dst.d.Kexts, src.d.Kexts) {
		t.Errorf("round-trip Kexts mismatch:\n got=%+v\n want=%+v", dst.d.Kexts, src.d.Kexts)
	}
	if dst.d.Old.Kernel.Version == nil || dst.d.New.Kernel.Version == nil {
		t.Fatal("round-trip dropped a Kernel version")
	}
	if dst.d.Old.Kernel.Version.KernelVersion.Darwin != "24.0.0" ||
		dst.d.New.Kernel.Version.KernelVersion.XNU != "11216.0.0" {
		t.Errorf("round-trip Kernel version mismatch:\n old=%+v\n new=%+v",
			dst.d.Old.Kernel.Version.KernelVersion, dst.d.New.Kernel.Version.KernelVersion)
	}
	if !dst.d.New.Kernel.Version.KernelVersion.Date.Equal(newVer.KernelVersion.Date) {
		t.Errorf("round-trip Kernel date mismatch: got=%v want=%v",
			dst.d.New.Kernel.Version.KernelVersion.Date, newVer.KernelVersion.Date)
	}
	if zone, _ := dst.d.New.Kernel.Version.KernelVersion.Date.Zone(); zone != "PDT" {
		t.Fatalf("round-trip Kernel date zone = %q, want PDT", zone)
	}
	if !dst.d.sameKernel {
		t.Fatal("round-trip sameKernel = false, want true")
	}
}

// TestKextsCacheEmptyResultRoundTrip exercises the sameKernel short-circuit
// shape: no kext diff and no Kernel version fields. persistTo writes zero rows;
// a later zero-row Hydrate yields a non-nil empty payload and publishes nil
// d.Kexts / nil Kernel.Version, matching a fresh short-circuited run.
func TestKextsCacheEmptyResultRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})

	src := newKextsTaskWithConf(&Config{}, oldInfo, newInfo)
	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo (empty): %v", err)
	}

	dst := newKextsTaskWithConf(&Config{}, oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate (empty): %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left t.hydrated nil on an empty result")
	}
	if dst.d.Kexts != nil {
		t.Fatalf("empty Hydrate published non-nil Kexts: %+v", dst.d.Kexts)
	}
	if dst.d.Old.Kernel.Version != nil || dst.d.New.Kernel.Version != nil {
		t.Fatal("empty Hydrate published a Kernel version")
	}
	if !dst.Empty() {
		t.Fatal("empty Hydrate did not render empty")
	}
}

// TestKextsCacheVersionOnlyRoundTrip covers the functional-segments
// short-circuit: parseKernelcache returns no kext diff but DOES set both Kernel
// versions, which the `## Kernel` table renders. persistTo must write the row
// (versions are content-bearing) so a hit restores the version table.
func TestKextsCacheVersionOnlyRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	src := newKextsTaskWithConf(&Config{}, oldInfo, newInfo)
	oldVer := &kernelcache.Version{}
	oldVer.KernelVersion.Darwin = "24.0.0"
	newVer := &kernelcache.Version{}
	newVer.KernelVersion.Darwin = "24.0.0"
	src.d.Old.Kernel.Version = oldVer
	src.d.New.Kernel.Version = newVer

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo (version-only): %v", err)
	}

	dst := newKextsTaskWithConf(&Config{}, oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate (version-only): %v", err)
	}
	if dst.d.Old.Kernel.Version == nil || dst.d.New.Kernel.Version == nil {
		t.Fatal("version-only Hydrate dropped a Kernel version (the ## Kernel table would render empty)")
	}
	if dst.d.Kexts != nil {
		t.Fatalf("version-only Hydrate published non-nil Kexts: %+v", dst.d.Kexts)
	}
}

// stubSignaturesIdentity swaps the signatures-directory identity seam for the
// test's lifetime, mirroring the kdkFileIdentity stub pattern.
func stubSignaturesIdentity(t *testing.T, fn func(dir string) ([]byte, bool)) {
	t.Helper()
	orig := signaturesDirIdentity
	signaturesDirIdentity = fn
	t.Cleanup(func() { signaturesDirIdentity = orig })
}

// TestKextsOptionsHashFoldsSignaturesContent is the regression for the
// stale-symbolication hole: regenerating the signature files in place (same
// --signatures path, different content identity) must move the OptionsHash so
// a rerun re-parses instead of hydrating the old symbolicated kext diff.
func TestKextsOptionsHashFoldsSignaturesContent(t *testing.T) {
	d := &Diff{conf: &Config{Signatures: "/sigs/kernel"}}
	task := newKextsTask(d)

	stubSignaturesIdentity(t, func(dir string) ([]byte, bool) {
		return []byte{0xAA}, true
	})
	base := task.OptionsHash()
	if again := task.OptionsHash(); again != base {
		t.Fatalf("OptionsHash unstable for identical signature identity: %s vs %s", base, again)
	}

	// Same path, regenerated contents -> identity changes -> hash moves.
	stubSignaturesIdentity(t, func(dir string) ([]byte, bool) {
		return []byte{0xBB}, true
	})
	if task.OptionsHash() == base {
		t.Fatal("OptionsHash did not change when the signatures dir content identity changed")
	}

	// No signatures dir at all -> absent marker, distinct from any present identity.
	stubSignaturesIdentity(t, func(dir string) ([]byte, bool) {
		return nil, false
	})
	if task.OptionsHash() == base {
		t.Fatal("OptionsHash for absent signatures collided with a present identity")
	}
}

// TestSignaturesDirIdentityRealWalk exercises the real (un-stubbed) identity
// against a temp tree: stable across calls, sensitive to added files and
// content-size changes, absent for empty paths and empty trees.
func TestSignaturesDirIdentityRealWalk(t *testing.T) {
	dir := t.TempDir()
	if _, ok := signaturesDirIdentity(""); ok {
		t.Fatal("empty path should have no identity")
	}
	if _, ok := signaturesDirIdentity(dir); ok {
		t.Fatal("empty tree should have no identity")
	}

	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"sig":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	id1, ok := signaturesDirIdentity(dir)
	if !ok {
		t.Fatal("expected identity for non-empty tree")
	}
	id1b, _ := signaturesDirIdentity(dir)
	if string(id1) != string(id1b) {
		t.Fatal("identity unstable across calls on an unchanged tree")
	}

	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"sig":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	id2, _ := signaturesDirIdentity(dir)
	if string(id1) == string(id2) {
		t.Fatal("identity did not change when a signature file was added")
	}
}
