package diff

import (
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/signature"
)

// newMachosJobWithConf builds a machosJob whose render config is conf and whose
// old/new Info are inserted for InputHash resolution. It does not run Setup so
// no temp cacheDir is created.
func newMachosJobWithConf(conf *mcmd.DiffConfig, oldInfo, newInfo *info.Info) *machosJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	j := newMachosJob(d)
	j.conf = conf
	return j
}

func baseMachoConf() *mcmd.DiffConfig {
	return &mcmd.DiffConfig{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	}
}

func TestMachosOptionsHashStableForEqualConfig(t *testing.T) {
	a := newMachosJobWithConf(baseMachoConf(), nil, nil)
	b := newMachosJobWithConf(baseMachoConf(), nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestMachosOptionsHashAllowBlockListOrderIndependent(t *testing.T) {
	c1 := baseMachoConf()
	c1.AllowList = []string{"/a", "/b", "/c"}
	c1.BlockList = []string{"/x", "/y"}
	c2 := baseMachoConf()
	c2.AllowList = []string{"/c", "/a", "/b"}
	c2.BlockList = []string{"/y", "/x"}

	a := newMachosJobWithConf(c1, nil, nil)
	b := newMachosJobWithConf(c2, nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash should be order-independent for allow/block lists:\n a=%s\n b=%s",
			a.OptionsHash(), b.OptionsHash())
	}
}

func TestMachosOptionsHashChangesPerField(t *testing.T) {
	base := newMachosJobWithConf(baseMachoConf(), nil, nil).OptionsHash()

	mutations := map[string]func(*mcmd.DiffConfig){
		"AllowList":  func(c *mcmd.DiffConfig) { c.AllowList = []string{"/usr/bin/foo"} },
		"BlockList":  func(c *mcmd.DiffConfig) { c.BlockList = []string{"/usr/bin/bar"} },
		"Markdown":   func(c *mcmd.DiffConfig) { c.Markdown = !c.Markdown },
		"Color":      func(c *mcmd.DiffConfig) { c.Color = !c.Color },
		"DiffTool":   func(c *mcmd.DiffConfig) { c.DiffTool = "delta" },
		"CStrings":   func(c *mcmd.DiffConfig) { c.CStrings = !c.CStrings },
		"FuncStarts": func(c *mcmd.DiffConfig) { c.FuncStarts = !c.FuncStarts },
		"PemDB":      func(c *mcmd.DiffConfig) { c.PemDB = "/tmp/pem.db" },
		"Verbose":    func(c *mcmd.DiffConfig) { c.Verbose = !c.Verbose },
	}

	for field, mutate := range mutations {
		conf := baseMachoConf()
		mutate(conf)
		got := newMachosJobWithConf(conf, nil, nil).OptionsHash()
		if got == base {
			t.Errorf("OptionsHash did not change when %s changed", field)
		}
	}
}

func TestMachosOptionsHashChangesWithSymMap(t *testing.T) {
	base := newMachosJobWithConf(baseMachoConf(), nil, nil).OptionsHash()
	conf := baseMachoConf()
	conf.SymMap = map[string]signature.SymbolMap{
		"libfoo.dylib": {0x1000: "_foo", 0x2000: "_bar"},
	}
	withMap := newMachosJobWithConf(conf, nil, nil).OptionsHash()
	if withMap == base {
		t.Fatal("OptionsHash did not change when SymMap was populated")
	}
}

func TestMachosInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	a := newMachosJobWithConf(baseMachoConf(), oldInfo, newInfo).InputHash()
	b := newMachosJobWithConf(baseMachoConf(), oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	// Changing a volume DMG digest must change the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	c := newMachosJobWithConf(baseMachoConf(), oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a volume DMG digest changed")
	}
}

func TestMachosInputHashDistinguishesPresence(t *testing.T) {
	// fs present on both sides.
	bothFS := newMachosJobWithConf(baseMachoConf(),
		testIPSWInfo(map[string]testManifestEntry{"OS": {path: "old-fs.dmg", digest: []byte{0x01}}}),
		testIPSWInfo(map[string]testManifestEntry{"OS": {path: "new-fs.dmg", digest: []byte{0x02}}}),
	).InputHash()

	// fs present only on the old side; the new side resolves no digest. The
	// absent marker must produce a different hash than the both-present case.
	oldOnly := newMachosJobWithConf(baseMachoConf(),
		testIPSWInfo(map[string]testManifestEntry{"OS": {path: "old-fs.dmg", digest: []byte{0x01}}}),
		&info.Info{},
	).InputHash()

	if bothFS == oldOnly {
		t.Fatal("InputHash did not distinguish a missing new-side volume from a present one")
	}
}

func TestMachosCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newMachosJobWithConf(baseMachoConf(), oldInfo, newInfo)
	src.d.Machos = map[string]*mcmd.MachoDiff{
		volumeLabel("fs"): {
			New:     []string{"/usr/bin/new"},
			Removed: []string{"/usr/bin/gone"},
			Updated: map[string]string{"/usr/bin/changed": "```diff\n+x\n```"},
		},
		volumeLabel("sys"): {
			New: []string{"/System/Library/Frameworks/New.framework/New"},
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

	dst := newMachosJobWithConf(baseMachoConf(), oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}

	// Finalize on the hydrate path publishes the hydrated map without touching
	// the (empty) temp cacheDir.
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if len(dst.d.Machos) != len(src.d.Machos) {
		t.Fatalf("round-trip volume count = %d, want %d", len(dst.d.Machos), len(src.d.Machos))
	}
	for label, want := range src.d.Machos {
		got, ok := dst.d.Machos[label]
		if !ok {
			t.Fatalf("round-trip missing volume %q", label)
		}
		if !machoDiffEqual(got, want) {
			t.Errorf("round-trip mismatch for %q:\n got=%+v\n want=%+v", label, got, want)
		}
	}
}

func TestMachosHydratePathSkipsCacheDir(t *testing.T) {
	// A hydrated job must not require a temp cacheDir: the orchestrator excludes
	// it from the volume walk, so Setup's cacheDir stays empty and Finalize must
	// not depend on it.
	j := newMachosJobWithConf(baseMachoConf(), nil, nil)
	j.hydrated = map[string]*mcmd.MachoDiff{
		volumeLabel("fs"): {New: []string{"/usr/bin/new"}},
	}
	if j.cacheDir != "" {
		t.Fatalf("expected empty cacheDir on a job that never ran Setup, got %q", j.cacheDir)
	}
	if err := j.Finalize(); err != nil {
		t.Fatalf("Finalize on hydrate path: %v", err)
	}
	if len(j.d.Machos) != 1 {
		t.Fatalf("hydrate Finalize published %d volumes, want 1", len(j.d.Machos))
	}
}

func machoDiffEqual(a, b *mcmd.MachoDiff) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.New) != len(b.New) || len(a.Removed) != len(b.Removed) || len(a.Updated) != len(b.Updated) {
		return false
	}
	for i := range a.New {
		if a.New[i] != b.New[i] {
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
