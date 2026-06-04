package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newEntsJobWithInfo builds an entsJob whose old/new Info are inserted for
// InputHash resolution.
func newEntsJobWithInfo(oldInfo, newInfo *info.Info) *entsJob {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newEntitlementsJob(d)
}

func TestEntsOptionsHashStable(t *testing.T) {
	a := newEntsJobWithInfo(nil, nil)
	b := newEntsJobWithInfo(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for a job with no options:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestEntsInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	a := newEntsJobWithInfo(oldInfo, newInfo).InputHash()
	b := newEntsJobWithInfo(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})
	c := newEntsJobWithInfo(oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when a volume DMG digest changed")
	}
}

// TestEntsInputHashMatchesMachos asserts the shared volume-DMG-digest helper
// produces an identical fingerprint for both jobs reading the same volumes.
func TestEntsInputHashMatchesMachos(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	ents := newEntsJobWithInfo(oldInfo, newInfo).InputHash()
	machos := newMachosJobWithConf(baseMachoConf(), oldInfo, newInfo).InputHash()
	if ents != machos {
		t.Fatalf("ents and machos InputHash differ for identical volumes:\n ents=%s\n machos=%s", ents, machos)
	}
}

func TestEntsCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newEntsJobWithInfo(oldInfo, newInfo)
	src.d.Ents = map[string]string{
		volumeLabel("fs"):  "```diff\n+com.apple.example\n```",
		volumeLabel("sys"): "```diff\n-com.apple.removed\n```",
	}

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newEntsJobWithInfo(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil {
		t.Fatal("Hydrate left j.hydrated nil")
	}
	if err := dst.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if len(dst.d.Ents) != len(src.d.Ents) {
		t.Fatalf("round-trip volume count = %d, want %d", len(dst.d.Ents), len(src.d.Ents))
	}
	for label, want := range src.d.Ents {
		if got := dst.d.Ents[label]; got != want {
			t.Errorf("round-trip mismatch for %q:\n got=%q\n want=%q", label, got, want)
		}
	}
}

// TestEntsHydratePathSkipsVolumeFold asserts a hydrated job publishes its cached
// result in Finalize without folding the (empty) per-side buckets.
func TestEntsHydratePathSkipsVolumeFold(t *testing.T) {
	j := newEntsJobWithInfo(nil, nil)
	j.hydrated = map[string]string{
		volumeLabel("fs"): "```diff\n+com.apple.example\n```",
	}
	if err := j.Finalize(); err != nil {
		t.Fatalf("Finalize on hydrate path: %v", err)
	}
	if len(j.d.Ents) != 1 {
		t.Fatalf("hydrate Finalize published %d volumes, want 1", len(j.d.Ents))
	}
}
