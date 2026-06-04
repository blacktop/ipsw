package diff

import (
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newIBootTaskWith builds an ibootTask whose old/new Info are inserted for
// InputHash resolution.
func newIBootTaskWith(oldInfo, newInfo *info.Info) *ibootTask {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	return newIBootTask(d)
}

func TestIBootOptionsHashStable(t *testing.T) {
	a := newIBootTaskWith(nil, nil)
	b := newIBootTaskWith(nil, nil)
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestIBootInputHashStableAndDigestSensitive(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.d93.RELEASE.im4p", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.d93.RELEASE.im4p", digest: []byte{0x02}},
	})

	a := newIBootTaskWith(oldInfo, newInfo).InputHash()
	b := newIBootTaskWith(oldInfo, newInfo).InputHash()
	if a != b {
		t.Fatalf("InputHash differs for identical inputs:\n a=%s\n b=%s", a, b)
	}

	// Changing the new-side iBoot digest must change the hash.
	newInfo2 := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.d93.RELEASE.im4p", digest: []byte{0x03}},
	})
	c := newIBootTaskWith(oldInfo, newInfo2).InputHash()
	if c == a {
		t.Fatal("InputHash did not change when an iBoot digest changed")
	}
}

func TestIBootInputHashDistinguishesPresence(t *testing.T) {
	both := newIBootTaskWith(
		testIPSWInfo(map[string]testManifestEntry{"iBoot": {path: "iBoot.im4p", digest: []byte{0x01}}}),
		testIPSWInfo(map[string]testManifestEntry{"iBoot": {path: "iBoot.im4p", digest: []byte{0x02}}}),
	).InputHash()

	// New side has no iBoot manifest entry: the absent marker must differ from
	// a present digest.
	oldOnly := newIBootTaskWith(
		testIPSWInfo(map[string]testManifestEntry{"iBoot": {path: "iBoot.im4p", digest: []byte{0x01}}}),
		&info.Info{},
	).InputHash()

	if both == oldOnly {
		t.Fatal("InputHash did not distinguish a missing new-side iBoot from a present one")
	}
}

func TestIBootCacheRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.im4p", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.im4p", digest: []byte{0x02}},
	})

	src := newIBootTaskWith(oldInfo, newInfo)
	src.d.IBoot = &IBootDiff{
		Versions: []string{"iBoot-11000.0.0", "iBoot-11001.0.0"},
		New:      map[string][]string{"iBoot": {"a new long string value"}},
		Removed:  map[string][]string{"iBoot": {"a removed long string value"}},
	}

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newIBootTaskWith(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.d.IBoot == nil {
		t.Fatal("Hydrate left d.IBoot nil")
	}
	if len(dst.d.IBoot.Versions) != 2 ||
		dst.d.IBoot.Versions[0] != "iBoot-11000.0.0" ||
		dst.d.IBoot.Versions[1] != "iBoot-11001.0.0" {
		t.Errorf("round-trip Versions mismatch: got=%v", dst.d.IBoot.Versions)
	}
	if got := dst.d.IBoot.New["iBoot"]; len(got) != 1 || got[0] != "a new long string value" {
		t.Errorf("round-trip New mismatch: got=%v", dst.d.IBoot.New)
	}
	if got := dst.d.IBoot.Removed["iBoot"]; len(got) != 1 || got[0] != "a removed long string value" {
		t.Errorf("round-trip Removed mismatch: got=%v", dst.d.IBoot.Removed)
	}
}

// TestIBootCacheEmptyResultRoundTrip exercises the empty-result contract:
// persistTo writes zero rows for an empty IBootDiff; a later zero-row Hydrate
// yields a non-nil empty IBootDiff so the hit path renders byte-identically to
// a fresh empty run.
func TestIBootCacheEmptyResultRoundTrip(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.im4p", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"iBoot": {path: "iBoot.im4p", digest: []byte{0x01}},
	})

	src := newIBootTaskWith(oldInfo, newInfo)
	src.d.IBoot = &IBootDiff{
		New:     make(map[string][]string),
		Removed: make(map[string][]string),
	}
	if !src.Empty() {
		t.Fatal("test setup: expected an empty IBootDiff")
	}

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo (empty): %v", err)
	}

	dst := newIBootTaskWith(oldInfo, newInfo)
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate (empty): %v", err)
	}
	if dst.hydrated == nil || dst.d.IBoot == nil {
		t.Fatal("empty Hydrate left a nil IBootDiff (the hit branch would not be taken)")
	}
	if !dst.Empty() {
		t.Fatalf("empty Hydrate did not render empty: %+v", dst.d.IBoot)
	}
}
