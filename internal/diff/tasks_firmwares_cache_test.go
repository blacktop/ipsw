package diff

import (
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// newFirmwaresTaskWith builds a firmwaresTask whose render config, old/new Info,
// and IPSW paths are inserted for OptionsHash / InputHash resolution.
func newFirmwaresTaskWith(conf *Config, oldInfo, newInfo *info.Info, oldPath, newPath string) *firmwaresTask {
	d := &Diff{conf: conf}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	d.Old.IPSWPath = oldPath
	d.New.IPSWPath = newPath
	return newFirmwaresTask(d)
}

func TestFirmwaresOptionsHashStableForEqualConfig(t *testing.T) {
	a := newFirmwaresTaskWith(&Config{}, nil, nil, "", "")
	b := newFirmwaresTaskWith(&Config{}, nil, nil, "", "")
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash differs for equal config:\n a=%s\n b=%s", a.OptionsHash(), b.OptionsHash())
	}
}

func TestFirmwaresOptionsHashAllowBlockListOrderIndependent(t *testing.T) {
	c1 := &Config{AllowList: []string{"/a", "/b", "/c"}, BlockList: []string{"/x", "/y"}}
	c2 := &Config{AllowList: []string{"/c", "/a", "/b"}, BlockList: []string{"/y", "/x"}}
	a := newFirmwaresTaskWith(c1, nil, nil, "", "")
	b := newFirmwaresTaskWith(c2, nil, nil, "", "")
	if a.OptionsHash() != b.OptionsHash() {
		t.Fatalf("OptionsHash should be order-independent for allow/block lists:\n a=%s\n b=%s",
			a.OptionsHash(), b.OptionsHash())
	}
}

func TestFirmwaresOptionsHashChangesPerField(t *testing.T) {
	base := newFirmwaresTaskWith(&Config{}, nil, nil, "", "").OptionsHash()

	mutations := map[string]func(*Config){
		"AllowList":  func(c *Config) { c.AllowList = []string{"/usr/bin/foo"} },
		"BlockList":  func(c *Config) { c.BlockList = []string{"/usr/bin/bar"} },
		"CStrings":   func(c *Config) { c.CStrings = true },
		"FuncStarts": func(c *Config) { c.FuncStarts = true },
		"Verbose":    func(c *Config) { c.Verbose = true },
	}

	for field, mutate := range mutations {
		conf := &Config{}
		mutate(conf)
		got := newFirmwaresTaskWith(conf, nil, nil, "", "").OptionsHash()
		if got == base {
			t.Errorf("OptionsHash did not change when %s changed", field)
		}
	}
}

// TestFirmwaresInputHashTracksFirmwareContent is the core invariant: a firmware
// ".im4p" member added/removed/changed must move the InputHash, while a non-im4p
// loose member (a DMG, a plist) must NOT — firmwares reads only ".im4p" members.
func TestFirmwaresInputHashTracksFirmwareContent(t *testing.T) {
	base := map[string][]zipMember{
		"old.ipsw": {
			{name: "Firmware/dfu/iBEC.d93.RELEASE.im4p", crc: 0xaa, size: 100},
			{name: "BuildManifest.plist", crc: 0x11, size: 50},
		},
		"new.ipsw": {
			{name: "Firmware/dfu/iBEC.d93.RELEASE.im4p", crc: 0xaa, size: 100},
			{name: "BuildManifest.plist", crc: 0x11, size: 50},
		},
	}
	stubZipListings(t, base)
	identical := newFirmwaresTaskWith(&Config{}, nil, nil, "old.ipsw", "new.ipsw").InputHash()

	// Changing a firmware .im4p member MUST move the hash.
	firmwareChanges := map[string][]zipMember{
		"im4p CRC changed": {
			{name: "Firmware/dfu/iBEC.d93.RELEASE.im4p", crc: 0xbb, size: 100},
			{name: "BuildManifest.plist", crc: 0x11, size: 50},
		},
		"im4p size changed": {
			{name: "Firmware/dfu/iBEC.d93.RELEASE.im4p", crc: 0xaa, size: 200},
			{name: "BuildManifest.plist", crc: 0x11, size: 50},
		},
		"im4p added": {
			{name: "Firmware/dfu/iBEC.d93.RELEASE.im4p", crc: 0xaa, size: 100},
			{name: "Firmware/agx/armfw.im4p", crc: 0xcc, size: 7},
			{name: "BuildManifest.plist", crc: 0x11, size: 50},
		},
		"im4p removed": {
			{name: "BuildManifest.plist", crc: 0x11, size: 50},
		},
	}
	for name, newListing := range firmwareChanges {
		stubZipListings(t, map[string][]zipMember{"old.ipsw": base["old.ipsw"], "new.ipsw": newListing})
		got := newFirmwaresTaskWith(&Config{}, nil, nil, "old.ipsw", "new.ipsw").InputHash()
		if got == identical {
			t.Fatalf("%s: InputHash did not change when a firmware .im4p member changed", name)
		}
	}

	// Changing a NON-firmware member (no .im4p) must NOT move the hash: firmwares
	// reads only .im4p members.
	nonFirmware := []zipMember{
		{name: "Firmware/dfu/iBEC.d93.RELEASE.im4p", crc: 0xaa, size: 100},
		{name: "BuildManifest.plist", crc: 0x99, size: 999}, // changed plist
		{name: "058-loose.dmg", crc: 0x42, size: 4242},      // new non-im4p member
	}
	stubZipListings(t, map[string][]zipMember{"old.ipsw": base["old.ipsw"], "new.ipsw": nonFirmware})
	got := newFirmwaresTaskWith(&Config{}, nil, nil, "old.ipsw", "new.ipsw").InputHash()
	if got != identical {
		t.Fatal("InputHash changed when a NON-firmware member changed; firmwares should track only .im4p members")
	}
}

// TestFirmwaresInputHashOrderIndependent asserts the .im4p filter + sort makes
// the digest independent of central-directory enumeration order.
func TestFirmwaresInputHashOrderIndependent(t *testing.T) {
	forward := []zipMember{
		{name: "a.im4p", crc: 0x1, size: 1},
		{name: "b.im4p", crc: 0x2, size: 2},
	}
	reversed := []zipMember{
		{name: "b.im4p", crc: 0x2, size: 2},
		{name: "a.im4p", crc: 0x1, size: 1},
	}
	stubZipListings(t, map[string][]zipMember{"old.ipsw": forward, "new.ipsw": forward})
	a := newFirmwaresTaskWith(&Config{}, nil, nil, "old.ipsw", "new.ipsw").InputHash()
	stubZipListings(t, map[string][]zipMember{"old.ipsw": reversed, "new.ipsw": reversed})
	b := newFirmwaresTaskWith(&Config{}, nil, nil, "old.ipsw", "new.ipsw").InputHash()
	if a != b {
		t.Fatalf("InputHash depends on central-directory order:\n a=%s\n b=%s", a, b)
	}
}

func TestFirmwaresCacheRoundTrip(t *testing.T) {
	stubZipListings(t, map[string][]zipMember{
		"old.ipsw": {{name: "fw.im4p", crc: 1, size: 1}},
		"new.ipsw": {{name: "fw.im4p", crc: 2, size: 1}},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	src := newFirmwaresTaskWith(&Config{}, oldInfo, newInfo, "old.ipsw", "new.ipsw")
	src.d.Firmwares = &mcmd.MachoDiff{
		New:     []string{"agx_GFX"},
		Removed: []string{"old_fw"},
		Updated: map[string]string{"iBEC": "```diff\n+x\n```"},
	}

	store := storage.NewMemoryStore()
	scope, ok := taskScope(oldInfo, newInfo, src)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo: %v", err)
	}

	dst := newFirmwaresTaskWith(&Config{}, oldInfo, newInfo, "old.ipsw", "new.ipsw")
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if dst.hydrated == nil || dst.d.Firmwares == nil {
		t.Fatal("Hydrate left d.Firmwares nil")
	}
	if !machoDiffEqual(dst.d.Firmwares, src.d.Firmwares) {
		t.Errorf("round-trip Firmwares mismatch:\n got=%+v\n want=%+v", dst.d.Firmwares, src.d.Firmwares)
	}
}

// TestFirmwaresCacheEmptyResultRoundTrip exercises the empty-result contract:
// persistTo writes zero rows for an empty MachoDiff; a later zero-row Hydrate
// yields a non-nil empty MachoDiff so the hit path renders byte-identically to a
// fresh empty run.
func TestFirmwaresCacheEmptyResultRoundTrip(t *testing.T) {
	stubZipListings(t, map[string][]zipMember{
		"old.ipsw": {{name: "fw.im4p", crc: 1, size: 1}},
		"new.ipsw": {{name: "fw.im4p", crc: 1, size: 1}},
	})
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "fs.dmg", digest: []byte{0x01}},
	})

	src := newFirmwaresTaskWith(&Config{}, oldInfo, newInfo, "old.ipsw", "new.ipsw")
	src.d.Firmwares = &mcmd.MachoDiff{Updated: make(map[string]string)} // all-empty
	if !src.Empty() {
		t.Fatal("test setup: expected an empty Firmwares")
	}

	store := storage.NewMemoryStore()
	scope, _ := taskScope(oldInfo, newInfo, src)
	if err := src.persistTo(scope, store); err != nil {
		t.Fatalf("persistTo (empty): %v", err)
	}

	dst := newFirmwaresTaskWith(&Config{}, oldInfo, newInfo, "old.ipsw", "new.ipsw")
	if err := dst.Hydrate(scope, store); err != nil {
		t.Fatalf("Hydrate (empty): %v", err)
	}
	if dst.hydrated == nil || dst.d.Firmwares == nil {
		t.Fatal("empty Hydrate left a nil MachoDiff (the hit branch would not be taken)")
	}
	if !dst.Empty() {
		t.Fatalf("empty Hydrate did not render empty: %+v", dst.d.Firmwares)
	}
}
