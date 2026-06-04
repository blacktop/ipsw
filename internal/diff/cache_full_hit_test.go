package diff

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
)

// writeLaunchdMachO writes a minimal ARM64 Mach-O at path carrying a single
// __TEXT,__config section whose bytes are configBody. launchdJob extracts that
// section verbatim, so two different bodies produce a real git diff. The layout
// is mach_header_64 + one LC_SEGMENT_64 (with one section_64) + the section
// payload, which is the smallest input launchdConfigFromRoots can read.
func writeLaunchdMachO(t *testing.T, path, configBody string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}

	const (
		headerSize  = 32
		segCmdSize  = 72
		sectionSize = 80
		loadSize    = segCmdSize + sectionSize
	)
	body := []byte(configBody)
	sectOffset := uint32(headerSize + loadSize)

	buf := make([]byte, sectOffset)
	le := binary.LittleEndian

	// mach_header_64
	le.PutUint32(buf[0:], 0xfeedfacf)  // magic MH_MAGIC_64
	le.PutUint32(buf[4:], 0x0100000c)  // cputype ARM64
	le.PutUint32(buf[8:], 0x00000000)  // cpusubtype
	le.PutUint32(buf[12:], 0x00000002) // filetype MH_EXECUTE
	le.PutUint32(buf[16:], 1)          // ncmds
	le.PutUint32(buf[20:], loadSize)   // sizeofcmds
	le.PutUint32(buf[24:], 0)          // flags
	// buf[28:32] reserved

	// LC_SEGMENT_64
	seg := buf[headerSize:]
	le.PutUint32(seg[0:], 0x19)                                  // cmd LC_SEGMENT_64
	le.PutUint32(seg[4:], loadSize)                              // cmdsize
	copy(seg[8:24], "__TEXT")                                    // segname
	le.PutUint64(seg[24:], 0)                                    // vmaddr
	le.PutUint64(seg[32:], uint64(sectOffset)+uint64(len(body))) // vmsize
	le.PutUint64(seg[40:], 0)                                    // fileoff
	le.PutUint64(seg[48:], uint64(sectOffset)+uint64(len(body))) // filesize
	le.PutUint32(seg[56:], 5)                                    // maxprot
	le.PutUint32(seg[60:], 5)                                    // initprot
	le.PutUint32(seg[64:], 1)                                    // nsects
	le.PutUint32(seg[68:], 0)                                    // flags

	// section_64
	sect := seg[segCmdSize:]
	copy(sect[0:16], "__config")                // sectname
	copy(sect[16:32], "__TEXT")                 // segname
	le.PutUint64(sect[32:], uint64(sectOffset)) // addr
	le.PutUint64(sect[40:], uint64(len(body)))  // size
	le.PutUint32(sect[48:], sectOffset)         // offset
	le.PutUint32(sect[52:], 0)                  // align
	// reloff/nreloc/flags/reserved all zero

	buf = append(buf, body...)
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

// writeMinimalIPSWZip writes a tiny but valid zip at path with a single loose
// member, so filesJob.Setup (which scans the IPSW zip pseudo-bucket before the
// hydration decision) can open it on every run without a real firmware image.
func writeMinimalIPSWZip(t *testing.T, path, memberName, memberBody string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%s): %v", path, err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create(memberName)
	if err != nil {
		t.Fatalf("zip.Create(%s): %v", memberName, err)
	}
	if _, err := w.Write([]byte(memberBody)); err != nil {
		t.Fatalf("zip member write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

// fullHitVolumeDir builds an "fs" volume root carrying content for every
// content-bearing OS-volume job: a Mach-O (machos/ents/files), a FeatureFlags
// plist (features), and a localized .strings resource (localizations). The
// returned root is what the fake session hands back for the "fs" volume.
func fullHitVolumeDir(t *testing.T, tmpDir, name, marker string) string {
	t.Helper()
	root := filepath.Join(tmpDir, name)

	writeMinimalMachO(t, filepath.Join(root, "usr", "bin", marker))

	featurePlist := filepath.Join(root, "System", "Library", "FeatureFlags", "Domain.plist")
	if err := os.MkdirAll(filepath.Dir(featurePlist), 0o755); err != nil {
		t.Fatalf("MkdirAll(features): %v", err)
	}
	plistBody := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Enabled</key><` + marker + `/></dict></plist>
`
	if err := os.WriteFile(featurePlist, []byte(plistBody), 0o644); err != nil {
		t.Fatalf("WriteFile(features): %v", err)
	}

	strings := filepath.Join(root, "System", "Library", "Frameworks", "X.framework", "en.lproj", "Localizable.strings")
	if err := os.MkdirAll(filepath.Dir(strings), 0o755); err != nil {
		t.Fatalf("MkdirAll(strings): %v", err)
	}
	if err := os.WriteFile(strings, []byte(`"key" = "`+marker+`";`+"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(strings): %v", err)
	}

	writeLaunchdMachO(t, filepath.Join(root, "sbin", "launchd"), "launchd-config: "+marker+"\n")

	return root
}

// newFullHitDiff wires a *Diff with the old/new Info, IPSW zip paths, and the
// minimal config the real cacheable jobs read in their constructors. The
// manifests carry both the "OS" (fs) and "Cryptex1,SystemOS" (sys) keys, so the
// six OS-volume jobs walk fs and dscJob walks sys.
func newFullHitDiff(oldInfo, newInfo *info.Info, oldZip, newZip string) *Diff {
	d := &Diff{conf: &Config{}}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	d.Old.IPSWPath = oldZip
	d.New.IPSWPath = newZip
	return d
}

// allCacheableFsJobs builds one fresh instance of every cacheable job that
// participates in the fs volume walk. Each run gets its own instances because
// the real jobs carry mutable per-run state.
func allCacheableFsJobs(d *Diff) []Task {
	return []Task{
		newMachosJob(d),
		newEntitlementsJob(d),
		newFilesJob(d),
		newLaunchdJob(d),
		newFeaturesJob(d),
		newLocalizationsJob(d),
	}
}

// seedDSCScopeComplete writes a complete dscJob cache scope into the store so a
// later full-hit run hydrates dsc instead of mounting "sys". A real dscJob
// ProcessVolume opens a dyld_shared_cache from the mounted root, which cannot be
// synthesized in a unit test; seeding the scope (persistTo + MarkComplete, the
// same rows the orchestrator's persistAndComplete writes) reproduces the on-disk
// state a prior real run leaves behind, which is all the hydrate path reads.
func seedDSCScopeComplete(t *testing.T, oldInfo, newInfo *info.Info, store storage.Store) {
	t.Helper()
	seed := newDSCJobWithInfo(oldInfo, newInfo)
	seed.d.Dylibs = &mcmd.MachoDiff{New: []string{"/usr/lib/seeded.dylib"}, Updated: make(map[string]string)}
	seed.d.Old.Webkit = "623.0.0.0.0"
	seed.d.New.Webkit = "623.9.9.9.9"
	scope, ok := taskScope(oldInfo, newInfo, seed)
	if !ok {
		t.Fatal("taskScope ok=false for dsc seed")
	}
	if err := seed.persistTo(scope, store); err != nil {
		t.Fatalf("seed dsc persistTo: %v", err)
	}
	if err := store.MarkComplete(scope); err != nil {
		t.Fatalf("seed dsc MarkComplete: %v", err)
	}
}

// TestFullCacheHitSkipsMounting is the headline-win regression guard: once every
// cacheable task's scope is complete in the store, a rerun must hydrate ALL of
// them and mount ZERO volumes. The orchestrator drops hydrated tasks from each
// volume's active set (excludeHydrated); when every task that wants "fs" is
// hydrated the active set is empty, so the volume loop continues WITHOUT ever
// calling Root — proving a fully-cached rerun skips mounting entirely.
//
// Every fs-volume cacheable task participates, including launchd: the synthetic
// /sbin/launchd carries a real __TEXT,__config section so its diff is non-empty
// and gets cached, completed, and hydrated like the others.
func TestFullCacheHitSkipsMounting(t *testing.T) {
	tmpDir := t.TempDir()

	oldFS := fullHitVolumeDir(t, tmpDir, "old-fs", "old-marker")
	newFS := fullHitVolumeDir(t, tmpDir, "new-fs", "new-marker")

	oldZip := filepath.Join(tmpDir, "old.ipsw")
	newZip := filepath.Join(tmpDir, "new.ipsw")
	writeMinimalIPSWZip(t, oldZip, "BuildManifest.plist", "old")
	writeMinimalIPSWZip(t, newZip, "BuildManifest.plist", "new-and-longer")

	// Both fs and sys resolve so dscJob (which reads "sys") joins the run. A
	// leaked sys mount on the full-hit rerun would call Root("sys"), which the
	// zero-Root assertion below catches.
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "old-fs.dmg", digest: []byte{0x01}},
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x10}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "new-fs.dmg", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x20}},
	})

	// Sessions hand back a root for BOTH volumes so a leaked sys mount would
	// resolve (and increment rootCalls) rather than erroring — the zero-Root
	// assertion is the real guard.
	newSessions := func() (*fakeVolumeFileSession, *fakeVolumeFileSession) {
		return &fakeVolumeFileSession{roots: map[string]string{"fs": oldFS, "sys": oldFS}},
			&fakeVolumeFileSession{roots: map[string]string{"fs": newFS, "sys": newFS}}
	}

	shared := storage.NewMemoryStore()
	t.Cleanup(func() { _ = shared.Close() })

	// Run 1: cache MISS against a fresh store. Every task walks the fs volume,
	// persists, and is marked complete. Both sessions must mount the fs pair.
	d1 := newFullHitDiff(oldInfo, newInfo, oldZip, newZip)
	jobs1 := allCacheableFsJobs(d1)
	oldS1, newS1 := newSessions()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldS1, newS1, nil, jobs1, shared); err != nil {
		t.Fatalf("run 1 (miss): %v", err)
	}
	if oldS1.rootCalls == 0 || newS1.rootCalls == 0 {
		t.Fatalf("run 1 (miss) mounted old=%d new=%d Root calls, want >0 on both (a fresh run must mount)",
			oldS1.rootCalls, newS1.rootCalls)
	}

	// Capture run-1 output so run 2's hydrated output can be compared.
	want := snapshotDiffSections(d1)

	// Every cacheable task must have stamped its completion sentinel.
	for _, j := range jobs1 {
		ct, ok := j.(CacheableTask)
		if !ok {
			t.Fatalf("%s is not a CacheableTask", j.Name())
		}
		scope, ok := taskScope(oldInfo, newInfo, ct)
		if !ok {
			t.Fatalf("taskScope ok=false for %s", j.Name())
		}
		done, err := shared.Complete(scope)
		if err != nil {
			t.Fatalf("Complete(%s): %v", j.Name(), err)
		}
		if !done {
			t.Fatalf("%s did not mark its scope complete after run 1", j.Name())
		}
	}

	// Seed dscJob's "sys" scope complete (a real DSC ProcessVolume cannot run on a
	// synthetic root). Run 2 then carries dsc alongside the six fs jobs; a full hit
	// must hydrate dsc and leave the sys volume unmounted, just like the fs jobs.
	seedDSCScopeComplete(t, oldInfo, newInfo, shared)

	// Run 2: cache HIT against the same store. Every task hydrates, the active
	// set for both the fs AND sys volumes empties, and NO volume is mounted on
	// either side — proving a full hit (including dsc) skips the sys mount too.
	d2 := newFullHitDiff(oldInfo, newInfo, oldZip, newZip)
	jobs2 := append(allCacheableFsJobs(d2), newDSCJob(d2))
	oldS2, newS2 := newSessions()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldS2, newS2, nil, jobs2, shared); err != nil {
		t.Fatalf("run 2 (hit): %v", err)
	}

	// THE headline assertion: a fully-cached rerun mounts ZERO volumes, including
	// the "sys" volume dscJob would otherwise read.
	if oldS2.rootCalls != 0 || newS2.rootCalls != 0 {
		t.Fatalf("run 2 (full hit) mounted old=%d new=%d Root calls, want 0 (excludeHydrated must empty every volume's active set, including sys)",
			oldS2.rootCalls, newS2.rootCalls)
	}
	if len(oldS2.released) != 0 || len(newS2.released) != 0 {
		t.Fatalf("run 2 (full hit) released old=%v new=%v volumes, want none (nothing was mounted)",
			oldS2.released, newS2.released)
	}

	// Every cacheable task must have taken the hydrate path on run 2.
	assertHydrated := func(name string, hydrated bool) {
		if !hydrated {
			t.Fatalf("run 2: %s did not hydrate on a full cache hit", name)
		}
	}
	for _, j := range jobs2 {
		switch v := j.(type) {
		case *machosJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		case *entsJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		case *filesJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		case *launchdJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		case *featuresJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		case *locsJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		case *dscJob:
			assertHydrated(v.Name(), v.hydrated != nil)
		default:
			t.Fatalf("unexpected job type %T in full-hit set", j)
		}
	}

	// The hydrated render state must equal the freshly-walked run-1 state, so a
	// fully-cached rerun publishes byte-identical output without mounting.
	got := snapshotDiffSections(d2)
	if got.machos != want.machos {
		t.Errorf("machos output differs across the cache boundary:\n hit =%q\n miss=%q", got.machos, want.machos)
	}
	if got.ents != want.ents {
		t.Errorf("ents output differs across the cache boundary:\n hit =%q\n miss=%q", got.ents, want.ents)
	}
	if got.files != want.files {
		t.Errorf("files output differs across the cache boundary:\n hit =%q\n miss=%q", got.files, want.files)
	}
	if got.features != want.features {
		t.Errorf("features output differs across the cache boundary:\n hit =%q\n miss=%q", got.features, want.features)
	}
	if got.localizations != want.localizations {
		t.Errorf("localizations output differs across the cache boundary:\n hit =%q\n miss=%q", got.localizations, want.localizations)
	}
	if got.launchd != want.launchd {
		t.Errorf("launchd output differs across the cache boundary:\n hit =%q\n miss=%q", got.launchd, want.launchd)
	}
}

// diffSectionSnapshot is a stable, comparable rendering of the cacheable diff
// sections, used to assert hit == miss output across the cache boundary.
type diffSectionSnapshot struct {
	machos        string
	ents          string
	files         string
	features      string
	localizations string
	launchd       string
}

// snapshotDiffSections renders each cacheable section's JSON report payload.
// Snapshotting via the JSON payload (encoding/json sorts map keys) gives a
// stable, comparable string without the renderers' Markdown filesystem side
// effects (e.g. entsRenderer.Markdown writes Entitlements.md).
func snapshotDiffSections(d *Diff) diffSectionSnapshot {
	marshal := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			return "<marshal-error: " + err.Error() + ">"
		}
		return string(b)
	}
	return diffSectionSnapshot{
		machos:        marshal(newMachosRenderer(d.Machos).JSON()),
		ents:          marshal(newEntsRenderer(d.Ents).JSON()),
		files:         marshal(newFilesRenderer(d.Files).JSON()),
		features:      marshal(newFeaturesRenderer(d.Features).JSON()),
		localizations: marshal(newLocsRenderer(d.Localizations).JSON()),
		launchd:       marshal(newLaunchdRenderer(d.Launchd).JSON()),
	}
}
