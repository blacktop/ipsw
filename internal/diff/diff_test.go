package diff

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

type fakeVolumeFileSession struct {
	roots    map[string]string
	mounted  map[string]bool
	released []string
	// rootCalls counts every Root invocation so a full-cache-hit test can assert
	// the orchestrator mounted ZERO volumes (excludeHydrated empties every
	// volume's active set, so the loop continues without ever calling Root).
	rootCalls int
}

func (f *fakeVolumeFileSession) Root(typ string) (string, error) {
	f.rootCalls++
	root, ok := f.roots[typ]
	if !ok {
		return "", errors.New("unexpected root request: " + typ)
	}
	if f.mounted == nil {
		f.mounted = make(map[string]bool)
	}
	f.mounted[typ] = true
	return root, nil
}

func (f *fakeVolumeFileSession) Release(typ string) error {
	if !f.mounted[typ] {
		return nil
	}
	delete(f.mounted, typ)
	f.released = append(f.released, typ)
	return nil
}

func TestIPSWSessionExtractDirsArePerSide(t *testing.T) {
	tmpDir := t.TempDir()

	oldDir := ipswSessionExtractDir(tmpDir, "old")
	newDir := ipswSessionExtractDir(tmpDir, "new")

	if oldDir == newDir {
		t.Fatalf("old and new extract dirs are equal: %s", oldDir)
	}
	for _, dir := range []string{oldDir, newDir} {
		rel, err := filepath.Rel(tmpDir, dir)
		if err != nil {
			t.Fatalf("Rel(%s, %s): %v", tmpDir, dir, err)
		}
		if rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatalf("extract dir %s is not under temp dir %s", dir, tmpDir)
		}
	}

	dmgName := "shared-volume-name.dmg"
	oldDMG := filepath.Join(oldDir, dmgName)
	newDMG := filepath.Join(newDir, dmgName)
	if oldDMG == newDMG {
		t.Fatalf("same-named DMGs collide: %s", oldDMG)
	}
}

func TestIndexIdenticalIPSWArtifactsUsesBuildManifestDigests(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache":       {path: "kernelcache.release.v53", digest: []byte{0x01}},
		"OS":                {path: "094-55036-099.dmg.aea", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "094-55682-100.dmg.aea", digest: []byte{0x03}},
		"Cryptex1,AppOS":    {path: "094-54871-103.dmg", digest: []byte{0x04}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache":       {path: "kernelcache.release.v53", digest: []byte{0x01}},
		"OS":                {path: "094-55036-101.dmg.aea", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "094-55682-102.dmg.aea", digest: []byte{0x03}},
		"Cryptex1,AppOS":    {path: "094-54871-105.dmg", digest: []byte{0x04}},
	})
	d := &Diff{
		Old: Context{InputMode: inputModeIPSW, Info: oldInfo},
		New: Context{InputMode: inputModeIPSW, Info: newInfo},
	}

	d.indexIdenticalIPSWArtifacts()

	if !d.sameKernel {
		t.Fatal("sameKernel = false, want true")
	}
	for _, typ := range []string{"fs", "sys", "app"} {
		if !d.ipswVolumeUnchanged(typ) {
			t.Fatalf("%s unchanged = false, want true", typ)
		}
	}
	if !d.allIPSWOSVolumesUnchanged() {
		t.Fatal("allIPSWOSVolumesUnchanged() = false, want true")
	}
}

func TestIndexIdenticalIPSWArtifactsFailsClosedOnDigestMismatch(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache":       {path: "kernelcache.release.v53", digest: []byte{0x01}},
		"OS":                {path: "094-55036-099.dmg.aea", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "094-55682-100.dmg.aea", digest: []byte{0x03}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache":       {path: "kernelcache.release.v53", digest: []byte{0x09}},
		"OS":                {path: "094-55036-101.dmg.aea", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "094-55682-102.dmg.aea", digest: []byte{0x08}},
	})
	d := &Diff{
		Old: Context{InputMode: inputModeIPSW, Info: oldInfo},
		New: Context{InputMode: inputModeIPSW, Info: newInfo},
	}

	d.indexIdenticalIPSWArtifacts()

	if d.sameKernel {
		t.Fatal("sameKernel = true, want false")
	}
	if d.ipswVolumeUnchanged("sys") {
		t.Fatal("sys unchanged = true, want false")
	}
	if d.allIPSWOSVolumesUnchanged() {
		t.Fatal("allIPSWOSVolumesUnchanged() = true, want false")
	}
}

func TestDSCVolumeUnchangedFallsBackToFilesystemDigest(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "filesystem-old.dmg", digest: []byte{0x02}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "filesystem-new.dmg", digest: []byte{0x02}},
	})
	d := &Diff{
		Old: Context{InputMode: inputModeIPSW, Info: oldInfo},
		New: Context{InputMode: inputModeIPSW, Info: newInfo},
	}

	d.indexIdenticalIPSWArtifacts()

	if !d.dscVolumeUnchanged() {
		t.Fatal("dscVolumeUnchanged() = false, want true")
	}
}

// TestEnsureKernelcachePathsNoOpWhenSet is the regression for the partial-hit
// ordering fix: extractKernelcaches sets Kernel.Path as a side effect of the
// kexts task's Parse, but a warm kexts cache hit SKIPS that Parse, leaving the
// path empty for a sibling task (e.g. a partial-hit sandbox) that runs fresh.
// ensureKernelcachePaths backfills the path; when both sides are already set it
// must be a pure no-op (never re-extract, never touch the paths), which this test
// pins. The extraction branch needs real IPSW artifacts and is covered by the
// real-IPSW integration runs.
func TestEnsureKernelcachePathsNoOpWhenSet(t *testing.T) {
	d := &Diff{}
	d.Old.Kernel.Path = "/extracted/old/kernelcache"
	d.New.Kernel.Path = "/extracted/new/kernelcache"

	if err := d.ensureKernelcachePaths(); err != nil {
		t.Fatalf("ensureKernelcachePaths() with both paths set = %v, want nil (must be a no-op)", err)
	}
	if d.Old.Kernel.Path != "/extracted/old/kernelcache" || d.New.Kernel.Path != "/extracted/new/kernelcache" {
		t.Fatalf("ensureKernelcachePaths mutated already-set paths: old=%q new=%q",
			d.Old.Kernel.Path, d.New.Kernel.Path)
	}
}

func TestFilesSHA256Equal(t *testing.T) {
	tmpDir := t.TempDir()
	oldPath := filepath.Join(tmpDir, "old")
	newPath := filepath.Join(tmpDir, "new")

	if err := os.WriteFile(oldPath, []byte("same kernel bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile(old) error = %v", err)
	}
	if err := os.WriteFile(newPath, []byte("same kernel bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile(new) error = %v", err)
	}

	same, err := filesSHA256Equal(oldPath, newPath)
	if err != nil {
		t.Fatalf("filesSHA256Equal() error = %v", err)
	}
	if !same {
		t.Fatal("filesSHA256Equal() = false, want true")
	}

	if err := os.WriteFile(newPath, []byte("different kernel bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile(new different) error = %v", err)
	}
	same, err = filesSHA256Equal(oldPath, newPath)
	if err != nil {
		t.Fatalf("filesSHA256Equal() after change error = %v", err)
	}
	if same {
		t.Fatal("filesSHA256Equal() = true, want false")
	}
}

func TestVolumeJobOrchestratorScansAndReleasesVolumePairs(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-fs-file")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-fs-file")
	oldSys := testVolumeDir(t, tmpDir, "old-sys", "old-sys-file")
	newSys := testVolumeDir(t, tmpDir, "new-sys", "new-sys-file")
	oldSession := &fakeVolumeFileSession{roots: map[string]string{
		"fs":  oldFS,
		"sys": oldSys,
	}}
	newSession := &fakeVolumeFileSession{roots: map[string]string{
		"fs":  newFS,
		"sys": newSys,
	}}
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "old-fs.dmg", digest: []byte{0x01}},
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x02}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "new-fs.dmg", digest: []byte{0x03}},
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x04}},
	})

	job := newRecordingFilesJob()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{job}, storage.NewMemoryStore()); err != nil {
		t.Fatalf("runVolumeJobsAcrossSessions() error = %v", err)
	}

	if got, want := oldSession.released, []string{"fs", "sys"}; !slices.Equal(got, want) {
		t.Fatalf("old released = %v, want %v", got, want)
	}
	if got, want := newSession.released, []string{"fs", "sys"}; !slices.Equal(got, want) {
		t.Fatalf("new released = %v, want %v", got, want)
	}
	if !job.finalized {
		t.Fatal("Finalize was not called")
	}
	assertFileSeen(t, job.prev, "filesystem", "old-fs-file")
	assertFileSeen(t, job.next, "filesystem", "new-fs-file")
	assertFileSeen(t, job.prev, "SystemOS", "old-sys-file")
	assertFileSeen(t, job.next, "SystemOS", "new-sys-file")
}

func TestVolumeJobOrchestratorDropsTaskWhenSetupFails(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-fs-file")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-fs-file")
	oldSession := &fakeVolumeFileSession{roots: map[string]string{"fs": oldFS}}
	newSession := &fakeVolumeFileSession{roots: map[string]string{"fs": newFS}}
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	failing := newSetupFailingJob()
	ok := newRecordingFilesJob()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{failing, ok}, storage.NewMemoryStore()); err != nil {
		t.Fatalf("runVolumeJobsAcrossSessions() error = %v", err)
	}

	if failing.processed {
		t.Fatal("setup-failing task ran ProcessVolume; want it dropped after Setup error")
	}
	if failing.finalized {
		t.Fatal("setup-failing task was finalized; want it dropped after Setup error")
	}
	if !ok.finalized {
		t.Fatal("healthy task was not finalized; one task's setup failure must not poison siblings")
	}
	assertFileSeen(t, ok.prev, "filesystem", "old-fs-file")
}

// recordingSessionFallbackJob is a sys-only MountTask that opts into the
// session fallback and records the roots it receives.
type recordingSessionFallbackJob struct {
	gotOld, gotNew string
	processed      bool
}

func (j *recordingSessionFallbackJob) Name() string                         { return "fallback-test" }
func (j *recordingSessionFallbackJob) Needs(typ string) bool                { return typ == "sys" }
func (j *recordingSessionFallbackJob) WantsSessionFallback(typ string) bool { return typ == "sys" }
func (j *recordingSessionFallbackJob) Finalize() error                      { return nil }
func (j *recordingSessionFallbackJob) ProcessVolume(_, oldRoot, newRoot string) error {
	j.processed = true
	j.gotOld, j.gotNew = oldRoot, newRoot
	return nil
}

// recordingPlainSysJob is a sys-only MountTask WITHOUT the fallback opt-in,
// proving the fallback root is handed only to tasks that asked for it.
type recordingPlainSysJob struct {
	gotOld, gotNew string
}

func (j *recordingPlainSysJob) Name() string          { return "plain-sys-test" }
func (j *recordingPlainSysJob) Needs(typ string) bool { return typ == "sys" }
func (j *recordingPlainSysJob) Finalize() error       { return nil }
func (j *recordingPlainSysJob) ProcessVolume(_, oldRoot, newRoot string) error {
	j.gotOld, j.gotNew = oldRoot, newRoot
	return nil
}

// TestVolumeJobOrchestratorSessionFallbackForMixedPair covers the mixed
// pre-cryptex-vs-cryptex case: the old IPSW has no SystemOS cryptex, so the
// sys phase mounts nothing for it via the strict resolver, but a
// SessionFallbackTask (dscJob in production) receives the session-resolved
// root — the real mount.Session.Root("sys") falls back to the filesystem DMG,
// simulated here by the fake session mapping "sys" to the fs dir. A plain
// task in the same phase still sees the absent side as empty.
func TestVolumeJobOrchestratorSessionFallbackForMixedPair(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-fs-file")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-fs-file")
	newSys := testVolumeDir(t, tmpDir, "new-sys", "new-sys-file")
	oldSession := &fakeVolumeFileSession{roots: map[string]string{
		"fs":  oldFS,
		"sys": oldFS, // mount.Session.Root("sys") falls back to the fs DMG
	}}
	newSession := &fakeVolumeFileSession{roots: map[string]string{
		"fs":  newFS,
		"sys": newSys,
	}}
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "new-fs.dmg", digest: []byte{0x02}},
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x03}},
	})

	fallback := &recordingSessionFallbackJob{}
	plain := &recordingPlainSysJob{}
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{fallback, plain}, storage.NewMemoryStore()); err != nil {
		t.Fatalf("runVolumeJobsAcrossSessions() error = %v", err)
	}

	if !fallback.processed {
		t.Fatal("fallback job never processed the sys volume")
	}
	if fallback.gotOld != oldFS {
		t.Fatalf("fallback job old root = %q, want session-fallback %q", fallback.gotOld, oldFS)
	}
	if fallback.gotNew != newSys {
		t.Fatalf("fallback job new root = %q, want %q", fallback.gotNew, newSys)
	}
	if plain.gotOld != "" {
		t.Fatalf("plain job old root = %q, want empty (no fallback for non-opting tasks)", plain.gotOld)
	}
	if plain.gotNew != newSys {
		t.Fatalf("plain job new root = %q, want %q", plain.gotNew, newSys)
	}
	if got, want := oldSession.released, []string{"sys"}; !slices.Equal(got, want) {
		t.Fatalf("old released = %v, want %v (fallback mount must be released)", got, want)
	}
}

func TestVolumeJobOrchestratorReleasesOnlyMountedAsymmetricVolume(t *testing.T) {
	tmpDir := t.TempDir()
	oldExc := testVolumeDir(t, tmpDir, "old-exc", "old-exc-file")
	oldSession := &fakeVolumeFileSession{roots: map[string]string{
		"exc": oldExc,
	}}
	newSession := &fakeVolumeFileSession{roots: map[string]string{}}
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"Ap,ExclaveOS": {path: "old-exc.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(nil)

	job := newRecordingFilesJob()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{job}, storage.NewMemoryStore()); err != nil {
		t.Fatalf("runVolumeJobsAcrossSessions() error = %v", err)
	}

	if got, want := oldSession.released, []string{"exc"}; !slices.Equal(got, want) {
		t.Fatalf("old released = %v, want %v", got, want)
	}
	if len(newSession.released) != 0 {
		t.Fatalf("new released = %v, want no releases", newSession.released)
	}
	assertFileSeen(t, job.prev, "ExclaveOS", "old-exc-file")
	if len(job.next) != 0 {
		t.Fatalf("new files = %v, want no files", job.next)
	}
}

func TestVolumeJobOrchestratorSkipsVolumesWithMatchingDigest(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-fs-file")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-fs-file")
	oldSys := testVolumeDir(t, tmpDir, "old-sys", "old-sys-file")
	newSys := testVolumeDir(t, tmpDir, "new-sys", "new-sys-file")
	oldSession := &fakeVolumeFileSession{roots: map[string]string{
		"fs":  oldFS,
		"sys": oldSys,
	}}
	newSession := &fakeVolumeFileSession{roots: map[string]string{
		"fs":  newFS,
		"sys": newSys,
	}}
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "old-fs.dmg", digest: []byte{0x01}},
		"Cryptex1,SystemOS": {path: "old-sys.dmg", digest: []byte{0x02}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS":                {path: "new-fs.dmg", digest: []byte{0x03}},
		"Cryptex1,SystemOS": {path: "new-sys.dmg", digest: []byte{0x04}},
	})

	// Pretend fs is unchanged. Only sys should be scanned.
	unchanged := func(typ string) bool { return typ == "fs" }

	job := newRecordingFilesJob()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, unchanged, []Task{job}, storage.NewMemoryStore()); err != nil {
		t.Fatalf("runVolumeJobsAcrossSessions() error = %v", err)
	}

	if got, want := oldSession.released, []string{"sys"}; !slices.Equal(got, want) {
		t.Fatalf("old released = %v, want %v (fs should be skipped)", got, want)
	}
	if len(job.prev["filesystem"]) != 0 || len(job.next["filesystem"]) != 0 {
		t.Fatalf("fs was scanned despite digest match: prev=%v next=%v", job.prev["filesystem"], job.next["filesystem"])
	}
	assertFileSeen(t, job.prev, "SystemOS", "old-sys-file")
	assertFileSeen(t, job.next, "SystemOS", "new-sys-file")
}

func TestDSCJobOnlyNeedsSysVolume(t *testing.T) {
	j := newDSCJob(nil)
	if j.Name() != "dsc" {
		t.Fatalf("Name() = %q, want dsc", j.Name())
	}
	for _, typ := range []string{"fs", "app", "exc"} {
		if j.Needs(typ) {
			t.Errorf("dscJob.Needs(%q) = true, want false", typ)
		}
	}
	if !j.Needs("sys") {
		t.Error("dscJob.Needs(\"sys\") = false, want true")
	}
	if err := j.Finalize(); err != nil {
		t.Errorf("Finalize() = %v, want nil", err)
	}
}

func TestDSCJobFallsBackToFilesystemWhenSystemOSAbsent(t *testing.T) {
	d := &Diff{
		Old: Context{Info: testIPSWInfo(map[string]testManifestEntry{
			"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
		})},
		New: Context{Info: testIPSWInfo(map[string]testManifestEntry{
			"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
		})},
	}

	j := newDSCJob(d)
	if !j.Needs("fs") {
		t.Fatal("dscJob.Needs(\"fs\") = false, want true when SystemOS is absent")
	}
	if j.Needs("sys") {
		t.Fatal("dscJob.Needs(\"sys\") = true, want false when SystemOS is absent")
	}
	for _, typ := range []string{"app", "exc"} {
		if j.Needs(typ) {
			t.Fatalf("dscJob.Needs(%q) = true, want false", typ)
		}
	}
}

func TestLaunchdJobOnlyNeedsFsVolume(t *testing.T) {
	j := newLaunchdJob(nil)
	if j.Name() != "launchd" {
		t.Fatalf("Name() = %q, want launchd", j.Name())
	}
	for _, typ := range []string{"sys", "app", "exc"} {
		if j.Needs(typ) {
			t.Errorf("launchdJob.Needs(%q) = true, want false", typ)
		}
	}
	if !j.Needs("fs") {
		t.Error("launchdJob.Needs(\"fs\") = false, want true")
	}
	if err := j.Finalize(); err != nil {
		t.Errorf("Finalize() = %v, want nil", err)
	}
}

// recordingFilesJob is a minimal MountTask used in orchestrator tests. It
// mirrors filesJob's file-walking behavior without depending on FileDiff
// assembly so the tests focus on orchestration.
type recordingFilesJob struct {
	prev      map[string][]string
	next      map[string][]string
	finalized bool
}

func newRecordingFilesJob() *recordingFilesJob {
	return &recordingFilesJob{
		prev: make(map[string][]string),
		next: make(map[string][]string),
	}
}

func (j *recordingFilesJob) Name() string { return "files-test" }

func (j *recordingFilesJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

func (j *recordingFilesJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	label := volumeLabel(typ)
	if oldRoot != "" {
		if err := search.ForEachFileInMount(oldRoot, label, "", func(dmg, path string) error {
			j.prev[dmg] = append(j.prev[dmg], path)
			return nil
		}); err != nil {
			return err
		}
	}
	if newRoot != "" {
		if err := search.ForEachFileInMount(newRoot, label, "", func(dmg, path string) error {
			j.next[dmg] = append(j.next[dmg], path)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (j *recordingFilesJob) Finalize() error {
	j.finalized = true
	return nil
}

// setupFailingJob is a MountTask whose Setup always errors. The orchestrator
// must drop it before any volume is processed so it never sees ProcessVolume
// or Finalize with half-initialized state.
type setupFailingJob struct {
	recordingFilesJob
	processed bool
}

func newSetupFailingJob() *setupFailingJob {
	return &setupFailingJob{recordingFilesJob: *newRecordingFilesJob()}
}

func (j *setupFailingJob) Name() string { return "setup-failing" }

func (j *setupFailingJob) Setup(storage.Store) error {
	return errors.New("setup boom")
}

func (j *setupFailingJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	j.processed = true
	return j.recordingFilesJob.ProcessVolume(typ, oldRoot, newRoot)
}

// recordingMachoJob is a minimal MachoWalkTask used to verify the
// orchestrator's per-volume BeginVolume/MachoHandler/EndVolume sequencing
// without depending on real Mach-O fixtures. It records the call order so
// the test can assert structure, not heap state.
type recordingMachoJob struct {
	beginCalls []string
	endCalls   []string
	handlerOld []string
	handlerNew []string
	handlerErr error
	abortCalls []string
	oldCalls   int
	newCalls   int
	finalized  bool
}

func newRecordingMachoJob() *recordingMachoJob { return &recordingMachoJob{} }

func (j *recordingMachoJob) Name() string { return "machos-test" }

func (j *recordingMachoJob) Needs(typ string) bool {
	switch typ {
	case "fs", "sys", "app", "exc":
		return true
	}
	return false
}

func (j *recordingMachoJob) BeginVolume(typ string) error {
	j.beginCalls = append(j.beginCalls, volumeLabel(typ))
	return nil
}

func (j *recordingMachoJob) MachoHandler(typ string, side Side) MachoScanHandler {
	label := volumeLabel(typ)
	switch side {
	case SideOld:
		j.handlerOld = append(j.handlerOld, label)
	case SideNew:
		j.handlerNew = append(j.handlerNew, label)
	}
	return func(string, *macho.File) error {
		switch side {
		case SideOld:
			j.oldCalls++
		case SideNew:
			j.newCalls++
		}
		return j.handlerErr
	}
}

func (j *recordingMachoJob) EndVolume(typ string) error {
	j.endCalls = append(j.endCalls, volumeLabel(typ))
	return nil
}

func (j *recordingMachoJob) AbortVolume(typ string) {
	j.abortCalls = append(j.abortCalls, typ)
}

func (j *recordingMachoJob) Finalize() error {
	j.finalized = true
	return nil
}

func TestVolumeJobOrchestratorRunsMachoWalkTasksPerSide(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-fs-file")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-fs-file")
	oldSession := &fakeVolumeFileSession{roots: map[string]string{"fs": oldFS}}
	newSession := &fakeVolumeFileSession{roots: map[string]string{"fs": newFS}}
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x03}},
	})

	job := newRecordingMachoJob()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{job}, storage.NewMemoryStore()); err != nil {
		t.Fatalf("runVolumeJobsAcrossSessions() error = %v", err)
	}

	if got, want := job.beginCalls, []string{"filesystem"}; !slices.Equal(got, want) {
		t.Errorf("beginCalls = %v, want %v", got, want)
	}
	if got, want := job.endCalls, []string{"filesystem"}; !slices.Equal(got, want) {
		t.Errorf("endCalls = %v, want %v", got, want)
	}
	if got, want := job.handlerOld, []string{"filesystem"}; !slices.Equal(got, want) {
		t.Errorf("handlerOld = %v, want %v", got, want)
	}
	if got, want := job.handlerNew, []string{"filesystem"}; !slices.Equal(got, want) {
		t.Errorf("handlerNew = %v, want %v", got, want)
	}
	if !job.finalized {
		t.Error("Finalize was not called")
	}
}

func TestRunVolumeTasksAbortsMachoTaskOnHandlerFailure(t *testing.T) {
	tmpDir := t.TempDir()
	oldRoot := filepath.Join(tmpDir, "old")
	newRoot := filepath.Join(tmpDir, "new")
	writeMinimalMachO(t, filepath.Join(oldRoot, "usr", "bin", "old-tool"))
	writeMinimalMachO(t, filepath.Join(newRoot, "usr", "bin", "new-tool"))

	want := errors.New("handler failed")
	job := newRecordingMachoJob()
	job.handlerErr = want

	errs := runVolumeTasks("fs", volumeRoots{old: oldRoot, new: newRoot}, []Task{job})
	if len(errs) != 1 {
		t.Fatalf("runVolumeTasks errors = %d, want 1 (%v)", len(errs), errs)
	}
	if !errors.Is(errs[0], want) {
		t.Fatalf("runVolumeTasks error = %v, want %v", errs[0], want)
	}
	if got, want := job.abortCalls, []string{"fs"}; !slices.Equal(got, want) {
		t.Fatalf("abortCalls = %v, want %v", got, want)
	}
	if job.oldCalls != 1 {
		t.Fatalf("oldCalls = %d, want 1", job.oldCalls)
	}
	if job.newCalls != 0 {
		t.Fatalf("newCalls = %d, want 0 after old-side abort", job.newCalls)
	}
	if len(job.endCalls) != 0 {
		t.Fatalf("endCalls = %v, want no EndVolume after abort", job.endCalls)
	}
}

func TestMachosJobAbortVolumeDropsPartialState(t *testing.T) {
	d := &Diff{conf: &Config{}}
	job := newMachosJob(d)
	job.cacheDir = t.TempDir()
	if err := job.BeginVolume("fs"); err != nil {
		t.Fatalf("BeginVolume: %v", err)
	}
	label := volumeLabel("fs")
	job.prevKeysByVolume[label]["/usr/bin/old"] = false
	job.diffByVolume[label].New = append(job.diffByVolume[label].New, "/usr/bin/new")

	job.AbortVolume("fs")

	if len(job.volumes) != 0 {
		t.Fatalf("volumes = %v, want empty after abort", job.volumes)
	}
	if _, ok := job.prevKeysByVolume[label]; ok {
		t.Fatalf("prevKeysByVolume still has %q after abort", label)
	}
	if _, ok := job.diffByVolume[label]; ok {
		t.Fatalf("diffByVolume still has %q after abort", label)
	}
	if err := job.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if len(d.Machos) != 0 {
		t.Fatalf("d.Machos = %v, want no output for aborted volume", d.Machos)
	}
}

func writeMinimalMachO(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	// mach_header_64, little-endian, ARM64, MH_EXECUTE, no load commands.
	data := []byte{
		0xcf, 0xfa, 0xed, 0xfe,
		0x0c, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestSplitJoinedErrorsAndTaskNameFromError(t *testing.T) {
	a := errors.New("foo: boom")
	b := errors.New("bar: split")
	joined := errors.Join(a, b)
	parts := splitJoinedErrors(joined)
	if len(parts) != 2 {
		t.Fatalf("splitJoinedErrors: len = %d, want 2", len(parts))
	}
	if name, ok := taskNameFromError(parts[0]); !ok || name != "foo" {
		t.Errorf("taskNameFromError(parts[0]) = (%q,%v), want (foo,true)", name, ok)
	}
	if name, ok := taskNameFromError(parts[1]); !ok || name != "bar" {
		t.Errorf("taskNameFromError(parts[1]) = (%q,%v), want (bar,true)", name, ok)
	}

	if _, ok := taskNameFromError(errors.New("no prefix here")); ok {
		t.Error("taskNameFromError accepted an unprefixed error")
	}
	if _, ok := taskNameFromError(errors.New("__walk__: ouch")); ok {
		t.Error("taskNameFromError accepted the walker sentinel")
	}

	// A non-joined error round-trips as a single element so the caller can
	// still attribute walker-level failures without losing them.
	parts = splitJoinedErrors(a)
	if len(parts) != 1 || parts[0] != a {
		t.Errorf("splitJoinedErrors(single) = %v, want [%v]", parts, a)
	}
}

// fakeCacheableJob is a MountTask that also implements CacheableTask
// (including persistTo). It records the lifecycle calls the orchestrator makes
// so the cache tests can assert miss -> walk -> persist -> complete on the
// first run and hit -> hydrate -> skip-walk on the second.
type fakeCacheableJob struct {
	name       string
	version    int
	optsHash   string
	inputHash  string
	processed  int
	finalized  int
	persisted  int
	hydrated   int
	hydrateErr error
}

func (j *fakeCacheableJob) Name() string { return j.name }

func (j *fakeCacheableJob) Needs(typ string) bool { return typ == "fs" }

func (j *fakeCacheableJob) ProcessVolume(typ, oldRoot, newRoot string) error {
	j.processed++
	return nil
}

func (j *fakeCacheableJob) Finalize() error {
	j.finalized++
	return nil
}

func (j *fakeCacheableJob) Version() int        { return j.version }
func (j *fakeCacheableJob) OptionsHash() string { return j.optsHash }
func (j *fakeCacheableJob) InputHash() string   { return j.inputHash }

func (j *fakeCacheableJob) Hydrate(scope storage.Scope, store storage.Store) error {
	j.hydrated++
	return j.hydrateErr
}

func (j *fakeCacheableJob) persistTo(scope storage.Scope, store storage.Store) error {
	j.persisted++
	return store.Put(scope, "result", j.name)
}

func TestCacheLifecycleMissThenHit(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-fs-file")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-fs-file")
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	store := storage.NewMemoryStore()
	job := &fakeCacheableJob{name: "cacheable", version: 1, optsHash: "opts", inputHash: "input"}

	newSessions := func() (*fakeVolumeFileSession, *fakeVolumeFileSession) {
		return &fakeVolumeFileSession{roots: map[string]string{"fs": oldFS}},
			&fakeVolumeFileSession{roots: map[string]string{"fs": newFS}}
	}

	// First run: cache is empty, so the task misses, walks, persists, and is
	// marked complete.
	oldSession, newSession := newSessions()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{job}, store); err != nil {
		t.Fatalf("first run error = %v", err)
	}
	if job.processed != 1 {
		t.Fatalf("first run processed = %d, want 1 (miss should walk)", job.processed)
	}
	if job.persisted != 1 {
		t.Fatalf("first run persisted = %d, want 1", job.persisted)
	}
	if job.hydrated != 0 {
		t.Fatalf("first run hydrated = %d, want 0", job.hydrated)
	}

	scope, ok := taskScope(oldInfo, newInfo, job)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if done, err := store.Complete(scope); err != nil || !done {
		t.Fatalf("store.Complete after first run = (%v,%v), want (true,nil)", done, err)
	}

	// Second run with the SAME store: the completion sentinel exists, so the
	// task hits, hydrates, and skips the volume walk.
	oldSession, newSession = newSessions()
	if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{job}, store); err != nil {
		t.Fatalf("second run error = %v", err)
	}
	if job.processed != 1 {
		t.Fatalf("second run processed = %d, want 1 (hit must skip the walk)", job.processed)
	}
	if job.hydrated != 1 {
		t.Fatalf("second run hydrated = %d, want 1", job.hydrated)
	}
	if job.persisted != 1 {
		t.Fatalf("second run persisted = %d, want 1 (hit must not re-persist)", job.persisted)
	}
	if len(oldSession.released) != 0 {
		t.Fatalf("second run mounted/released old volume = %v, want none (hydrated task skips mount)", oldSession.released)
	}
}

func TestCacheLifecycleUnderivableIdentityRunsFresh(t *testing.T) {
	// Info structs without a BuildManifest: identity is underivable, so the
	// task is treated as non-cacheable for the run. (Volume resolution also
	// requires a BuildManifest, so the underivable decision is made before
	// any walk could happen.)
	oldInfo := &info.Info{}
	newInfo := &info.Info{}

	job := &fakeCacheableJob{name: "cacheable", version: 1, optsHash: "opts", inputHash: "input"}
	if _, ok := taskScope(oldInfo, newInfo, job); ok {
		t.Fatal("taskScope returned ok=true for an underivable identity")
	}

	store := storage.NewMemoryStore()
	lc := newCacheLifecycle(oldInfo, newInfo, []Task{job}, store)
	if lc.isHydrated(job) {
		t.Fatal("underivable task was hydrated")
	}
	if len(lc.scopes) != 0 {
		t.Fatalf("underivable task recorded a scope: %v", lc.scopes)
	}

	// persistAndComplete must be a no-op for the underivable task: it has no
	// scope, so it is never persisted nor marked complete.
	lc.persistAndComplete(store)
	if job.persisted != 0 {
		t.Fatalf("underivable task persisted = %d, want 0", job.persisted)
	}
}

type testManifestEntry struct {
	path   string
	digest []byte
}

func testIPSWInfo(entries map[string]testManifestEntry) *info.Info {
	manifest := make(map[string]plist.IdentityManifest, len(entries))
	for key, entry := range entries {
		manifest[key] = plist.IdentityManifest{
			Digest: entry.digest,
			Info: map[string]any{
				"Path": entry.path,
			},
		}
	}
	return &info.Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				BuildIdentities: []plist.BuildIdentity{
					{
						Info: plist.IdentityInfo{
							DeviceClass: "v53",
							Variant:     "Customer Erase Install",
						},
						Manifest: manifest,
					},
				},
			},
		},
	}
}

func testVolumeDir(t *testing.T, tmpDir, name, fileName string) string {
	t.Helper()
	dir := filepath.Join(tmpDir, name)
	if err := os.MkdirAll(filepath.Join(dir, "System"), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	path := filepath.Join(dir, "System", fileName)
	if err := os.WriteFile(path, []byte(fileName), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return dir
}

func assertFileSeen(t *testing.T, files map[string][]string, dmg, want string) {
	t.Helper()
	if !strings.Contains(strings.Join(files[dmg], ","), want) {
		t.Fatalf("%s files = %v, want %s", dmg, files[dmg], want)
	}
}
