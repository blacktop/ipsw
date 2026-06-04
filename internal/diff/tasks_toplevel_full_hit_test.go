package diff

import (
	"context"
	"path/filepath"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

// cacheableTopLevel is the union a top-level task implements: the cache contract
// plus the Parse lifecycle the orchestrator drives.
type cacheableTopLevel interface {
	TopLevelTask
	CacheableTask
}

// parseCountingTopLevel wraps a real top-level task, delegating every cache
// identity / hydrate / persist call to the wrapped task (so the resolved scope is
// byte-identical to what was seeded) while counting Parse calls. It is the seam
// the top-level full-hit test uses to prove a warm rerun runs ZERO Parse work
// against the real tasks without standing up real kernelcaches / firmware.
type parseCountingTopLevel struct {
	inner  cacheableTopLevel
	parsed int
}

func (w *parseCountingTopLevel) Name() string        { return w.inner.Name() }
func (w *parseCountingTopLevel) Version() int        { return w.inner.Version() }
func (w *parseCountingTopLevel) OptionsHash() string { return w.inner.OptionsHash() }
func (w *parseCountingTopLevel) InputHash() string   { return w.inner.InputHash() }

func (w *parseCountingTopLevel) Hydrate(scope storage.Scope, store storage.Store) error {
	return w.inner.Hydrate(scope, store)
}

func (w *parseCountingTopLevel) persistTo(scope storage.Scope, store storage.Store) error {
	return w.inner.persistTo(scope, store)
}

// Parse counts the call. If the orchestrator ever invokes it on a full hit the
// counter trips the test; it deliberately does NOT delegate to the real Parse
// (which would open real artifacts that do not exist in the test).
func (w *parseCountingTopLevel) Parse(context.Context, *Diff) error {
	w.parsed++
	return nil
}

// TestTopLevelFullCacheHitSkipsParse is the top-level analogue of
// TestFullCacheHitSkipsMounting: once every cacheable top-level task's scope is
// complete in the store, a warm runTopLevelTasks rerun must hydrate ALL of them
// and call Parse ZERO times. It exercises the five real top-level task types
// (kexts, kdks, firmwares, iboot, sandbox) so the scope each wrapper resolves is
// the real one seeded by the run-1 persist below; a parse-counting wrapper makes
// "Parse never ran" observable without standing up real kernelcaches / firmware.
func TestTopLevelFullCacheHitSkipsParse(t *testing.T) {
	tmpDir := t.TempDir()
	oldZip := filepath.Join(tmpDir, "old.ipsw")
	newZip := filepath.Join(tmpDir, "new.ipsw")
	// firmwaresTask.InputHash reads the IPSW zip central directory; write real
	// (tiny) zips so the digest resolves on both the seed and the run.
	writeMinimalIPSWZip(t, oldZip, "Firmware/iBoot.img4.im4p", "old-iboot")
	writeMinimalIPSWZip(t, newZip, "Firmware/iBoot.img4.im4p", "new-iboot-longer")

	// A manifest carrying KernelCache (kexts/sandbox InputHash) and iBoot (iboot
	// InputHash) entries so all five scopes are derivable.
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
		"iBoot":       {path: "iBoot.v53", digest: []byte{0x0a}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
		"iBoot":       {path: "iBoot.v53", digest: []byte{0x0b}},
	})

	const oldKDK = "/Library/Developer/KDKs/A.kdk/System/Library/Kernels/kernel.release.t6000"
	const newKDK = "/Library/Developer/KDKs/B.kdk/System/Library/Kernels/kernel.release.t6000"
	stubKDKIdentities(t, map[string]kdkIdentityEntry{
		dsym(oldKDK): {size: 100, modTime: 1000, ok: true},
		dsym(newKDK): {size: 200, modTime: 2000, ok: true},
	})

	store := storage.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	// newDiff wires a fresh *Diff for one run. Each run gets its own so the tasks'
	// mutable per-run state never leaks across the cache boundary.
	newDiff := func() *Diff {
		d := &Diff{conf: &Config{}}
		d.Old.Info = oldInfo
		d.New.Info = newInfo
		d.Old.IPSWPath = oldZip
		d.New.IPSWPath = newZip
		d.Old.KDK = oldKDK
		d.New.KDK = newKDK
		d.SetStore(store)
		return d
	}

	// Run 1 equivalent: seed each real task's scope complete with content-bearing
	// output, exactly as a fresh runTopLevelTasks would after Parse. This is the
	// on-disk state run 2's hydrate reads.
	seedDiff := newDiff()
	seedTopLevelScopes(t, seedDiff, store, oldInfo, newInfo)

	// Run 2: warm rerun through the real orchestrator. Each task is wrapped so
	// Parse calls are counted; the wrapper delegates identity/hydrate to the real
	// task so the resolved scope matches the seeded one.
	d2 := newDiff()
	wrapped := []*parseCountingTopLevel{
		{inner: newKextsTask(d2)},
		{inner: newKDKsTask(d2)},
		{inner: newFirmwaresTask(d2)},
		{inner: newIBootTask(d2)},
		{inner: newSandboxTask(d2)},
	}
	tasks := make([]TopLevelTask, len(wrapped))
	for i, w := range wrapped {
		tasks[i] = w
	}

	// Every task's scope must be complete BEFORE the warm rerun (so the
	// orchestrator hydrates rather than re-parsing). This check must run
	// pre-rerun: hydration mutates Diff state that feeds some InputHashes
	// (kdks normalizes d.Old/New.KDK to display form), so a post-run
	// recompute would resolve a different scope than the orchestrator saw.
	for _, w := range wrapped {
		scope, ok := taskScope(oldInfo, newInfo, w)
		if !ok {
			t.Fatalf("taskScope ok=false for %s", w.Name())
		}
		done, err := store.Complete(scope)
		if err != nil {
			t.Fatalf("Complete(%s): %v", w.Name(), err)
		}
		if !done {
			t.Fatalf("%s scope not complete before the warm rerun; the seed did not stamp it", w.Name())
		}
	}

	if err := d2.runTopLevelTasks(context.Background(), tasks); err != nil {
		t.Fatalf("run 2 (full hit): %v", err)
	}

	// THE headline assertion: a fully-cached rerun runs ZERO Parse work.
	for _, w := range wrapped {
		if w.parsed != 0 {
			t.Errorf("%s Parse ran %d times on a full cache hit, want 0", w.Name(), w.parsed)
		}
	}

	// The warm rerun must publish the seeded outputs onto d2 (proving Hydrate ran
	// and republished to d.*), not leave them zero.
	if d2.Kexts == nil || len(d2.Kexts.New) == 0 {
		t.Errorf("kexts not republished on hit: %+v", d2.Kexts)
	}
	if d2.KDKs == "" {
		t.Error("kdks not republished on hit")
	}
	if d2.Firmwares == nil || len(d2.Firmwares.New) == 0 {
		t.Errorf("firmwares not republished on hit: %+v", d2.Firmwares)
	}
	if d2.IBoot == nil || len(d2.IBoot.Versions) == 0 {
		t.Errorf("iboot not republished on hit: %+v", d2.IBoot)
	}
}

// seedTopLevelScopes populates each real top-level task with content-bearing
// output and writes its complete cache scope into store, reproducing the on-disk
// state a fresh run leaves after Parse + persistAndComplete.
func seedTopLevelScopes(t *testing.T, d *Diff, store storage.Store, oldInfo, newInfo *info.Info) {
	t.Helper()

	d.Kexts = &mcmd.MachoDiff{New: []string{"com.apple.seeded"}, Updated: make(map[string]string)}
	d.Old.Kernel.Version = &kernelcache.Version{KernelVersion: kernelcache.KernelVersion{Darwin: "old"}}
	d.New.Kernel.Version = &kernelcache.Version{KernelVersion: kernelcache.KernelVersion{Darwin: "new"}}
	d.KDKs = "## KDK struct diff\n```diff\n+ int x;\n```\n"
	d.Firmwares = &mcmd.MachoDiff{New: []string{"Firmware/seeded.im4p"}, Updated: make(map[string]string)}
	d.IBoot = &IBootDiff{
		Versions: []string{"iBoot-1", "iBoot-2"},
		New:      map[string][]string{"iBoot.v53": {"str"}},
		Removed:  make(map[string][]string),
	}

	seeds := []cacheableTopLevel{
		newKextsTask(d),
		newKDKsTask(d),
		newFirmwaresTask(d),
		newIBootTask(d),
	}
	for _, ct := range seeds {
		scope, ok := taskScope(oldInfo, newInfo, ct)
		if !ok {
			t.Fatalf("seed taskScope ok=false for %s", ct.Name())
		}
		if err := ct.persistTo(scope, store); err != nil {
			t.Fatalf("seed persistTo %s: %v", ct.Name(), err)
		}
		if err := store.MarkComplete(scope); err != nil {
			t.Fatalf("seed MarkComplete %s: %v", ct.Name(), err)
		}
	}

	// sandbox is seeded separately: its OptionsHash folds the sandboxBuildTag, but
	// persistTo writes a string row, so seed it via the store directly with the
	// real scope and a non-empty value.
	sb := newSandboxTask(d)
	sb.d.Sandbox = "## Sandbox Profiles\n```diff\n+ (allow foo)\n```\n"
	scope, ok := taskScope(oldInfo, newInfo, sb)
	if !ok {
		t.Fatal("seed taskScope ok=false for sandbox")
	}
	if err := sb.persistTo(scope, store); err != nil {
		t.Fatalf("seed persistTo sandbox: %v", err)
	}
	if err := store.MarkComplete(scope); err != nil {
		t.Fatalf("seed MarkComplete sandbox: %v", err)
	}
}
