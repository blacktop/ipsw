package diff

import (
	"context"
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
)

// fakeTopLevelTask is a TopLevelTask that also implements CacheableTask. It
// records the lifecycle calls runTopLevelTasks makes so the test can assert
// miss -> Parse -> persist on the first run and hit -> Hydrate -> skip-Parse on
// the second.
type fakeTopLevelTask struct {
	name      string
	version   int
	optsHash  string
	inputHash string
	parsed    int
	persisted int
	hydrated  int
}

func (t *fakeTopLevelTask) Name() string { return t.name }

func (t *fakeTopLevelTask) Parse(_ context.Context, _ *Diff) error {
	t.parsed++
	return nil
}

func (t *fakeTopLevelTask) Version() int        { return t.version }
func (t *fakeTopLevelTask) OptionsHash() string { return t.optsHash }
func (t *fakeTopLevelTask) InputHash() string   { return t.inputHash }

func (t *fakeTopLevelTask) Hydrate(scope storage.Scope, store storage.Store) error {
	t.hydrated++
	return nil
}

func (t *fakeTopLevelTask) persistTo(scope storage.Scope, store storage.Store) error {
	t.persisted++
	return store.Put(scope, "result", t.name)
}

func TestTopLevelCacheLifecycleMissThenHit(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	store := storage.NewMemoryStore()
	task := &fakeTopLevelTask{name: "toplevel", version: 1, optsHash: "opts", inputHash: "input"}

	d := &Diff{}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	d.SetStore(store)

	// First run: cache is empty, so the task misses, parses, persists, and is
	// marked complete.
	if err := d.runTopLevelTasks(context.Background(), []TopLevelTask{task}); err != nil {
		t.Fatalf("first run error = %v", err)
	}
	if task.parsed != 1 {
		t.Fatalf("first run parsed = %d, want 1 (miss should Parse)", task.parsed)
	}
	if task.persisted != 1 {
		t.Fatalf("first run persisted = %d, want 1", task.persisted)
	}
	if task.hydrated != 0 {
		t.Fatalf("first run hydrated = %d, want 0", task.hydrated)
	}

	scope, ok := taskScope(oldInfo, newInfo, task)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if done, err := store.Complete(scope); err != nil || !done {
		t.Fatalf("store.Complete after first run = (%v,%v), want (true,nil)", done, err)
	}

	// Second run with the SAME store: the completion sentinel exists, so the
	// task hits, hydrates, and skips Parse.
	if err := d.runTopLevelTasks(context.Background(), []TopLevelTask{task}); err != nil {
		t.Fatalf("second run error = %v", err)
	}
	if task.parsed != 1 {
		t.Fatalf("second run parsed = %d, want 1 (hit must skip Parse)", task.parsed)
	}
	if task.hydrated != 1 {
		t.Fatalf("second run hydrated = %d, want 1", task.hydrated)
	}
	if task.persisted != 1 {
		t.Fatalf("second run persisted = %d, want 1 (hit must not re-persist)", task.persisted)
	}
}

func TestTopLevelCacheLifecycleTwoHitsNoParse(t *testing.T) {
	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"KernelCache": {path: "kernelcache.release.v53", digest: []byte{0x02}},
	})

	store := storage.NewMemoryStore()
	task := &fakeTopLevelTask{name: "toplevel", version: 1, optsHash: "opts", inputHash: "input"}

	d := &Diff{}
	d.Old.Info = oldInfo
	d.New.Info = newInfo
	d.SetStore(store)

	// Prime the cache (miss -> Parse -> persist -> complete).
	if err := d.runTopLevelTasks(context.Background(), []TopLevelTask{task}); err != nil {
		t.Fatalf("priming run error = %v", err)
	}
	if task.parsed != 1 {
		t.Fatalf("priming run parsed = %d, want 1", task.parsed)
	}

	// Two consecutive warm reruns must both hit and never Parse again.
	for i := range 2 {
		if err := d.runTopLevelTasks(context.Background(), []TopLevelTask{task}); err != nil {
			t.Fatalf("warm run %d error = %v", i, err)
		}
	}
	if task.parsed != 1 {
		t.Fatalf("after two warm reruns parsed = %d, want 1 (Parse must NOT run on a hit)", task.parsed)
	}
	if task.hydrated != 2 {
		t.Fatalf("after two warm reruns hydrated = %d, want 2", task.hydrated)
	}
	if task.persisted != 1 {
		t.Fatalf("after two warm reruns persisted = %d, want 1 (hits must not re-persist)", task.persisted)
	}
}
