package diff

import (
	"fmt"
	"maps"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
)

// idempotencyJob is an end-to-end fake CacheableTask that mirrors the
// machos/ents shape: on a cache miss it walks a volume, derives a per-volume
// result keyed by volume label, and publishes it (to j.published) in Finalize;
// on a cache hit it hydrates the same result from the store and publishes that
// instead. Unlike fakeCacheableJob in diff_test.go (which only records call
// counts), this job carries a real output so a test can assert the hydrated
// result equals the freshly-walked one byte-for-byte — the regression guard for
// the "Finalize skipped for hydrated tasks => empty output on every cache hit"
// bug.
//
// It registers as a MachoWalkTask so the orchestrator drives it through the
// shared per-volume walk (BeginVolume/MachoHandler/EndVolume) exactly like the
// production jobs, and so "walk skipped" is observable as zero handler calls on
// the hit path.
type idempotencyJob struct {
	optsHash  string
	inputHash string

	// walked counts how many Mach-Os the per-side handlers consumed across the
	// whole run. A cache hit must leave this at 0 because the orchestrator
	// excludes a hydrated task from the volume walk.
	walked int
	// hydrateCalls counts Hydrate invocations so a test can assert the hit path
	// rebuilt state from the store.
	hydrateCalls int
	// persistCalls counts persistTo invocations so a test can assert a hit does
	// not re-persist.
	persistCalls int

	volumes  []string
	byVolume map[string]string
	hydrated map[string]string

	// published is the per-volume result Finalize emits: the freshly-walked
	// byVolume map on a miss, or the hydrated map on a hit. A test asserts the
	// two are byte-for-byte equal across the cache boundary. Holding the result
	// on the job (not the Diff) keeps the production Diff struct free of
	// test-only fields.
	published map[string]string
}

func newIdempotencyJob(optsHash, inputHash string) *idempotencyJob {
	return &idempotencyJob{
		optsHash:  optsHash,
		inputHash: inputHash,
		byVolume:  make(map[string]string),
	}
}

func (j *idempotencyJob) Name() string { return "idempotency" }

func (j *idempotencyJob) Needs(typ string) bool { return typ == "fs" }

func (j *idempotencyJob) BeginVolume(typ string) error {
	label := volumeLabel(typ)
	trackVolumeOnce(&j.volumes, label)
	return nil
}

func (j *idempotencyJob) MachoHandler(typ string, side Side) search.MachoScanHandler {
	if side != SideNew {
		// Only the new side produces output for this fake; the old side is a
		// no-op so the per-volume result is deterministic regardless of walk
		// order.
		return func(string, *macho.File) error {
			j.walked++
			return nil
		}
	}
	label := volumeLabel(typ)
	return func(path string, _ *macho.File) error {
		j.walked++
		j.byVolume[label] = fmt.Sprintf("walked %s @ %s", label, path)
		return nil
	}
}

func (j *idempotencyJob) EndVolume(typ string) error { return nil }

func (j *idempotencyJob) Finalize() error {
	if j.hydrated != nil {
		j.published = j.hydrated
		return nil
	}
	out := make(map[string]string, len(j.volumes))
	maps.Copy(out, j.byVolume)
	j.published = out
	return nil
}

func (j *idempotencyJob) Version() int        { return 1 }
func (j *idempotencyJob) OptionsHash() string { return j.optsHash }
func (j *idempotencyJob) InputHash() string   { return j.inputHash }

func (j *idempotencyJob) Hydrate(scope storage.Scope, store storage.Store) error {
	j.hydrateCalls++
	out := make(map[string]string)
	err := store.Iter(scope, func(key string, decode func(v any) error) error {
		var rendered string
		if err := decode(&rendered); err != nil {
			return err
		}
		out[key] = rendered
		return nil
	})
	if err != nil {
		return err
	}
	j.hydrated = out
	return nil
}

func (j *idempotencyJob) persistTo(scope storage.Scope, store storage.Store) error {
	j.persistCalls++
	for label, rendered := range j.published {
		if err := store.Put(scope, label, rendered); err != nil {
			return err
		}
	}
	return nil
}

// TestCacheIdempotencyEndToEnd drives the full orchestrator lifecycle four
// times to lock the idempotency contract:
//
//  1. Fresh store  -> MISS: the task walks, persists, and is marked complete.
//  2. Same store   -> HIT : the task hydrates, the walk is skipped, and the
//     hydrated output equals run 1's output byte-for-byte.
//  3. Same store,
//     mutated opts -> MISS: a changed OptionsHash invalidates the scope, so
//     the task walks again instead of serving stale bytes.
//  4. Fresh store
//     (== --clean) -> MISS: a fresh DB has no completion sentinel, so the task
//     walks again.
func TestCacheIdempotencyEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	oldFS := testVolumeDir(t, tmpDir, "old-fs", "old-tool")
	newFS := testVolumeDir(t, tmpDir, "new-fs", "new-tool")
	writeMinimalMachO(t, oldFS+"/usr/bin/old-mach")
	writeMinimalMachO(t, newFS+"/usr/bin/new-mach")

	oldInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "old-fs.dmg", digest: []byte{0x01}},
	})
	newInfo := testIPSWInfo(map[string]testManifestEntry{
		"OS": {path: "new-fs.dmg", digest: []byte{0x02}},
	})

	newSessions := func() (*fakeVolumeFileSession, *fakeVolumeFileSession) {
		return &fakeVolumeFileSession{roots: map[string]string{"fs": oldFS}},
			&fakeVolumeFileSession{roots: map[string]string{"fs": newFS}}
	}
	run := func(store storage.Store, optsHash string) *idempotencyJob {
		job := newIdempotencyJob(optsHash, "input-v1")
		oldSession, newSession := newSessions()
		if err := runVolumeJobsAcrossSessions(oldInfo, newInfo, oldSession, newSession, nil, []Task{job}, store); err != nil {
			t.Fatalf("runVolumeJobsAcrossSessions: %v", err)
		}
		return job
	}

	shared := storage.NewMemoryStore()

	// Run 1: cache MISS against a fresh store.
	first := run(shared, "opts-v1")
	if first.walked == 0 {
		t.Fatal("run 1 (miss) did not walk any Mach-Os")
	}
	if first.hydrateCalls != 0 {
		t.Fatalf("run 1 hydrateCalls = %d, want 0 (a fresh store is a miss)", first.hydrateCalls)
	}
	if first.persistCalls != 1 {
		t.Fatalf("run 1 persistCalls = %d, want 1", first.persistCalls)
	}
	wantResult := first.published
	if len(wantResult) == 0 {
		t.Fatal("run 1 produced no result to cache")
	}

	scope, ok := taskScope(oldInfo, newInfo, first)
	if !ok {
		t.Fatal("taskScope returned ok=false for a derivable identity")
	}
	if done, err := shared.Complete(scope); err != nil || !done {
		t.Fatalf("Complete after run 1 = (%v,%v), want (true,nil)", done, err)
	}

	// Run 2: cache HIT against the same store. The task must hydrate, skip the
	// walk entirely, and republish output identical to run 1.
	second := run(shared, "opts-v1")
	if second.walked != 0 {
		t.Fatalf("run 2 (hit) walked %d Mach-Os, want 0 (hydrated task skips the walk)", second.walked)
	}
	if second.hydrateCalls != 1 {
		t.Fatalf("run 2 hydrateCalls = %d, want 1", second.hydrateCalls)
	}
	if second.persistCalls != 0 {
		t.Fatalf("run 2 persistCalls = %d, want 0 (a hit must not re-persist)", second.persistCalls)
	}
	if !maps.Equal(second.published, wantResult) {
		t.Fatalf("run 2 (hit) output != run 1 (miss) output:\n hit =%v\n miss=%v",
			second.published, wantResult)
	}

	// Run 3: mutate an OptionsHash input. The changed scope has no completion
	// sentinel, so the task MISSES and walks again rather than serving stale
	// bytes keyed under the old options.
	third := run(shared, "opts-v2")
	if third.walked == 0 {
		t.Fatal("run 3 (changed options) did not walk; a stale result was served")
	}
	if third.hydrateCalls != 0 {
		t.Fatalf("run 3 hydrateCalls = %d, want 0 (changed options must miss)", third.hydrateCalls)
	}
	if third.persistCalls != 1 {
		t.Fatalf("run 3 persistCalls = %d, want 1 (a fresh walk persists)", third.persistCalls)
	}

	// Run 4: simulate --clean by handing the task a fresh store. No completion
	// sentinel exists, so the task MISSES and walks.
	clean := run(storage.NewMemoryStore(), "opts-v1")
	if clean.walked == 0 {
		t.Fatal("run 4 (--clean / fresh store) did not walk")
	}
	if clean.hydrateCalls != 0 {
		t.Fatalf("run 4 hydrateCalls = %d, want 0 (a fresh store after --clean is a miss)", clean.hydrateCalls)
	}
	if !maps.Equal(clean.published, wantResult) {
		t.Fatalf("run 4 (clean re-walk) output != run 1 output:\n clean=%v\n miss =%v",
			clean.published, wantResult)
	}
}
