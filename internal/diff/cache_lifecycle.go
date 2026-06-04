package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

// constOptionsHash digests a constant per-task tag plus the task's cache
// version. Used by CacheableTasks with no output-affecting options, where
// any behavior change is signaled by bumping the version (which also lives
// in the cache Scope as TaskVersion).
func constOptionsHash(tag string, version int) string {
	h := sha256.New()
	_, _ = h.Write([]byte(tag))
	_, _ = h.Write([]byte{byte(version)})
	return hex.EncodeToString(h.Sum(nil))
}

// cacheIdentities derives the per-IPSW cache identities once per run. ok is
// false when either identity cannot be derived (OTA/Directory modes, or any
// IPSW missing a BuildManifest), in which case every task is non-cacheable.
func cacheIdentities(oldInfo, newInfo *info.Info) (oldID, newID string, ok bool) {
	oldID, err := storage.IPSWCacheIdentity(oldInfo)
	if err != nil {
		return "", "", false
	}
	newID, err = storage.IPSWCacheIdentity(newInfo)
	if err != nil {
		return "", "", false
	}
	return oldID, newID, true
}

// taskScope builds the storage.Scope for a CacheableTask from the old/new
// IPSW Info structs the orchestrator is driving. ok is false when the cache
// identities cannot be derived (OTA/Directory modes, or any IPSW missing a
// BuildManifest); the caller then treats the task as non-cacheable for the
// run and walks it fresh.
//
// IpswOld/IpswNew come from storage.IPSWCacheIdentity. Task/TaskVersion/
// OptionsHash/InputHash come from the task itself so every output-affecting
// option and every task-scope input digest contributes to the cache key.
func taskScope(oldInfo, newInfo *info.Info, t CacheableTask) (storage.Scope, bool) {
	oldID, newID, ok := cacheIdentities(oldInfo, newInfo)
	if !ok {
		return storage.Scope{}, false
	}
	return taskScopeWithIDs(oldID, newID, t), true
}

// taskScopeWithIDs builds the Scope from already-derived identities so the
// orchestrator hashes each BuildManifest once per run instead of once per
// task.
func taskScopeWithIDs(oldID, newID string, t CacheableTask) storage.Scope {
	return storage.Scope{
		IpswOld:     oldID,
		IpswNew:     newID,
		Task:        t.Name(),
		TaskVersion: t.Version(),
		OptionsHash: t.OptionsHash(),
		InputHash:   t.InputHash(),
	}
}

// cacheLifecycle tracks the per-run cache state for the volume-major
// orchestrator: which CacheableTasks have a derivable scope, which ones were
// hydrated from a completed cache (and therefore skip the volume walk), and
// which ones recorded an error (and therefore must not be marked complete).
type cacheLifecycle struct {
	// scopes maps task name -> resolved scope for every CacheableTask whose
	// identity is derivable. Tasks absent here are non-cacheable for the run.
	scopes map[string]storage.Scope
	// tasks maps task name -> the CacheableTask, used to call persistTo on a
	// fresh-walk success.
	tasks map[string]CacheableTask
	// hydrated names the tasks loaded from a completed cache; they are
	// excluded from the volume walk and finalize.
	hydrated map[string]bool
	// errored names tasks that failed any step and must not be marked complete.
	errored map[string]bool
}

// newCacheLifecycle resolves scopes for every CacheableTask, queries the
// store's completion sentinel, and hydrates the hits. A task whose identity
// is underivable (OTA/Directory, missing BuildManifest) is treated as
// non-cacheable and always walks fresh. A hit whose Hydrate fails is logged
// and treated as a miss so the task re-runs rather than serving partial state.
func newCacheLifecycle(oldInfo, newInfo *info.Info, jobs []Task, store storage.Store) *cacheLifecycle {
	lc := &cacheLifecycle{
		scopes:   make(map[string]storage.Scope),
		tasks:    make(map[string]CacheableTask),
		hydrated: make(map[string]bool),
		errored:  make(map[string]bool),
	}
	// Derive the per-IPSW identities once: they hash the full BuildManifest
	// and are identical for every task. Underivable identities (OTA or
	// Directory inputs) make every task non-cacheable for the run.
	oldID, newID, idOK := cacheIdentities(oldInfo, newInfo)
	if !idOK {
		return lc
	}
	for _, job := range jobs {
		ct, ok := job.(CacheableTask)
		if !ok {
			continue
		}
		scope := taskScopeWithIDs(oldID, newID, ct)
		lc.scopes[ct.Name()] = scope
		lc.tasks[ct.Name()] = ct

		done, err := store.Complete(scope)
		if err != nil {
			log.WithError(err).Warnf("cache: completion check failed for %s; running fresh", ct.Name())
			continue
		}
		if !done {
			continue
		}
		if err := ct.Hydrate(scope, store); err != nil {
			log.WithError(err).Warnf("cache: hydrate failed for %s; running fresh", ct.Name())
			continue
		}
		lc.hydrated[ct.Name()] = true
		utils.Indent(log.Info, 2)(fmt.Sprintf("Reusing cached %s (inputs and options unchanged)", ct.Name()))
	}
	return lc
}

// isHydrated reports whether the task was loaded from a completed cache.
func (lc *cacheLifecycle) isHydrated(t Task) bool { return lc.hydrated[t.Name()] }

// excludeHydrated drops hydrated tasks from a per-volume job slice so they
// skip BeginVolume/MachoHandler/EndVolume/ProcessVolume entirely.
func (lc *cacheLifecycle) excludeHydrated(jobs []Task) []Task {
	if len(lc.hydrated) == 0 {
		return jobs
	}
	out := make([]Task, 0, len(jobs))
	for _, j := range jobs {
		if lc.hydrated[j.Name()] {
			continue
		}
		out = append(out, j)
	}
	return out
}

// markErrored records the named tasks as failed so persistAndComplete skips
// their completion sentinel.
func (lc *cacheLifecycle) markErrored(names map[string]bool) {
	for name, bad := range names {
		if bad {
			lc.errored[name] = true
		}
	}
}

// persistAndComplete writes the result rows for every freshly-walked
// CacheableTask (not hydrated, not errored) via its persistTo method, then
// records the completion sentinel. Hydrated tasks are skipped because their
// rows already exist; errored tasks are skipped so a stale result is never
// served on the next run. A persistTo failure suppresses MarkComplete for
// that task only, so MarkComplete never stamps a scope with no rows behind it.
func (lc *cacheLifecycle) persistAndComplete(store storage.Store) {
	for name, scope := range lc.scopes {
		if lc.hydrated[name] || lc.errored[name] {
			continue
		}
		if err := lc.tasks[name].persistTo(scope, store); err != nil {
			log.WithError(err).Warnf("cache: persist failed for %s; not marking complete", name)
			continue
		}
		if err := store.MarkComplete(scope); err != nil {
			log.WithError(err).Warnf("cache: MarkComplete failed for %s", name)
		}
	}
}
