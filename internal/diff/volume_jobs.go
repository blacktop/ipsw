package diff

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

// runIPSWVolumePhases drives the volume-major loop for IPSW mode. See
// runVolumeJobsAcrossSessions for the per-volume orchestration logic; this
// method is the entry point that wires in the concrete Diff state.
//
// When d.store is non-nil (the CLI path that wires up --cache-dir /
// --no-cache) the orchestrator reuses that store so every task in the run
// shares one backend. When nil, a MemoryStore is allocated for the duration
// of the call and closed after finalize; that preserves the test/OTA paths
// that never need cross-run persistence.
func (d *Diff) runIPSWVolumePhases(jobs []Task) error {
	store, cleanup := d.acquireStore()
	if cleanup != nil {
		defer cleanup()
	}
	return runVolumeJobsAcrossSessions(
		d.Old.Info,
		d.New.Info,
		d.oldSession,
		d.newSession,
		func(typ string) bool { return d.ipswVolumeUnchanged(typ) },
		jobs,
		store,
	)
}

// acquireStore returns the cache backend the orchestrator should use, plus
// an optional cleanup hook. When the CLI installed a shared store via
// SetStore the cleanup is a no-op so the same store survives across the
// volume-major and top-level passes; otherwise an ephemeral MemoryStore is
// allocated and closed on return.
func (d *Diff) acquireStore() (storage.Store, func()) {
	if d.store != nil {
		return d.store, nil
	}
	store := storage.NewMemoryStore()
	return store, func() {
		if err := store.Close(); err != nil {
			log.WithError(err).Warn("failed to close diff store")
		}
	}
}

// runVolumeJobsAcrossSessions executes the volume-major loop. It is the
// pure orchestration helper that runIPSWVolumePhases delegates to; tests
// pass fake sessions and a fake "is volume unchanged" oracle to exercise
// the loop without real mounts.
//
// For each volume type in ipswVolumeOrderMachos it:
//
//  1. Filters jobs to those that need the volume.
//  2. Skips when no job wants it or neither side resolves it.
//  3. Skips when the per-volume short-circuit reports the digests match.
//  4. Mounts both sides, fans MachoWalkTasks out via a single shared
//     [search.ForEachMachoInMountMulti] per side, then runs the
//     remaining MountTasks sequentially.
//  5. Releases the volume pair (release fires even on scan error).
//
// After the loop, Finalize is called on every job (whether it processed any
// volume or not). Errors are logged per-stage and execution continues so a
// failure in one job does not poison the others.
func runVolumeJobsAcrossSessions(
	oldInfo, newInfo *info.Info,
	oldSession, newSession ipswVolumeFileSession,
	volumeUnchanged func(typ string) bool,
	jobs []Task,
	store storage.Store,
) error {
	if len(jobs) == 0 {
		return nil
	}

	// A task whose Setup fails is dropped for the whole run: it never sees a
	// volume and is not finalized. Running a half-initialized task produces
	// garbage (e.g. machosJob with an empty cacheDir writes its per-binary
	// cache into a relative path in the CWD; filesJob emits partial output).
	jobs = setupTasks(jobs, store)

	// Cache lifecycle: resolve each CacheableTask's scope, hydrate the ones
	// whose exact (task, version, options, inputs) tuple is already complete
	// in the store, and track per-task errors so a task that fails any step
	// is never marked complete. Hydrated tasks skip the volume walk entirely.
	lc := newCacheLifecycle(oldInfo, newInfo, jobs, store)

	for _, typ := range ipswVolumeOrderMachos {
		active := filterJobsByVolume(jobs, typ)
		active = lc.excludeHydrated(active)
		if len(active) == 0 {
			continue
		}

		oldPresent := volumeResolves(oldInfo, typ)
		newPresent := volumeResolves(newInfo, typ)
		if !oldPresent && !newPresent {
			continue
		}

		if volumeUnchanged != nil && volumeUnchanged(typ) {
			utils.Indent(log.Info, 2)(fmt.Sprintf("Skipping %s volume (DMG digest unchanged)", volumeLabel(typ)))
			continue
		}

		errs, errored := processVolumePair(typ, oldPresent, newPresent, oldSession, newSession, active)
		lc.markErrored(errored)
		if errs != nil {
			log.WithError(errs).Errorf("failed to process %s volume", volumeLabel(typ))
		}
	}

	// Finalize runs for EVERY task, hydrated or not. A freshly-walked task
	// folds its per-volume scan state here; a hydrated task takes its
	// Finalize hydrate-branch and publishes the cached result to the Diff
	// (e.g. machosJob.Finalize sets j.d.Machos = j.hydrated). Skipping
	// Finalize for hydrated tasks would leave their Diff field at the zero
	// value, serving empty output on every cache hit.
	for _, job := range jobs {
		if err := finalizeTask(job); err != nil {
			lc.markErrored(map[string]bool{job.Name(): true})
			log.WithError(err).Errorf("failed to finalize %s job", job.Name())
		}
	}

	// Persist freshly-walked cacheable tasks and stamp their completion
	// sentinel. Hydrated tasks already have their rows and completion sentinel
	// in the store, so persistAndComplete skips them; tasks with any recorded
	// error are skipped so a stale result is never served.
	lc.persistAndComplete(store)
	return nil
}

// setupTasks runs each task's setup hook and returns only the tasks that
// initialized successfully. A task whose Setup errors is logged and dropped
// from the run so it never processes a volume or finalizes with partial state.
// Tasks with no setup hook pass through unchanged.
func setupTasks(jobs []Task, store storage.Store) []Task {
	out := make([]Task, 0, len(jobs))
	for _, job := range jobs {
		if s, ok := job.(TaskSetup); ok {
			if err := s.Setup(store); err != nil {
				log.WithError(err).Errorf("disabling %s job: setup failed", job.Name())
				continue
			}
		}
		out = append(out, job)
	}
	return out
}

// finalizeTask dispatches Finalize to whichever per-volume interface the
// Task satisfies. MountTask and MachoWalkTask both declare Finalize
// separately so we type-assert to the matching surface.
func finalizeTask(t Task) error {
	if mw, ok := t.(MachoWalkTask); ok {
		return mw.Finalize()
	}
	if mt, ok := t.(MountTask); ok {
		return mt.Finalize()
	}
	return nil
}

func filterJobsByVolume(jobs []Task, typ string) []Task {
	out := make([]Task, 0, len(jobs))
	for _, j := range jobs {
		if taskNeedsVolume(j, typ) {
			out = append(out, j)
		}
	}
	return out
}

// taskNeedsVolume reports whether a Task wants the given volume type by
// dispatching through the richer per-volume interfaces. A Task that
// implements neither MountTask nor MachoWalkTask never sees a volume.
func taskNeedsVolume(t Task, typ string) bool {
	if mw, ok := t.(MachoWalkTask); ok {
		return mw.Needs(typ)
	}
	if mt, ok := t.(MountTask); ok {
		return mt.Needs(typ)
	}
	return false
}

// processVolumePair mounts the requested volume on both sides, runs the
// MachoWalkTask fan-out plus any remaining MountTasks, then releases the
// pair. Release fires even when a task errors so we never leak a mount.
//
// The returned errored set names the tasks whose work for this volume failed
// (mount, scan, or per-volume hook). The orchestrator uses it to keep those
// tasks from being marked complete in the cache. A mount failure poisons
// every active task for the volume because none of them saw the data.
func processVolumePair(
	typ string,
	oldPresent, newPresent bool,
	oldSession, newSession ipswVolumeFileSession,
	jobs []Task,
) (error, map[string]bool) {
	utils.Indent(log.Info, 2)(fmt.Sprintf("Scanning %s volume", volumeLabel(typ)))

	errored := make(map[string]bool)

	var roots volumeRoots
	var mountErrs []error
	if oldPresent {
		if oldSession == nil {
			mountErrs = append(mountErrs, fmt.Errorf("Old IPSW mount session is not initialized"))
		} else if r, err := oldSession.Root(typ); err != nil {
			mountErrs = append(mountErrs, fmt.Errorf("failed to mount Old %s volume: %w", typ, err))
		} else {
			roots.old = r
		}
	}
	if newPresent {
		if newSession == nil {
			mountErrs = append(mountErrs, fmt.Errorf("New IPSW mount session is not initialized"))
		} else if r, err := newSession.Root(typ); err != nil {
			mountErrs = append(mountErrs, fmt.Errorf("failed to mount New %s volume: %w", typ, err))
		} else {
			roots.new = r
		}
	}

	// Session-fallback mounts for absent sides: when an active
	// SessionFallbackTask wants this volume, ask the session to resolve the
	// missing side itself (mount.Session.Root("sys") falls back to the
	// filesystem DMG on pre-cryptex IPSWs). The fallback root is handed only
	// to tasks that asked for it; a fallback mount failure is logged and the
	// requesting task errors downstream on the empty root. releaseVolumePair
	// releases typ on both sessions, covering these mounts too.
	if len(mountErrs) == 0 && sessionFallbackWanted(jobs, typ) {
		if !oldPresent && oldSession != nil {
			if r, err := oldSession.Root(typ); err != nil {
				log.WithError(err).Warnf("failed to mount Old %s fallback volume", typ)
			} else {
				roots.oldFallback = r
			}
		}
		if !newPresent && newSession != nil {
			if r, err := newSession.Root(typ); err != nil {
				log.WithError(err).Warnf("failed to mount New %s fallback volume", typ)
			} else {
				roots.newFallback = r
			}
		}
	}

	var scanErrs []error
	if len(mountErrs) == 0 {
		scanErrs = runVolumeTasks(typ, roots, jobs)
		for _, err := range scanErrs {
			if name, ok := taskNameFromError(err); ok {
				errored[name] = true
			}
		}
	} else {
		// No task processed the volume, so every active task is incomplete.
		for _, j := range jobs {
			errored[j.Name()] = true
		}
	}

	releaseErr := releaseVolumePair(typ, oldSession, newSession)

	return errors.Join(errors.Join(mountErrs...), errors.Join(scanErrs...), releaseErr), errored
}

// volumeRoots carries the mounted roots for one volume pass. old/new are the
// strict per-volume mounts (empty when the side lacks the volume);
// oldFallback/newFallback are session-resolved roots for absent sides,
// populated only when an active [SessionFallbackTask] asked for them and
// handed only to such tasks.
type volumeRoots struct {
	old, new                 string
	oldFallback, newFallback string
}

// sessionFallbackWanted reports whether any active job wants the session-
// resolved fallback root for absent sides of this volume.
func sessionFallbackWanted(jobs []Task, typ string) bool {
	for _, j := range jobs {
		if f, ok := j.(SessionFallbackTask); ok && f.WantsSessionFallback(typ) {
			return true
		}
	}
	return false
}

// runVolumeTasks dispatches MachoWalkTasks via a single shared Mach-O walk
// per side, then runs any remaining MountTasks sequentially. A task that
// implements both interfaces is treated as a MachoWalkTask. Tasks that
// fail during the shared walk are disabled across both sides of the
// current volume so the new-side closure never sees a half-populated
// old-side state.
func runVolumeTasks(typ string, roots volumeRoots, jobs []Task) []error {
	var errs []error

	var machoTasks []MachoWalkTask
	var mountTasks []MountTask
	for _, j := range jobs {
		if mw, ok := j.(MachoWalkTask); ok {
			machoTasks = append(machoTasks, mw)
			continue
		}
		if mt, ok := j.(MountTask); ok {
			mountTasks = append(mountTasks, mt)
			continue
		}
		log.Warnf("%s job is neither MachoWalkTask nor MountTask; skipping", j.Name())
	}

	// Track which MachoWalkTasks are disabled for this volume. A disable
	// from the old-side walk also suppresses the new-side handler and the
	// EndVolume hook to avoid mixing partial state.
	disabled := make(map[string]bool, len(machoTasks))
	machoByName := make(map[string]MachoWalkTask, len(machoTasks))
	for _, mw := range machoTasks {
		machoByName[mw.Name()] = mw
	}

	for _, mw := range machoTasks {
		if err := mw.BeginVolume(typ); err != nil {
			disabled[mw.Name()] = true
			abortMachoVolume(mw, typ)
			errs = append(errs, fmt.Errorf("%s: BeginVolume(%s): %w", mw.Name(), typ, err))
		}
	}

	runSide := func(root string, side Side) {
		if root == "" {
			return
		}
		// Normalize the walk root so APFS-FUSE mounts (Linux) descend into
		// <mount>/root, matching the path keys the legacy entsJob and other
		// utils.MountedFilesystemRoot-aware callers produced.
		walkRoot := utils.MountedFilesystemRoot(root)
		handlers := make([]search.NamedMachoScanHandler, 0, len(machoTasks))
		for _, mw := range machoTasks {
			if disabled[mw.Name()] {
				continue
			}
			h := mw.MachoHandler(typ, side)
			if h == nil {
				continue
			}
			handlers = append(handlers, search.NamedMachoScanHandler{
				Task:   mw.Name(),
				Handle: h,
			})
		}
		if len(handlers) == 0 {
			return
		}
		if err := search.ForEachMachoInMountMulti(walkRoot, handlers); err != nil {
			for _, perTask := range splitJoinedErrors(err) {
				if name, ok := taskNameFromError(perTask); ok {
					disabled[name] = true
					if mw, ok := machoByName[name]; ok {
						abortMachoVolume(mw, typ)
					}
					// Keep the task name as the leading prefix so the
					// orchestrator can attribute the failure back to the
					// task (and skip its cache completion sentinel).
					errs = append(errs, fmt.Errorf("%s: %s mount %s: %w", name, side, walkRoot, perTask))
					continue
				}
				errs = append(errs, fmt.Errorf("%s mount %s: %w", side, walkRoot, perTask))
			}
		}
	}
	runSide(roots.old, SideOld)
	runSide(roots.new, SideNew)

	for _, mw := range machoTasks {
		if disabled[mw.Name()] {
			continue
		}
		if err := mw.EndVolume(typ); err != nil {
			errs = append(errs, fmt.Errorf("%s: EndVolume(%s): %w", mw.Name(), typ, err))
		}
	}

	for _, mt := range mountTasks {
		oldRoot, newRoot := roots.old, roots.new
		if f, ok := mt.(SessionFallbackTask); ok && f.WantsSessionFallback(typ) {
			if oldRoot == "" {
				oldRoot = roots.oldFallback
			}
			if newRoot == "" {
				newRoot = roots.newFallback
			}
		}
		if err := mt.ProcessVolume(typ, oldRoot, newRoot); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", mt.Name(), err))
		}
	}
	return errs
}

func abortMachoVolume(mw MachoWalkTask, typ string) {
	if aborter, ok := mw.(MachoVolumeAborter); ok {
		aborter.AbortVolume(typ)
	}
}

// splitJoinedErrors flattens an [errors.Join] result back into its
// constituent errors so per-task attribution survives a join.
func splitJoinedErrors(err error) []error {
	type joined interface{ Unwrap() []error }
	if j, ok := err.(joined); ok {
		out := j.Unwrap()
		if len(out) > 0 {
			return out
		}
	}
	return []error{err}
}

// taskNameFromError extracts the task-name prefix that
// [search.ForEachMachoInMountMulti] uses to attribute per-handler
// failures, so the orchestrator can mark the task disabled across the
// remainder of this volume.
func taskNameFromError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 {
		name := msg[:i]
		if name == "" || name == "__walk__" {
			return "", false
		}
		return name, true
	}
	return "", false
}

func releaseVolumePair(typ string, oldSession, newSession ipswVolumeFileSession) error {
	var errs []error
	if oldSession != nil {
		if err := oldSession.Release(typ); err != nil {
			errs = append(errs, fmt.Errorf("failed to release Old %s volume: %w", typ, err))
		}
	}
	if newSession != nil {
		if err := newSession.Release(typ); err != nil {
			errs = append(errs, fmt.Errorf("failed to release New %s volume: %w", typ, err))
		}
	}
	return errors.Join(errs...)
}

// runTopLevelTasks invokes Parse on each top-level task that opts in via
// the registered filter. A MemoryStore is allocated for the duration of
// the call and closed afterward, providing the same [TaskSetup] surface
// mount-based jobs receive. Errors are logged per-task and the loop
// continues so a single failure does not poison sibling tasks.
//
// The cache lifecycle mirrors runVolumeJobsAcrossSessions exactly: after
// setup, resolve each CacheableTask's scope and hydrate the hits; a hydrated
// task has its result published by Hydrate, so its Parse is skipped. Fresh
// tasks Parse, then persistAndComplete writes their rows and stamps the
// completion sentinel. A fully-cached warm rerun therefore runs ZERO Parse
// work for every cacheable top-level task.
//
// Top-level tasks (kexts / kdks / firmwares / iboot / sandbox) run BEFORE
// the volume-major orchestrator today because the kernelcache parse
// produces state (Kernel.Path, sameKernel) that the sandbox task and the
// mount-based jobs may consult. The future shape (post-cache landing)
// moves them after MountTask Finalize per the migration plan.
func (d *Diff) runTopLevelTasks(ctx context.Context, tasks []TopLevelTask) error {
	if len(tasks) == 0 {
		return nil
	}
	store, cleanup := d.acquireStore()
	if cleanup != nil {
		defer cleanup()
	}

	for _, t := range tasks {
		if s, ok := t.(TaskSetup); ok {
			if err := s.Setup(store); err != nil {
				log.WithError(err).Errorf("failed to set up %s task", t.Name())
			}
		}
	}

	// Cache lifecycle: resolve each CacheableTask's scope, hydrate the ones
	// whose exact (task, version, options, inputs) tuple is already complete
	// in the store, and track per-task errors so a task that fails any step is
	// never marked complete. Hydrated tasks have their result published by
	// Hydrate, so their Parse is skipped entirely.
	lc := newCacheLifecycle(d.Old.Info, d.New.Info, topLevelTasksAsTaskSlice(tasks), store)

	for _, t := range tasks {
		if lc.isHydrated(t) {
			continue
		}
		if err := t.Parse(ctx, d); err != nil {
			lc.markErrored(map[string]bool{t.Name(): true})
			log.WithError(err).Errorf("failed to parse %s", t.Name())
		}
	}

	// Persist freshly-parsed cacheable tasks and stamp their completion
	// sentinel. Hydrated tasks already have their rows and sentinel; tasks with
	// any recorded error are skipped so a stale result is never served.
	lc.persistAndComplete(store)

	for _, t := range tasks {
		if c, ok := t.(TaskCleanup); ok {
			if err := c.Cleanup(); err != nil {
				log.WithError(err).Warnf("failed to clean up %s task", t.Name())
			}
		}
	}
	return nil
}

// topLevelTasksAsTaskSlice widens a []TopLevelTask to the []Task the
// volume-agnostic cache lifecycle consumes. Every TopLevelTask embeds Task,
// so the conversion is a straight copy.
func topLevelTasksAsTaskSlice(tasks []TopLevelTask) []Task {
	out := make([]Task, len(tasks))
	for i, t := range tasks {
		out[i] = t
	}
	return out
}
