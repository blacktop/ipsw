package diff

import (
	"context"
	"html/template"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/internal/search"
)

// Side identifies which IPSW (old or new) a Mach-O handler is being invoked
// against during the shared per-volume walk.
type Side string

const (
	SideOld Side = "old"
	SideNew Side = "new"
)

// HTMLFragment is the per-Task contribution to the final HTML report. Body
// uses html/template so renderers may compose pre-escaped fragments without
// re-escaping them at the outer template level.
type HTMLFragment struct {
	Heading string
	Body    template.HTML
}

// MachoScanHandler is invoked once per Mach-O encountered during a shared
// per-volume walk. The same (path, *macho.File) is fed to every registered
// handler before the next binary is opened.
//
// The type is defined in internal/search so that ForEachMachoInMountMulti
// can fan handlers out without a cyclic dependency on internal/diff. Diff
// re-exports the alias here so task implementations read naturally.
type MachoScanHandler = search.MachoScanHandler

// Task is the minimal contract every diff dimension implements: a stable
// identifier used for logs, cache scoping, and ordering. Specialized
// behaviors (rendering, caching, per-volume work) are layered via the
// optional interfaces below.
//
// Report rendering is intentionally not modeled as an interface here. Each
// section is rendered by a small per-section renderer (jobs_*.go) or
// TopLevelTask (tasks_*.go) that exposes Markdown/HTML/JSON/JSONKey/Empty
// methods; buildReport duck-types them through the narrow reportContributor
// interface in report.go, and md.go / format.go call the concrete renderers
// directly. The renderers and the TopLevelTasks deliberately keep distinct
// shapes (the renderers are not Tasks), so a single shared RenderTask
// interface would not unify them.
type Task interface {
	// Name returns the stable cache and log identifier for this task.
	Name() string
}

// CacheableTask is implemented by tasks that participate in idempotent
// reruns. The orchestrator consults Version/OptionsHash/InputHash to build a
// storage.Scope, queries the store's completion sentinel, and on a hit calls
// Hydrate to rebuild render/report state before any rendering occurs. On a
// miss it calls persistTo after a successful fresh walk and only then
// MarkComplete(scope).
//
// Hydrate (load) and persistTo (store) are inverses and both are required:
// a task that could be marked complete without writing its rows would leave
// an empty completed scope that hydrates to bogus empty output on the next
// run. Keeping both on one interface makes that state unrepresentable.
type CacheableTask interface {
	Task
	// Version is bumped when the cache payload layout or output semantics
	// change in a way that invalidates prior runs.
	Version() int
	// OptionsHash digests every output-affecting option (allow/block
	// lists, verbosity, task-specific flags).
	OptionsHash() string
	// InputHash digests the task-scope old/new input set (e.g. relevant
	// DMG or kernelcache pair digest).
	InputHash() string
	// Hydrate rebuilds render/report state from a cache hit so the task
	// can render without re-running ProcessVolume or Parse.
	Hydrate(scope storage.Scope, store storage.Store) error
	// persistTo writes the task's final result rows under scope. It runs
	// only after a successful fresh walk + Finalize and before MarkComplete.
	persistTo(scope storage.Scope, store storage.Store) error
}

// MountTask is the subset of Task that needs per-volume mount roots.
type MountTask interface {
	Task
	// Needs reports whether this task wants the given volume type
	// ("fs", "sys", "app", "exc").
	Needs(typ string) bool
	// ProcessVolume runs once per applicable volume after both sides are
	// mounted. Implementations scan both roots, store per-volume diff
	// results internally, and release raw scan data before returning.
	ProcessVolume(typ, oldRoot, newRoot string) error
	// Finalize is called once after every applicable volume has been
	// processed (or skipped). Implementations aggregate per-volume
	// results into the final shape consumers expect.
	Finalize() error
}

// MachoWalkTask is a mount-scoped Task that participates in the shared
// per-volume Mach-O walk. The orchestrator collects handlers from every
// active task and feeds each Mach-O to all of them before moving on.
type MachoWalkTask interface {
	Task
	// Needs reports whether this task wants the given volume type.
	Needs(typ string) bool
	// BeginVolume initializes per-volume state or cache buckets.
	BeginVolume(typ string) error
	// MachoHandler returns the handler that consumes Mach-Os for the
	// given volume and side. Returning nil opts out of that side for
	// this volume.
	MachoHandler(typ string, side Side) MachoScanHandler
	// EndVolume runs after both sides have been walked; tasks perform
	// fold/removal checks here.
	EndVolume(typ string) error
	// Finalize is called once after every volume has been processed.
	Finalize() error
}

// MachoVolumeAborter is optionally implemented by [MachoWalkTask]s that keep
// per-volume state which must be discarded after a handler failure. The
// orchestrator calls it before suppressing the task's EndVolume hook.
type MachoVolumeAborter interface {
	AbortVolume(typ string)
}

// SessionFallbackTask is optionally implemented by [MountTask]s whose absent
// side should still receive a root resolved by the mount session itself.
// mount.Session.Root("sys") falls back to the filesystem DMG on pre-cryptex
// IPSWs — exactly where the DSC lives on those builds — while the strict
// per-volume resolver (volumeResolves) deliberately has no such fallback
// because the walk-based jobs must not re-scan filesystem content under the
// SystemOS label. The orchestrator hands the session-resolved fallback root
// ONLY to tasks implementing this interface; every other active job still
// sees the absent side as an empty root.
type SessionFallbackTask interface {
	// WantsSessionFallback reports whether the task wants the session-
	// resolved root for a side whose typ is absent per the strict resolver.
	WantsSessionFallback(typ string) bool
}

// TopLevelTask runs after all mounts have closed and needs no per-volume
// state. Kexts, KDKs, firmwares, iBoot, and sandbox parse here.
type TopLevelTask interface {
	Task
	// Parse runs the task against the fully populated Diff. ctx allows
	// cancellation of long-running parse work.
	Parse(ctx context.Context, d *Diff) error
}

// TaskSetup is the optional storage-aware setup hook.
type TaskSetup interface {
	// Setup runs before the volume loop starts and receives the chosen
	// store backend.
	Setup(store storage.Store) error
}

// TaskCleanup is implemented by tasks that need to release resources after
// the full diff completes (regardless of success or error).
type TaskCleanup interface {
	// Cleanup releases task-owned resources.
	Cleanup() error
}
