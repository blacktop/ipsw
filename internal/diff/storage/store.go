// Package storage defines the pluggable backing store used by diff Tasks to
// persist per-key state across runs. Implementations (in-memory, SQLite) live
// in sibling files; this file holds only the contract.
package storage

// Scope identifies the unique cache namespace for a single Task's output on a
// specific (old, new) IPSW pair. Every field contributes to cache identity:
// changing the task version, options, or input fingerprint invalidates prior
// rows under the same (IpswOld, IpswNew, Task) tuple without colliding with
// older entries that other consumers may still be reading.
type Scope struct {
	IpswOld     string
	IpswNew     string
	Task        string
	TaskVersion int
	OptionsHash string
	// InputHash is the task-scope input-set fingerprint, e.g. relevant
	// DMG or kernelcache pair digest.
	InputHash string
}

// Store is the backing key/value persistence used by CacheableTask
// implementations. Keys are scoped by Scope so two tasks (or two versions of
// the same task) cannot collide. Implementations must be safe for concurrent
// readers; writers may be serialized by the implementation.
type Store interface {
	// Put stores v under (scope, key). Implementations encode v with gob.
	Put(scope Scope, key string, v any) error
	// Get loads the value at (scope, key) into v. found is false when no
	// row exists; err is non-nil only on real storage errors.
	Get(scope Scope, key string, v any) (found bool, err error)
	// Iter calls fn for every row in scope. fn receives the row key and a
	// decode callback that copies the row's gob-encoded payload into the
	// caller-supplied destination (typically a pointer to the task's row
	// struct). The callback may only be invoked during the fn call;
	// implementations are free to invalidate the underlying buffer after
	// fn returns. Returning an error from fn (or from the decode callback)
	// stops iteration.
	Iter(scope Scope, fn func(key string, decode func(v any) error) error) error
	// MarkComplete records that every row required by the task at scope has
	// been written. Callers must only invoke this after all per-row Put
	// calls, EndVolume hooks, top-level Parse, and any Finalize have all
	// succeeded.
	MarkComplete(scope Scope) error
	// Complete reports whether MarkComplete was previously recorded for
	// scope. A true result is the only signal that the orchestrator may
	// skip work and call CacheableTask.Hydrate instead.
	Complete(scope Scope) (bool, error)
	// Close releases any resources held by the store.
	Close() error
}
