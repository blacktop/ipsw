package search

import (
	"errors"
	"fmt"

	"github.com/blacktop/go-macho"
)

// MachoScanHandler is invoked once per Mach-O encountered during a shared
// per-volume walk. The same (path, *macho.File) is fed to every registered
// handler before the next binary is opened.
type MachoScanHandler func(path string, m *macho.File) error

// NamedMachoScanHandler binds a [MachoScanHandler] to a stable task name so
// the orchestrator can attribute per-handler errors back to the registering
// task without forcing every caller to wrap closures by hand.
type NamedMachoScanHandler struct {
	// Task is the stable task identifier used for error attribution and
	// per-walk disable bookkeeping.
	Task string
	// Handle is the per-Mach-O callback. A nil Handle is treated as
	// "this task does not participate in the current walk" and is
	// silently skipped.
	Handle MachoScanHandler
}

// ForEachMachoInMountMulti walks root exactly like [ForEachMachoInMount]
// and dispatches each opened Mach-O to every registered handler in
// registration order before opening the next binary. This lets independent
// jobs (e.g. machos+ents) share one filesystem walk and one Mach-O open
// per file instead of paying that cost per task.
//
// Error handling is per-task: a handler that returns an error is
// recorded against its task name and disabled for the remainder of THIS
// walk. Other handlers keep receiving subsequent Mach-Os. The returned
// error is a [errors.Join] of per-task errors, each prefixed with the
// task name. The caller is responsible for translating those errors into
// cross-side / cross-volume disable state.
func ForEachMachoInMountMulti(root string, handlers []NamedMachoScanHandler) error {
	if len(handlers) == 0 {
		return nil
	}
	// disabled[i] mirrors handlers[i] so we never reorder caller-visible
	// state mid-walk.
	disabled := make([]bool, len(handlers))
	taskErrs := make(map[string]error, len(handlers))
	order := make([]string, 0, len(handlers))
	recordErr := func(idx int, err error) {
		name := handlers[idx].Task
		if _, ok := taskErrs[name]; !ok {
			order = append(order, name)
		}
		taskErrs[name] = fmt.Errorf("%s: %w", name, err)
		disabled[idx] = true
	}

	walkErr := ForEachMachoInMount(root, func(path string, m *macho.File) error {
		for i := range handlers {
			if disabled[i] || handlers[i].Handle == nil {
				continue
			}
			if err := handlers[i].Handle(path, m); err != nil {
				recordErr(i, err)
			}
		}
		return nil
	})
	if walkErr != nil {
		// A walker-level error is fatal for the whole walk; attribute it
		// to no specific task so the caller can decide whether to keep
		// going on the next volume.
		taskErrs["__walk__"] = fmt.Errorf("walk: %w", walkErr)
		order = append(order, "__walk__")
	}

	if len(taskErrs) == 0 {
		return nil
	}
	joined := make([]error, 0, len(order))
	for _, name := range order {
		joined = append(joined, taskErrs[name])
	}
	return errors.Join(joined...)
}
