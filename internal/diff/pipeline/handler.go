// Package pipeline implements a modular, concurrent pipeline architecture for IPSW diffing.
//
// The pipeline groups diff operations (handlers) by their DMG requirements, mounts each DMG type
// once, runs all handlers that need it concurrently, then unmounts. This minimizes expensive
// mount/unmount operations and maximizes parallelism.
package pipeline

import (
	"context"
	"errors"
)

// DMGType represents the category of DMG required for a handler.
type DMGType int

const (
	// DMGTypeNone indicates no DMG mounting is required (IPSW-direct operations).
	// Handlers with this type work directly with the IPSW zip file.
	DMGTypeNone DMGType = iota

	// DMGTypeSystemOS is the primary system OS DMG containing dyld_shared_cache,
	// system frameworks, and core system files.
	DMGTypeSystemOS

	// DMGTypeAppOS is the application OS DMG.
	DMGTypeAppOS

	// DMGTypeFileSystem is the generic filesystem DMG.
	DMGTypeFileSystem

	// DMGTypeExclave is the exclave-related DMG.
	DMGTypeExclave
)

// String returns the human-readable name of the DMG type.
func (d DMGType) String() string {
	return [...]string{
		"None",
		"SystemOS",
		"AppOS",
		"FileSystem",
		"Exclave",
	}[d]
}

// Handler defines the interface for diff operations.
//
// Each handler is responsible for a specific diff task (e.g., DSC, MachO, launchd).
// Handlers declare their dependencies (DMG types) and are executed by the pipeline
// when those dependencies are available.
//
// Handlers should be stateless and reusable. All state should be passed via the
// Executor or stored in the returned Result.
type Handler interface {
	// Name returns the human-readable name of this handler.
	// Used for logging and error messages.
	Name() string

	// DMGTypes returns the types of DMGs this handler needs mounted.
	// Handlers returning DMGTypeNone work directly with IPSW files.
	// Handlers can require multiple DMG types if needed.
	DMGTypes() []DMGType

	// Enabled returns whether this handler should run based on configuration.
	// This allows handlers to be conditionally executed via CLI flags.
	Enabled(cfg *Config) bool

	// Execute performs the diff operation using the provided context.
	//
	// The executor provides access to both old and new IPSW contexts,
	// mounted DMGs, configuration, and temporary directories.
	//
	// Returns a Result containing the handler's output, or an error if
	// the operation fails fatally. Non-fatal issues should be returned
	// as warnings in the Result.
	//
	// The context may be canceled if the user interrupts execution.
	// Handlers should respect context cancellation.
	Execute(ctx context.Context, exec *Executor) (*Result, error)
}

// Result represents the output of a handler execution.
type Result struct {
	// HandlerName identifies which handler produced this result.
	HandlerName string

	// Data contains handler-specific output. The executor doesn't interpret this;
	// it's passed through to the aggregator or renderer.
	//
	// Common types:
	//   - *mcmd.MachoDiff for MachO/DSC/Kext diffs
	//   - string for text-based diffs
	//   - *PlistDiff for plist comparisons
	//   - *IBootDiff for iBoot string diffs
	Data any

	// Warnings are non-fatal issues encountered during execution.
	// These are logged but don't stop the handler from completing.
	Warnings []error

	// Metadata provides additional context (execution time, file counts, etc.).
	// This can be used for debugging, logging, or statistics.
	Metadata map[string]any
}

// HandlerFunc is an adapter to allow ordinary functions to be used as Handlers.
// This enables simple handlers without defining full types.
//
// Example:
//
//	handler := NewHandlerFunc(
//	    "Quick Diff",
//	    []DMGType{DMGTypeNone},
//	    func(cfg *Config) bool { return true },
//	    func(ctx context.Context, e *Executor) (*Result, error) {
//	        // diff logic here
//	        return &Result{HandlerName: "Quick Diff", Data: "..."}, nil
//	    },
//	)
type HandlerFunc struct {
	name        string
	dmgTypes    []DMGType
	enabled     func(*Config) bool
	executeFunc func(context.Context, *Executor) (*Result, error)
}

func (h *HandlerFunc) Name() string        { return h.name }
func (h *HandlerFunc) DMGTypes() []DMGType { return h.dmgTypes }
func (h *HandlerFunc) Enabled(cfg *Config) bool {
	if h.enabled == nil {
		return true
	}
	return h.enabled(cfg)
}
func (h *HandlerFunc) Execute(ctx context.Context, e *Executor) (*Result, error) {
	return h.executeFunc(ctx, e)
}

// NewHandlerFunc creates a Handler from a function.
// If enabled is nil, the handler is always enabled.
func NewHandlerFunc(
	name string,
	dmgTypes []DMGType,
	enabled func(*Config) bool,
	execute func(context.Context, *Executor) (*Result, error),
) Handler {
	return &HandlerFunc{
		name:        name,
		dmgTypes:    dmgTypes,
		enabled:     enabled,
		executeFunc: execute,
	}
}

var (
	// ErrHandlerFailed indicates a handler encountered a fatal error.
	ErrHandlerFailed = errors.New("handler failed")

	// ErrDMGMountFailed indicates DMG mounting failed.
	ErrDMGMountFailed = errors.New("DMG mount failed")

	// ErrContextCanceled indicates the context was canceled.
	ErrContextCanceled = errors.New("context canceled")
)
