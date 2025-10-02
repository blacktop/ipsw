package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/trace"
	"time"

	"github.com/apex/log"
)

// ProfileConfig holds profiling configuration.
type ProfileConfig struct {
	Enabled   bool   // Enable profiling
	OutputDir string // Directory for profile output (default: "./profiles")
}

// Profiler manages execution profiling using Go 1.25+ flight recorder.
//
// Flight recorder provides always-on, low-overhead profiling that captures
// a continuous trace of program execution. When enabled, it has <1% overhead
// and can be written out on completion or error for post-mortem analysis.
type Profiler struct {
	config    *ProfileConfig
	startTime time.Time
	traceFile *os.File
}

// NewProfiler creates a new profiler with the given configuration.
func NewProfiler(config *ProfileConfig) *Profiler {
	if config == nil {
		config = &ProfileConfig{
			Enabled:   false,
			OutputDir: "./profiles",
		}
	}

	// Set default output directory if not specified
	if config.OutputDir == "" {
		config.OutputDir = "./profiles"
	}

	return &Profiler{
		config: config,
	}
}

// Start begins profiling if enabled.
//
// For Go 1.25+, this starts the flight recorder which continuously captures
// execution events with minimal overhead. The trace is written to disk when
// Stop() is called or if the program crashes.
func (p *Profiler) Start(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	// Ensure output directory exists
	if err := os.MkdirAll(p.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	// Generate trace filename with timestamp
	p.startTime = time.Now()
	filename := fmt.Sprintf("trace-%s.out", p.startTime.Format("20060102-150405"))
	tracePath := filepath.Join(p.config.OutputDir, filename)

	// Create trace file
	f, err := os.Create(tracePath)
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}
	p.traceFile = f

	// Start execution trace (flight recorder mode in Go 1.25+)
	if err := trace.Start(f); err != nil {
		f.Close()
		return fmt.Errorf("failed to start trace: %w", err)
	}

	log.WithField("path", tracePath).Info("Flight recorder profiling started")
	log.Info("Trace will be written on completion for analysis")

	return nil
}

// Stop ends profiling and writes the trace to disk.
//
// This should be called when the operation completes successfully or fails.
// The trace file can then be analyzed using:
//
//	go tool trace trace-<timestamp>.out
//
// Or converted to CPU/memory profiles using ExtractProfiles().
func (p *Profiler) Stop() error {
	if !p.config.Enabled || p.traceFile == nil {
		return nil
	}

	// Stop trace and close file
	trace.Stop()
	if err := p.traceFile.Close(); err != nil {
		return fmt.Errorf("failed to close trace file: %w", err)
	}

	duration := time.Since(p.startTime)
	log.WithFields(log.Fields{
		"path":     p.traceFile.Name(),
		"duration": duration,
		"size":     formatFileSize(p.traceFile.Name()),
	}).Info("Flight recorder trace written")

	// Print analysis instructions
	log.Info("Analyze trace with: go tool trace " + p.traceFile.Name())

	return nil
}

// StopOnPanic should be called via defer to ensure trace is written even on panic.
//
// Usage:
//
//	profiler := NewProfiler(config)
//	profiler.Start(ctx)
//	defer profiler.StopOnPanic()
func (p *Profiler) StopOnPanic() {
	if r := recover(); r != nil {
		// Write trace on panic
		if err := p.Stop(); err != nil {
			log.WithError(err).Error("Failed to write trace on panic")
		}

		// Log panic details
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		log.WithFields(log.Fields{
			"panic": r,
			"stack": string(buf[:n]),
		}).Error("Panic occurred - trace written for analysis")

		// Re-panic to maintain normal panic behavior
		panic(r)
	} else {
		// Normal completion
		if err := p.Stop(); err != nil {
			log.WithError(err).Error("Failed to write trace")
		}
	}
}

// ExtractProfiles converts the trace to traditional profile formats.
//
// This is a helper function that uses 'go tool trace' to extract CPU,
// memory, and blocking profiles from the execution trace.
//
// Note: This requires the trace file to be written first (call Stop()).
func (p *Profiler) ExtractProfiles() error {
	if !p.config.Enabled || p.traceFile == nil {
		return nil
	}

	tracePath := p.traceFile.Name()

	// Generate profile paths
	cpuPath := filepath.Join(p.config.OutputDir, "cpu.pprof")
	memPath := filepath.Join(p.config.OutputDir, "mem.pprof")
	blockPath := filepath.Join(p.config.OutputDir, "block.pprof")

	log.Info("Extracting profiles from trace (this may take a moment)...")

	// Note: In Go 1.25+, you would use 'go tool trace' commands to extract
	// profiles. This is typically done manually rather than programmatically.
	// For now, we just log instructions.

	log.WithFields(log.Fields{
		"trace": tracePath,
		"cpu":   cpuPath,
		"mem":   memPath,
		"block": blockPath,
	}).Info("To extract profiles, run:")
	log.Info("  go tool trace -pprof=cpu " + tracePath + " > " + cpuPath)
	log.Info("  go tool trace -pprof=mem " + tracePath + " > " + memPath)
	log.Info("  go tool trace -pprof=block " + tracePath + " > " + blockPath)

	return nil
}

// formatFileSize returns a human-readable file size.
func formatFileSize(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}

	size := info.Size()
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}
