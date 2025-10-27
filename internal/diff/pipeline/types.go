package pipeline

import (
	"fmt"
	"sync"
	"time"

	"github.com/blacktop/ipsw/pkg/info"
)

// Config holds configuration flags for diff operations.
// This maps to the CLI flags and controls which handlers are enabled.
type Config struct {
	// Feature flags
	LaunchD      bool
	Firmware     bool
	Features     bool
	Files        bool
	CStrings     bool
	FuncStarts   bool
	Entitlements bool

	// Filter lists
	AllowList []string
	BlockList []string

	// External resources
	PemDB      string
	Signatures string

	// Output settings
	Output  string
	Verbose bool

	// Profiling settings
	Profile    bool   // Enable flight recorder profiling
	ProfileDir string // Profile output directory
	MemProfile bool   // Enable memory profiling
}

// Context represents the state for one IPSW being diffed (either old or new).
// It holds metadata about the IPSW and tracks which DMGs are currently mounted.
type Context struct {
	IPSWPath string
	Info     *info.Info
	Version  string
	Build    string
	Folder   string // temp extraction folder

	// Mount tracking per DMG type
	Mounts map[DMGType]*Mount

	// MachO cache - populated once, read by multiple handlers
	MachoCache *MachoCache

	// Derived paths
	KDK string

	mu sync.RWMutex
}

// Mount holds information about a mounted DMG.
type Mount struct {
	DMGPath   string  // Path to the DMG file (may be decrypted from .aea)
	MountPath string  // Where the DMG is mounted
	IsMounted bool    // Whether we mounted it (vs already mounted)
	Type      DMGType // Type of DMG
	Managed   bool    // Whether the pipeline created/extracted this DMG
}

// GetMount safely retrieves a mount by type.
func (c *Context) GetMount(dmgType DMGType) (*Mount, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	mount, ok := c.Mounts[dmgType]
	return mount, ok
}

// SetMount safely sets a mount by type.
func (c *Context) SetMount(dmgType DMGType, mount *Mount) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Mounts[dmgType] = mount
}

// ExecutionStats tracks pipeline execution metrics.
type ExecutionStats struct {
	StartTime       time.Time
	EndTime         time.Time
	HandlersRun     int
	HandlersSkipped int
	Errors          []error
	Warnings        []error

	// Cache metrics
	CachePopulated    bool          // Whether cache population ran
	CachePopulateTime time.Duration // Time spent populating caches
	OldCacheSize      int           // Number of files in old cache
	NewCacheSize      int           // Number of files in new cache
	OldCacheErrors    int           // Parse errors in old cache
	NewCacheErrors    int           // Parse errors in new cache

	// Per-handler performance metrics
	HandlerTimes map[string]time.Duration // Execution time per handler

	// DMG mount/unmount metrics
	MountCount   int           // Total number of mount operations
	UnmountCount int           // Total number of unmount operations
	MountTime    time.Duration // Total time spent mounting DMGs
	UnmountTime  time.Duration // Total time spent unmounting DMGs

	// Memory metrics
	StartMemory uint64 // Memory in use at start (bytes)
	EndMemory   uint64 // Memory in use at end (bytes)
	PeakMemory  uint64 // Peak memory usage (bytes)

	// GC metrics
	TotalGCPause time.Duration // Total GC pause time
	NumGC        uint32        // Number of GC runs
}

// Duration returns the total execution time.
func (s *ExecutionStats) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// Summary returns a formatted string with execution statistics.
func (s *ExecutionStats) Summary() string {
	var summary string
	summary += fmt.Sprintf("Execution time: %s\n", s.Duration())
	summary += fmt.Sprintf("Handlers run: %d, skipped: %d\n", s.HandlersRun, s.HandlersSkipped)

	// Cache metrics
	if s.CachePopulated {
		summary += fmt.Sprintf("Cache populated: %d + %d files in %s\n",
			s.OldCacheSize, s.NewCacheSize, s.CachePopulateTime)
		if s.OldCacheErrors > 0 || s.NewCacheErrors > 0 {
			summary += fmt.Sprintf("Cache errors: %d + %d\n", s.OldCacheErrors, s.NewCacheErrors)
		}
	}

	// Per-handler timing (if verbose)
	if len(s.HandlerTimes) > 0 {
		summary += fmt.Sprintf("\nHandler execution times:\n")
		for name, dur := range s.HandlerTimes {
			summary += fmt.Sprintf("  %s: %s\n", name, dur)
		}
	}

	// DMG operations
	if s.MountCount > 0 || s.UnmountCount > 0 {
		summary += fmt.Sprintf("\nDMG operations:\n")
		summary += fmt.Sprintf("  Mounts: %d (total time: %s)\n", s.MountCount, s.MountTime)
		summary += fmt.Sprintf("  Unmounts: %d (total time: %s)\n", s.UnmountCount, s.UnmountTime)
	}

	// Memory metrics
	if s.StartMemory > 0 {
		summary += fmt.Sprintf("\nMemory usage:\n")
		summary += fmt.Sprintf("  Start: %s\n", formatBytes(s.StartMemory))
		summary += fmt.Sprintf("  End: %s\n", formatBytes(s.EndMemory))
		summary += fmt.Sprintf("  Peak: %s\n", formatBytes(s.PeakMemory))
		if s.EndMemory > s.StartMemory {
			summary += fmt.Sprintf("  Delta: +%s\n", formatBytes(s.EndMemory-s.StartMemory))
		} else {
			summary += fmt.Sprintf("  Delta: -%s\n", formatBytes(s.StartMemory-s.EndMemory))
		}
	}

	// GC metrics
	if s.NumGC > 0 {
		summary += fmt.Sprintf("\nGarbage collection:\n")
		summary += fmt.Sprintf("  Runs: %d\n", s.NumGC)
		summary += fmt.Sprintf("  Total pause: %s\n", s.TotalGCPause)
		avgPause := time.Duration(int64(s.TotalGCPause) / int64(s.NumGC))
		summary += fmt.Sprintf("  Avg pause: %s\n", avgPause)
	}

	// Errors and warnings
	if len(s.Errors) > 0 {
		summary += fmt.Sprintf("\nErrors: %d\n", len(s.Errors))
	}
	if len(s.Warnings) > 0 {
		summary += fmt.Sprintf("Warnings: %d\n", len(s.Warnings))
	}

	return summary
}

// formatBytes returns a human-readable byte count.
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// HandlerGroup groups handlers by their DMG requirements.
// All handlers in a group can run concurrently since they need the same DMGs.
type HandlerGroup struct {
	DMGTypes []DMGType
	Handlers []Handler
}
