package pipeline

import (
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
}

// Duration returns the total execution time.
func (s *ExecutionStats) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// HandlerGroup groups handlers by their DMG requirements.
// All handlers in a group can run concurrently since they need the same DMGs.
type HandlerGroup struct {
	DMGTypes []DMGType
	Handlers []Handler
}
