package pipeline

import (
	"sync"
	"time"
)

// MachoMetadata represents all data extracted from a single MachO file.
//
// This data is extracted once during the cache population phase and reused
// by multiple handlers (MachO handler, Entitlements handler, etc.) to avoid
// redundant file parsing.
type MachoMetadata struct {
	// Identity
	Path    string // Full path to the MachO file
	UUID    string // MachO UUID for identification
	Version string // Version string if available
	Size    int64  // File size in bytes

	// MachO Analysis Data
	Sections     []SectionInfo // Section names and sizes
	Symbols      []string      // Symbol names
	CStrings     []string      // C strings (optional, memory-intensive)
	Functions    int           // Function count
	LoadCommands []string      // Load command types

	// Entitlements Data
	Entitlements string // XML entitlements from code signature

	// Metadata
	ParseError error     // If parsing failed, error is stored here
	ParsedAt   time.Time // When this file was parsed
}

// SectionInfo represents a MachO section's basic information.
type SectionInfo struct {
	Name string // Section name (e.g., "__text", "__data")
	Size uint64 // Section size in bytes
}

// MachoCache is a thread-safe cache holding all parsed MachO metadata.
//
// Populated once during the cache scan phase, then read concurrently by
// multiple handlers without additional file I/O.
type MachoCache struct {
	data map[string]*MachoMetadata // path -> metadata
	mu   sync.RWMutex               // Thread-safe access
}

// NewMachoCache creates a new empty MachO cache.
func NewMachoCache() *MachoCache {
	return &MachoCache{
		data: make(map[string]*MachoMetadata),
	}
}

// Get retrieves metadata for the given path.
// Returns nil, false if the path is not in the cache.
func (c *MachoCache) Get(path string) (*MachoMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	md, ok := c.data[path]
	return md, ok
}

// Set stores metadata for the given path.
func (c *MachoCache) Set(path string, md *MachoMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[path] = md
}

// All returns all cached metadata.
// Returns a copy of the internal map to prevent concurrent modification.
func (c *MachoCache) All() map[string]*MachoMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to prevent concurrent modification issues
	result := make(map[string]*MachoMetadata, len(c.data))
	for k, v := range c.data {
		result[k] = v
	}
	return result
}

// Len returns the number of cached entries.
func (c *MachoCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

// Keys returns all cached file paths.
func (c *MachoCache) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.data))
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}

// HasErrors returns true if any cached file had parsing errors.
func (c *MachoCache) HasErrors() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, md := range c.data {
		if md.ParseError != nil {
			return true
		}
	}
	return false
}

// ErrorCount returns the number of files that failed to parse.
func (c *MachoCache) ErrorCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, md := range c.data {
		if md.ParseError != nil {
			count++
		}
	}
	return count
}
