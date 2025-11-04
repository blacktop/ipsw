package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// TestData manages test data paths and availability
type TestData struct {
	// IPSWPath is the path to a test IPSW file
	IPSWPath string
	// OTAPath is the path to a test OTA file
	OTAPath string
	// MacOSIPSWPath is the path to a macOS IPSW file
	MacOSIPSWPath string
	// CacheDir is where test artifacts can be cached
	CacheDir string
}

// GetTestData returns test data configuration from environment variables
func GetTestData(t *testing.T) *TestData {
	td := &TestData{
		IPSWPath:      os.Getenv("IPSW_TEST_IPSW"),
		OTAPath:       os.Getenv("IPSW_TEST_OTA"),
		MacOSIPSWPath: os.Getenv("IPSW_TEST_MACOS"),
		CacheDir:      os.Getenv("IPSW_TEST_CACHE"),
	}

	// Use default cache dir if not specified
	if td.CacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Logf("Warning: could not determine home directory: %v", err)
			td.CacheDir = filepath.Join(os.TempDir(), "ipsw-test-cache")
		} else {
			td.CacheDir = filepath.Join(home, ".cache", "ipsw-test")
		}
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(td.CacheDir, 0755); err != nil {
		t.Logf("Warning: could not create cache directory %s: %v", td.CacheDir, err)
	}

	return td
}

// HasIPSW returns true if an iOS IPSW file is available for testing
func (td *TestData) HasIPSW() bool {
	return td.IPSWPath != "" && fileExists(td.IPSWPath)
}

// HasOTA returns true if an OTA file is available for testing
func (td *TestData) HasOTA() bool {
	return td.OTAPath != "" && fileExists(td.OTAPath)
}

// HasMacOSIPSW returns true if a macOS IPSW file is available for testing
func (td *TestData) HasMacOSIPSW() bool {
	return td.MacOSIPSWPath != "" && fileExists(td.MacOSIPSWPath)
}

// SkipIfNoIPSW skips the test if no iOS IPSW is available
func (td *TestData) SkipIfNoIPSW(t *testing.T) {
	if !td.HasIPSW() {
		t.Skip("Skipping test: no iOS IPSW available. Set IPSW_TEST_IPSW environment variable to enable.")
	}
}

// SkipIfNoOTA skips the test if no OTA is available
func (td *TestData) SkipIfNoOTA(t *testing.T) {
	if !td.HasOTA() {
		t.Skip("Skipping test: no OTA available. Set IPSW_TEST_OTA environment variable to enable.")
	}
}

// SkipIfNoMacOSIPSW skips the test if no macOS IPSW is available
func (td *TestData) SkipIfNoMacOSIPSW(t *testing.T) {
	if !td.HasMacOSIPSW() {
		t.Skip("Skipping test: no macOS IPSW available. Set IPSW_TEST_MACOS environment variable to enable.")
	}
}

// fileExists checks if a file exists and is not a directory
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
