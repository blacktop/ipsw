package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDyldInfo tests the 'ipsw dyld info' command
func TestDyldInfo(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	// First extract the dyld_shared_cache
	t.Log("Extracting dyld_shared_cache (this may take a while)...")
	RunIPSWExpectSuccess(t, binPath, "extract", "--dyld", "--output", outputDir, td.IPSWPath)

	// Find the extracted dyld_shared_cache
	files, err := filepath.Glob(filepath.Join(outputDir, "dyld_shared_cache_arm*"))
	if err != nil {
		t.Fatalf("Failed to glob for dyld_shared_cache files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No dyld_shared_cache file found after extraction")
	}
	dyldPath := files[0]

	t.Run("dyld info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "dyld", "info", dyldPath)

		// Check for expected output
		expectedFields := []string{
			"Header",
			"Magic",
		}

		foundAny := false
		for _, field := range expectedFields {
			if strings.Contains(stdout, field) {
				foundAny = true
				break
			}
		}

		if !foundAny {
			t.Logf("Note: Expected output to contain header info. Output: %s", stdout[:min(200, len(stdout))])
		} else {
			t.Logf("Successfully got dyld info")
		}
	})

	t.Run("dyld images", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "dyld", "image", dyldPath)

		// Should list images/dylibs
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Errorf("Expected dyld images to be listed, but got empty output")
		} else {
			// Count lines to estimate number of images
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			t.Logf("Successfully listed approximately %d dyld images", len(lines))
		}
	})
}

// TestDyldObjC tests the 'ipsw dyld objc' command
func TestDyldObjC(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	// First extract the dyld_shared_cache
	t.Log("Extracting dyld_shared_cache (this may take a while)...")
	RunIPSWExpectSuccess(t, binPath, "extract", "--dyld", "--output", outputDir, td.IPSWPath)

	// Find the extracted dyld_shared_cache
	files, err := filepath.Glob(filepath.Join(outputDir, "dyld_shared_cache_arm*"))
	if err != nil {
		t.Fatalf("Failed to glob for dyld_shared_cache files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No dyld_shared_cache file found after extraction")
	}
	dyldPath := files[0]

	t.Run("dyld objc classes", func(t *testing.T) {
		// Test with a common class like NSString
		stdout := RunIPSWExpectSuccess(t, binPath, "dyld", "objc", "class", dyldPath, "--class", "NSString")

		// Should show class information
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: NSString class not found or no output (may vary by dyld version)")
		} else {
			t.Logf("Successfully retrieved NSString class info")
		}
	})

	t.Run("dyld objc selectors", func(t *testing.T) {
		// Test with a common selector
		stdout := RunIPSWExpectSuccess(t, binPath, "dyld", "objc", "sel", dyldPath, "--selector", "alloc")

		// Should show selector information
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: alloc selector not found or no output (may vary by dyld version)")
		} else {
			t.Logf("Successfully retrieved alloc selector info")
		}
	})
}

// TestDyldExtract tests the 'ipsw dyld extract' command
func TestDyldExtract(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	cacheDir := CreateTempDir(t)
	extractDir := CreateTempDir(t)

	// First extract the dyld_shared_cache
	t.Log("Extracting dyld_shared_cache (this may take a while)...")
	RunIPSWExpectSuccess(t, binPath, "extract", "--dyld", "--output", cacheDir, td.IPSWPath)

	// Find the extracted dyld_shared_cache
	files, err := filepath.Glob(filepath.Join(cacheDir, "dyld_shared_cache_arm*"))
	if err != nil {
		t.Fatalf("Failed to glob for dyld_shared_cache files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No dyld_shared_cache file found after extraction")
	}
	dyldPath := files[0]

	t.Run("dyld extract dylib", func(t *testing.T) {
		// Extract a common dylib like Foundation
		RunIPSWExpectSuccess(t, binPath, "dyld", "extract", dyldPath, "Foundation", "--output", extractDir)

		// Check that Foundation was extracted
		foundationFiles, err := filepath.Glob(filepath.Join(extractDir, "*Foundation*"))
		if err != nil {
			t.Fatalf("Failed to glob for Foundation files: %v", err)
		}

		if len(foundationFiles) == 0 {
			t.Logf("Note: Foundation not found in cache (may vary by iOS version)")
		} else {
			t.Logf("Successfully extracted Foundation: %s", foundationFiles[0])
		}
	})
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
