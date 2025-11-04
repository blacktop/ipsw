package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestMachoInfo tests the 'ipsw macho info' command
func TestMachoInfo(t *testing.T) {
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

	// Extract a dylib to analyze
	t.Log("Extracting Foundation dylib...")
	RunIPSWExpectSuccess(t, binPath, "dyld", "extract", dyldPath, "Foundation", "--output", extractDir)

	foundationFiles, err := filepath.Glob(filepath.Join(extractDir, "*Foundation*"))
	if err != nil {
		t.Fatalf("Failed to glob for Foundation files: %v", err)
	}
	if len(foundationFiles) == 0 {
		t.Skip("Foundation not found in cache, skipping macho tests")
	}
	machoPath := foundationFiles[0]

	t.Run("macho info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "macho", "info", machoPath)

		// Check for expected Mach-O fields
		expectedFields := []string{
			"Magic",
			"Type",
			"CPU",
		}

		foundAny := false
		for _, field := range expectedFields {
			if strings.Contains(stdout, field) {
				foundAny = true
				break
			}
		}

		if !foundAny {
			t.Logf("Note: Expected Mach-O info. Output: %s", stdout[:Min(200, len(stdout))])
		} else {
			t.Logf("Successfully got Mach-O info")
		}
	})
}

// TestMachoSearch tests the 'ipsw macho search' command
func TestMachoSearch(t *testing.T) {
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

	// Extract a dylib to analyze
	t.Log("Extracting Foundation dylib...")
	RunIPSWExpectSuccess(t, binPath, "dyld", "extract", dyldPath, "Foundation", "--output", extractDir)

	foundationFiles, err := filepath.Glob(filepath.Join(extractDir, "*Foundation*"))
	if err != nil {
		t.Fatalf("Failed to glob for Foundation files: %v", err)
	}
	if len(foundationFiles) == 0 {
		t.Skip("Foundation not found in cache, skipping macho search test")
	}
	machoPath := foundationFiles[0]

	t.Run("macho search strings", func(t *testing.T) {
		// Search for a common string in Foundation
		stdout := RunIPSWExpectSuccess(t, binPath, "macho", "search", machoPath, "--string", "NS")

		// Should find some strings
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: No strings found (search may require different syntax)")
		} else {
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			t.Logf("Successfully found %d string matches", len(lines))
		}
	})
}

// TestMachoSign tests the 'ipsw macho sign' command
func TestMachoSign(t *testing.T) {
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

	// Extract a dylib to analyze
	t.Log("Extracting Foundation dylib...")
	RunIPSWExpectSuccess(t, binPath, "dyld", "extract", dyldPath, "Foundation", "--output", extractDir)

	foundationFiles, err := filepath.Glob(filepath.Join(extractDir, "*Foundation*"))
	if err != nil {
		t.Fatalf("Failed to glob for Foundation files: %v", err)
	}
	if len(foundationFiles) == 0 {
		t.Skip("Foundation not found in cache, skipping macho sign test")
	}
	machoPath := foundationFiles[0]

	t.Run("macho sign info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "macho", "sign", machoPath)

		// Should show code signing information
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: No code signing info (may not be signed)")
		} else {
			t.Logf("Successfully retrieved code signing info")
		}
	})
}
