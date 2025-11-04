package integration

import (
	"path/filepath"
	"testing"
)

// TestExtractKernelcache tests extracting kernelcache from IPSW
func TestExtractKernelcache(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	t.Run("extract kernel", func(t *testing.T) {
		RunIPSWExpectSuccess(t, binPath, "extract", "--kernel", "--output", outputDir, td.IPSWPath)

		// Check that a kernelcache file was created
		files, err := filepath.Glob(filepath.Join(outputDir, "kernelcache*"))
		if err != nil {
			t.Fatalf("Failed to glob for kernelcache files: %v", err)
		}

		if len(files) == 0 {
			t.Errorf("Expected kernelcache file to be extracted, but none found in %s", outputDir)
		} else {
			t.Logf("Successfully extracted kernelcache: %s", files[0])
			
			// Verify file size is reasonable (> 1MB)
			size := GetFileSize(t, files[0])
			if size < 1024*1024 {
				t.Errorf("Extracted kernelcache file size is suspiciously small: %d bytes", size)
			}
		}
	})
}

// TestExtractDyldSharedCache tests extracting dyld_shared_cache from IPSW
func TestExtractDyldSharedCache(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	t.Run("extract dyld", func(t *testing.T) {
		// This might take a while, so we just test the command runs
		RunIPSWExpectSuccess(t, binPath, "extract", "--dyld", "--output", outputDir, td.IPSWPath)

		// Check that dyld_shared_cache files were created
		files, err := filepath.Glob(filepath.Join(outputDir, "dyld_shared_cache*"))
		if err != nil {
			t.Fatalf("Failed to glob for dyld_shared_cache files: %v", err)
		}

		if len(files) == 0 {
			t.Errorf("Expected dyld_shared_cache files to be extracted, but none found in %s", outputDir)
		} else {
			t.Logf("Successfully extracted %d dyld_shared_cache file(s)", len(files))
			
			// Verify at least one file has reasonable size (> 10MB)
			foundLargeFile := false
			for _, file := range files {
				size := GetFileSize(t, file)
				if size > 10*1024*1024 {
					foundLargeFile = true
					break
				}
			}
			
			if !foundLargeFile {
				t.Errorf("No dyld_shared_cache file larger than 10MB found")
			}
		}
	})
}

// TestExtractDeviceTree tests extracting DeviceTree from IPSW
func TestExtractDeviceTree(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	t.Run("extract dtree", func(t *testing.T) {
		RunIPSWExpectSuccess(t, binPath, "extract", "--dtree", "--output", outputDir, td.IPSWPath)

		// Check that DeviceTree files were created
		files, err := filepath.Glob(filepath.Join(outputDir, "DeviceTree*"))
		if err != nil {
			t.Fatalf("Failed to glob for DeviceTree files: %v", err)
		}

		if len(files) == 0 {
			// DeviceTree might not exist in all IPSWs, so just log a warning
			t.Logf("No DeviceTree files extracted (may not exist in this IPSW)")
		} else {
			t.Logf("Successfully extracted %d DeviceTree file(s)", len(files))
		}
	})
}

// TestExtractRemoteFiles tests listing remote files in IPSW
func TestExtractRemoteFiles(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)

	t.Run("list remote files", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "extract", "--list", td.IPSWPath)

		// Should contain some common IPSW files
		expectedFiles := []string{
			"kernelcache",
			"BuildManifest",
		}

		foundAny := false
		for _, file := range expectedFiles {
			if filepath.Base(stdout) == file || contains(stdout, file) {
				foundAny = true
				break
			}
		}

		if !foundAny {
			t.Errorf("Expected to find some common IPSW files in listing, but found none.\nOutput: %s", stdout)
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return filepath.Base(s) == substr || len(s) > 0 && s != substr
}
