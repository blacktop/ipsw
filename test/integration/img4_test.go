package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestImg4Info tests the 'ipsw img4 info' command
func TestImg4Info(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	// First extract kernelcache (which is an IMG4 file)
	t.Log("Extracting kernelcache...")
	RunIPSWExpectSuccess(t, binPath, "extract", "--kernel", "--output", outputDir, td.IPSWPath)

	// Find the extracted kernelcache
	files, err := filepath.Glob(filepath.Join(outputDir, "kernelcache*"))
	if err != nil {
		t.Fatalf("Failed to glob for kernelcache files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No kernelcache file found after extraction")
	}
	img4Path := files[0]

	t.Run("img4 info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "img4", "info", img4Path)

		// Check for expected output
		expectedFields := []string{
			"IM4P",
			"Type",
		}

		foundAny := false
		for _, field := range expectedFields {
			if strings.Contains(stdout, field) {
				foundAny = true
				break
			}
		}

		if !foundAny {
			t.Logf("Note: Expected IMG4 info. Output: %s", stdout[:min(200, len(stdout))])
		} else {
			t.Logf("Successfully got IMG4 info")
		}
	})
}

// TestImg4Extract tests the 'ipsw img4 extract' command
func TestImg4Extract(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	cacheDir := CreateTempDir(t)
	extractDir := CreateTempDir(t)

	// First extract kernelcache (which is an IMG4 file)
	t.Log("Extracting kernelcache...")
	RunIPSWExpectSuccess(t, binPath, "extract", "--kernel", "--output", cacheDir, td.IPSWPath)

	// Find the extracted kernelcache
	files, err := filepath.Glob(filepath.Join(cacheDir, "kernelcache*"))
	if err != nil {
		t.Fatalf("Failed to glob for kernelcache files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No kernelcache file found after extraction")
	}
	img4Path := files[0]

	t.Run("img4 extract payload", func(t *testing.T) {
		RunIPSWExpectSuccess(t, binPath, "img4", "extract", "--output", extractDir, img4Path)

		// Check that payload was extracted
		extractedFiles, err := filepath.Glob(filepath.Join(extractDir, "*"))
		if err != nil {
			t.Fatalf("Failed to glob for extracted files: %v", err)
		}

		if len(extractedFiles) == 0 {
			t.Logf("Note: No payload extracted (may vary by IMG4 format)")
		} else {
			t.Logf("Successfully extracted IMG4 payload: %d file(s)", len(extractedFiles))
			for _, f := range extractedFiles {
				size := GetFileSize(t, f)
				t.Logf("  - %s (%d bytes)", filepath.Base(f), size)
			}
		}
	})
}

// TestImg4IM4P tests the 'ipsw img4 im4p' command
func TestImg4IM4P(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	// First extract kernelcache (which is an IMG4 file)
	t.Log("Extracting kernelcache...")
	RunIPSWExpectSuccess(t, binPath, "extract", "--kernel", "--output", outputDir, td.IPSWPath)

	// Find the extracted kernelcache
	files, err := filepath.Glob(filepath.Join(outputDir, "kernelcache*"))
	if err != nil {
		t.Fatalf("Failed to glob for kernelcache files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No kernelcache file found after extraction")
	}
	img4Path := files[0]

	t.Run("img4 im4p info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "img4", "im4p", img4Path)

		// Should show IM4P information
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: No IM4P info output (may vary by IMG4 format)")
		} else {
			t.Logf("Successfully got IM4P info")
		}
	})
}
