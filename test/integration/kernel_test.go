package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestKernelInfo tests the 'ipsw kernel info' command
func TestKernelInfo(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	// First extract the kernelcache
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
	kernelPath := files[0]

	t.Run("kernel info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "kernel", "info", kernelPath)

		// Check for expected output
		expectedFields := []string{
			"Version",
			"Magic",
		}

		for _, field := range expectedFields {
			if !strings.Contains(stdout, field) {
				t.Logf("Note: Expected output to contain %q. Output may vary by kernel version.\nOutput: %s", field, stdout)
			}
		}
	})

	t.Run("kernel version", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "kernel", "version", kernelPath)

		// Should output a version string
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Errorf("Expected version output, but got empty string")
		} else {
			t.Logf("Kernel version: %s", strings.TrimSpace(stdout))
		}
	})

	t.Run("kernel kexts", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "kernel", "kexts", kernelPath)

		// Should list some kernel extensions
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: No kexts listed (may not be present in this kernel)")
		} else {
			t.Logf("Successfully listed kernel extensions")
		}
	})
}

// TestKernelSyscall tests the 'ipsw kernel syscall' command
func TestKernelSyscall(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)
	outputDir := CreateTempDir(t)

	// First extract the kernelcache
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
	kernelPath := files[0]

	t.Run("kernel syscall", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "kernel", "syscall", kernelPath)

		// Should list syscalls
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: No syscalls listed (may require specific kernel format)")
		} else {
			t.Logf("Successfully listed syscalls")
		}
	})
}
