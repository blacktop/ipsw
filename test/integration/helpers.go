package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// BuildIPSW builds the ipsw binary and returns the path to it
func BuildIPSW(t *testing.T) string {
	t.Helper()

	// Build the binary
	binPath := filepath.Join(t.TempDir(), "ipsw")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/ipsw")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build ipsw binary: %v\nOutput: %s", err, output)
	}

	return binPath
}

// RunIPSW runs the ipsw binary with the given arguments
func RunIPSW(t *testing.T, binPath string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binPath, args...)
	
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("Failed to run ipsw: %v", err)
		}
	}

	return stdout, stderr, exitCode
}

// RunIPSWExpectSuccess runs ipsw and expects it to succeed
func RunIPSWExpectSuccess(t *testing.T, binPath string, args ...string) string {
	t.Helper()

	stdout, stderr, exitCode := RunIPSW(t, binPath, args...)
	if exitCode != 0 {
		t.Fatalf("ipsw command failed with exit code %d\nArgs: %v\nStdout: %s\nStderr: %s",
			exitCode, args, stdout, stderr)
	}

	return stdout
}

// CreateTempDir creates a temporary directory for test output
func CreateTempDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	return dir
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// FileContains checks if a file contains the given substring
func FileContains(t *testing.T, path string, substr string) bool {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}

	return strings.Contains(string(data), substr)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(t *testing.T, path string) int64 {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Failed to stat file %s: %v", path, err)
	}

	return info.Size()
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
