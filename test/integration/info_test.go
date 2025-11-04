package integration

import (
	"strings"
	"testing"
)

// TestInfoCommand tests the 'ipsw info' command
func TestInfoCommand(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoIPSW(t)

	binPath := BuildIPSW(t)

	t.Run("basic info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "info", td.IPSWPath)

		// Check for expected info fields
		expectedFields := []string{
			"Version",
			"Build",
			"Device",
		}

		for _, field := range expectedFields {
			if !strings.Contains(stdout, field) {
				t.Errorf("Expected output to contain %q, but it didn't.\nOutput: %s", field, stdout)
			}
		}
	})

	t.Run("json output", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "info", "--json", td.IPSWPath)

		// Check that output is valid JSON by looking for typical JSON structure
		if !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
			t.Errorf("Expected JSON output to start with '{', but got: %s", stdout[:Min(100, len(stdout))])
		}

		// Check for expected JSON fields
		expectedFields := []string{
			"\"version\"",
			"\"build\"",
		}

		for _, field := range expectedFields {
			if !strings.Contains(stdout, field) {
				t.Errorf("Expected JSON output to contain %q, but it didn't.\nOutput: %s", field, stdout)
			}
		}
	})
}

// TestInfoOTACommand tests the 'ipsw info' command on OTA files
func TestInfoOTACommand(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoOTA(t)

	binPath := BuildIPSW(t)

	t.Run("ota info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "info", td.OTAPath)

		// Check for expected info fields
		expectedFields := []string{
			"Version",
			"Build",
		}

		for _, field := range expectedFields {
			if !strings.Contains(stdout, field) {
				t.Errorf("Expected output to contain %q, but it didn't.\nOutput: %s", field, stdout)
			}
		}
	})
}

// TestInfoMacOSCommand tests the 'ipsw info' command on macOS IPSWs
func TestInfoMacOSCommand(t *testing.T) {
	td := GetTestData(t)
	td.SkipIfNoMacOSIPSW(t)

	binPath := BuildIPSW(t)

	t.Run("macos info", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "info", td.MacOSIPSWPath)

		// Check for expected info fields
		expectedFields := []string{
			"Version",
			"Build",
		}

		for _, field := range expectedFields {
			if !strings.Contains(stdout, field) {
				t.Errorf("Expected output to contain %q, but it didn't.\nOutput: %s", field, stdout)
			}
		}
	})
}
