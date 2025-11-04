package integration

import (
	"strings"
	"testing"
)

// TestDiffCommand tests the 'ipsw diff' command
// Note: This test requires two IPSW files to compare
func TestDiffCommand(t *testing.T) {
	// Get test data
	td := GetTestData(t)
	
	// Check if we have at least two different firmware files to compare
	var file1, file2 string
	hasTwo := false
	
	if td.HasIPSW() && td.HasOTA() {
		file1 = td.IPSWPath
		file2 = td.OTAPath
		hasTwo = true
	} else if td.HasIPSW() && td.HasMacOSIPSW() {
		file1 = td.IPSWPath
		file2 = td.MacOSIPSWPath
		hasTwo = true
	} else if td.HasOTA() && td.HasMacOSIPSW() {
		file1 = td.OTAPath
		file2 = td.MacOSIPSWPath
		hasTwo = true
	}
	
	if !hasTwo {
		t.Skip("Skipping diff test: need at least two firmware files. Set IPSW_TEST_IPSW and IPSW_TEST_OTA (or IPSW_TEST_MACOS) to enable.")
	}

	binPath := BuildIPSW(t)

	t.Run("basic diff", func(t *testing.T) {
		stdout := RunIPSWExpectSuccess(t, binPath, "diff", file1, file2)

		// The diff command should produce some output
		if len(strings.TrimSpace(stdout)) == 0 {
			t.Logf("Note: Diff produced no output (files might be very similar)")
		} else {
			t.Logf("Successfully performed diff between firmware files")
			
			// Log first few lines of output
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			maxLines := 10
			if len(lines) > maxLines {
				t.Logf("First %d lines of diff output:", maxLines)
				for i := 0; i < maxLines; i++ {
					t.Logf("  %s", lines[i])
				}
				t.Logf("  ... (%d more lines)", len(lines)-maxLines)
			} else {
				t.Logf("Diff output (%d lines):", len(lines))
				for _, line := range lines {
					t.Logf("  %s", line)
				}
			}
		}
	})
}
