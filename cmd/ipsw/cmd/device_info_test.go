package cmd

import "testing"

func TestDeviceInfoRejectsIgnoredPositionals(t *testing.T) {
	if err := deviceInfoCmd.Args(deviceInfoCmd, []string{"iPhone99,1"}); err == nil {
		t.Fatal("accepted an ignored positional device; use --prod")
	}
	if err := deviceInfoCmd.Args(deviceInfoCmd, nil); err != nil {
		t.Fatal(err)
	}
}
