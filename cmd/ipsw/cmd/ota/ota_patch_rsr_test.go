//go:build darwin && cgo

package ota

import "testing"

// TestRsrSystemCryptexREDefaultCoversArm64_32 pins the unfiltered RSR selector.
// `arm64e?` cannot match arm64_32, so an unfiltered patch would skip a watchOS
// system cryptex it was asked to handle.
func TestRsrSystemCryptexREDefaultCoversArm64_32(t *testing.T) {
	re := rsrSystemCryptexRE(nil)
	for _, name := range []string{
		"cryptex-system-arm64",
		"cryptex-system-arm64e",
		"cryptex-system-arm64_32",
		"cryptex-system-x86_64",
		"cryptex-system-x86_64h",
	} {
		if !re.MatchString(name) {
			t.Errorf("rsrSystemCryptexRE(nil) does not match %q", name)
		}
	}
	if re.MatchString("cryptex-app") {
		t.Error("rsrSystemCryptexRE(nil) unexpectedly matches cryptex-app")
	}
	if !rsrSystemCryptexRE([]string{"arm64_32"}).MatchString("cryptex-system-arm64_32") {
		t.Error("rsrSystemCryptexRE([arm64_32]) does not match its own arch")
	}
}
