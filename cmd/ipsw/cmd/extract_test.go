package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestExtractDeviceModesReachInput(t *testing.T) {
	defaults := map[string]any{
		"kernel": false, "dyld": false, "dmg": "", "dtree": false,
		"iboot": false, "sep": false, "sptm": false, "kbag": false,
		"sys-ver": false, "exclave": false, "pattern": "", "fcs-key": false,
		"dyld-arch": []string{}, "files": false, "driverkit": false,
		"device": "Mac99,2", "remote": false, "lookup": false,
	}
	for key := range defaults {
		previous := viper.Get("extract." + key)
		t.Cleanup(func() { viper.Set("extract."+key, previous) })
	}
	for _, mode := range []struct {
		name   string
		flags  map[string]any
		reject bool
	}{
		{"kernel", map[string]any{"kernel": true}, false},
		{"dyld without arch", map[string]any{"dyld": true}, false},
		{"dyld with arch", map[string]any{"dyld": true, "dyld-arch": []string{"arm64e_x1"}}, false},
		{"files", map[string]any{"files": true, "pattern": `.*\.plist$`}, false},
		{"fcs-key", map[string]any{"fcs-key": true}, false},
		{"dmg", map[string]any{"dmg": "sys"}, false},
		{"iboot", map[string]any{"iboot": true}, true},
		{"dtree", map[string]any{"dtree": true}, true},
		{"sep", map[string]any{"sep": true}, true},
		{"sptm", map[string]any{"sptm": true}, true},
		{"kbag", map[string]any{"kbag": true}, true},
		{"sys-ver", map[string]any{"sys-ver": true}, true},
		{"exclave", map[string]any{"exclave": true}, true},
		{"zip pattern", map[string]any{"pattern": ".*"}, true},
		{"mixed kernel iboot", map[string]any{"kernel": true, "iboot": true}, true},
		{"mixed dyld zip pattern", map[string]any{"dyld": true, "dyld-arch": []string{"arm64e"}, "pattern": ".*"}, true},
		{"mixed dmg sep", map[string]any{"dmg": "sys", "sep": true}, true},
	} {
		for _, remote := range []bool{false, true} {
			name := mode.name + "/local"
			if remote {
				name = mode.name + "/remote"
			}
			t.Run(name, func(t *testing.T) {
				for key, value := range defaults {
					viper.Set("extract."+key, value)
				}
				for key, value := range mode.flags {
					viper.Set("extract."+key, value)
				}
				viper.Set("extract.remote", remote)
				input := filepath.Join(t.TempDir(), "missing.ipsw")
				// A missing local file or invalid remote URL proves RunE passed
				// flag validation without extracting or contacting a server.
				err := extractCmd.RunE(extractCmd, []string{input})
				if mode.reject {
					if err == nil || !strings.Contains(err.Error(), "--device can only be used with") {
						t.Fatalf("expected unsupported device mode error, got %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), input) {
					t.Fatalf("expected input error for %q, got %v", input, err)
				}
			})
		}
	}
}
