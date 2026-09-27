package dyld

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestDyldInfoArgs(t *testing.T) {
	keys := []string{"dyld.info.diff", "dyld.info.delta", "dyld.info.dylibs", "dyld.info.json"}
	for _, key := range keys {
		previous := viper.Get(key)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
	for _, tc := range []struct {
		name                      string
		diff, delta, dylibs, json bool
		count                     int
		wantErr                   string
	}{
		{"ordinary", false, false, false, false, 1, ""},
		{"ordinary missing", false, false, false, false, 0, "arg(s)"},
		{"ordinary excess", false, false, false, false, 2, "arg(s)"},
		{"diff", true, false, true, false, 2, ""},
		{"delta", false, true, true, false, 2, ""},
		{"json diff", true, false, true, true, 2, ""},
		{"json delta", false, true, true, true, 2, ""},
		{"diff missing input", true, false, true, false, 1, "2 arg(s)"},
		{"delta excess input", false, true, true, false, 3, "2 arg(s)"},
		{"dylibs required", true, false, false, true, 2, "--dylibs"},
		{"conflicting modes", true, true, true, true, 2, "mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, value := range []bool{tc.diff, tc.delta, tc.dylibs, tc.json} {
				viper.Set(keys[i], value)
			}
			args := make([]string, tc.count)
			err := dyldInfoCmd.Args(dyldInfoCmd, args)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Args returned %v; want %q", err, tc.wantErr)
			}
			if err := dyldInfoCmd.RunE(dyldInfoCmd, args); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RunE must reject invalid configuration before reading inputs: %v", err)
			}
		})
	}
}

func TestCompareDylibVersions(t *testing.T) {
	before := map[string]string{
		"/lib/unchanged": "1.0", "/lib/changed-z": "2.0", "/lib/changed-a": "",
		"/lib/removed-z": "3.0", "/lib/removed-a": "4.0",
	}
	after := map[string]string{
		"/lib/unchanged": "1.0", "/lib/changed-z": "2.1", "/lib/changed-a": "1.0",
		"/lib/added-z": "6.0", "/lib/added-a": "5.0",
	}
	want := dylibComparison{
		Added:   []dylibVersion{{Name: "/lib/added-a", Version: "5.0"}, {Name: "/lib/added-z", Version: "6.0"}},
		Removed: []dylibVersion{{Name: "/lib/removed-a", Version: "4.0"}, {Name: "/lib/removed-z", Version: "3.0"}},
		Changed: []dylibVersionChange{{Name: "/lib/changed-a", OldVersion: "", NewVersion: "1.0"}, {Name: "/lib/changed-z", OldVersion: "2.0", NewVersion: "2.1"}},
	}
	if got := compareDylibVersions(before, after); !reflect.DeepEqual(got, want) {
		t.Fatalf("comparison = %#v; want %#v", got, want)
	}
	b, err := json.Marshal(compareDylibVersions(before, before))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"added":[],"removed":[],"changed":[]}` {
		t.Fatalf("unchanged JSON = %s", b)
	}
}
