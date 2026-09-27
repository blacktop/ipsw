package dyld

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/viper"
)

func TestWebkitArgs(t *testing.T) {
	previous := viper.Get("dyld.webkit.diff")
	t.Cleanup(func() { viper.Set("dyld.webkit.diff", previous) })
	for _, diff := range []bool{false, true} {
		// An override also exercises effective configuration rather than only flags.
		viper.Set("dyld.webkit.diff", diff)
		for count := 0; count <= 3; count++ {
			t.Run(fmt.Sprintf("diff_%t_args_%d", diff, count), func(t *testing.T) {
				args := make([]string, count)
				wantValid := (!diff && count == 1) || (diff && count == 2)
				err := WebkitCmd.Args(WebkitCmd, args)
				if (err == nil) != wantValid {
					t.Fatalf("Args returned %v; valid=%t", err, wantValid)
				}
				if !wantValid {
					if err := WebkitCmd.RunE(WebkitCmd, args); err == nil || !strings.Contains(err.Error(), "arg(s)") {
						t.Fatalf("RunE must reject arity before opening a cache: %v", err)
					}
				}
			})
		}
	}
}

func TestSelectWebkitTag(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		tags          []string
		want          string
		exact         bool
		wantErr       bool
	}{
		{"exact after lower", "620.1.2", []string{"WebKit-7619.9.1", "WebKit-7620.1.2"}, "WebKit-7620.1.2", true, false},
		{"unsorted lower", "620.1.2", []string{"WebKit-7610.1.1", "WebKit-7621.1.1", "WebKit-7619.9.1", "WebKit-7618.1.1"}, "WebKit-7619.9.1", false, false},
		{"old catalog remains approximate", "640.1.1", []string{"WebKit-7610.1.1"}, "WebKit-7610.1.1", false, false},
		{"no usable tags", "620.1.2", []string{"Other-7620.1.2", "WebKit-7bad", "WebKit-7621.1.1"}, "", false, true},
		{"empty catalog", "620.1.2", nil, "", false, true},
		{"invalid detected version", "invalid", nil, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tags []download.GithubTag
			for _, name := range tc.tags {
				tags = append(tags, download.GithubTag{Name: name})
			}
			got, exact, err := selectWebkitTag(tc.version, tags)
			if (err != nil) != tc.wantErr || got.Name != tc.want || exact != tc.exact {
				t.Fatalf("selectWebkitTag = %q, %t, %v; want %q, %t, error=%t", got.Name, exact, err, tc.want, tc.exact, tc.wantErr)
			}
		})
	}
}

func TestWriteWebkitDiff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		old     string
		new     string
		changed bool
	}{
		{"changed", "620.1.1", "621.2.3", true},
		{"same", "620.1.1", "620.1.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := writeWebkitDiff(&out, webkitDiff{
				Old:     webkitVersionAt{Path: "/old/dsc", Version: tc.old},
				New:     webkitVersionAt{Path: "/new/dsc", Version: tc.new},
				Changed: tc.old != tc.new,
			})
			if err != nil {
				t.Fatal(err)
			}
			var got webkitDiff
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("output is not JSON: %v\n%s", err, out.String())
			}
			if got.Old.Version != tc.old || got.New.Version != tc.new || got.Changed != tc.changed || got.Old.Path != "/old/dsc" {
				t.Fatalf("unexpected diff JSON: %+v", got)
			}
		})
	}
}
