package plist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	goplist "github.com/blacktop/go-plist"
)

func TestGetBinaryInAppValidatesExecutable(t *testing.T) {
	for _, layout := range []struct {
		name, plistDir, executableDir string
		format                        int
	}{
		{"iOS", "", "", goplist.XMLFormat},
		{"macOS", "Contents", "Contents/MacOS", goplist.BinaryFormat},
	} {
		for _, tc := range []struct{ name, executable, wantErr string }{
			{"normal", "Main", ""},
			{"traversal", "../../../../outside", "invalid CFBundleExecutable"},
			{"missing", "", "failed to find CFBundleExecutable"},
		} {
			t.Run(layout.name+"/"+tc.name, func(t *testing.T) {
				app := filepath.Join(t.TempDir(), "Synthetic.app")
				infoPath := filepath.Join(app, layout.plistDir, "Info.plist")
				if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
					t.Fatal(err)
				}
				data, err := goplist.Marshal(map[string]string{"CFBundleExecutable": tc.executable}, layout.format)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(infoPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				got, err := GetBinaryInApp(app)
				if tc.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) || got != "" {
						t.Fatalf("GetBinaryInApp() = %q, %v; want %q", got, err, tc.wantErr)
					}
				} else if want := filepath.Join(app, layout.executableDir, tc.executable); err != nil || got != want {
					t.Fatalf("GetBinaryInApp() = %q, %v; want %q", got, err, want)
				}
			})
		}
	}
}
