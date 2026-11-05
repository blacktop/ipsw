package resources

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateCodeResourcesRejectsExecutableTraversal(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Synthetic.app")
	infoPath := filepath.Join(app, frameworksDirectory, "Synthetic.framework", "Resources", "Info.plist")
	for _, dir := range []string{filepath.Dir(infoPath), filepath.Join(app, libraryDirectory), filepath.Join(app, resourcesDirectory)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	data := []byte(`<plist version="1.0"><dict><key>CFBundleExecutable</key><string>../../../../outside</string></dict></plist>`)
	if err := os.WriteFile(infoPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateCodeResources(app); err == nil || !strings.Contains(err.Error(), "invalid CFBundleExecutable") {
		t.Fatalf("CreateCodeResources() = %v; want invalid executable error", err)
	}
	if _, err := os.Stat(filepath.Join(app, CodeResourcesPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("CodeResources was created: %v", err)
	}
}
