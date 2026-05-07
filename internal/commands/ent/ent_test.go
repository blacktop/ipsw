package ent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMountedEntitlementFilesRootNormalization(t *testing.T) {
	tests := []struct {
		name      string
		fileParts []string
		wantParts []string
	}{
		{
			name:      "apfs fuse root",
			fileParts: []string{"root", "System", "Library", "CoreServices", "testd"},
			wantParts: []string{"System", "Library", "CoreServices", "testd"},
		},
		{
			name:      "direct root",
			fileParts: []string{"System", "Library", "CoreServices", "testd"},
			wantParts: []string{"System", "Library", "CoreServices", "testd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := pathUnder(root, tt.fileParts...)
			writeTestFile(t, path)

			files, err := mountedEntitlementFiles(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 1 {
				t.Fatalf("expected 1 file, got %d: %#v", len(files), files)
			}

			wantDBPath := rootedPath(tt.wantParts...)
			if files[0].Path != path {
				t.Fatalf("Path = %q, want %q", files[0].Path, path)
			}
			if files[0].DBPath != wantDBPath {
				t.Fatalf("DBPath = %q, want %q", files[0].DBPath, wantDBPath)
			}
		})
	}
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
}

func pathUnder(root string, parts ...string) string {
	return filepath.Join(append([]string{root}, parts...)...)
}

func rootedPath(parts ...string) string {
	return string(filepath.Separator) + filepath.Join(parts...)
}
