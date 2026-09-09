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

func TestDeviceScopedDatabase(t *testing.T) {
	for _, tc := range []struct{ database, device, want string }{
		{"", "Mac18,5", ""},
		{"ents.gob", "", "ents.gob"},
		{"ents.gob", "Mac18,5", "ents.Mac18,5.gob"},
		{"/cache/ents", "j873gap", "/cache/ents.j873gap"},
	} {
		if got := deviceScopedDatabase(tc.database, tc.device); got != tc.want {
			t.Errorf("deviceScopedDatabase(%q, %q) = %q, want %q", tc.database, tc.device, got, tc.want)
		}
	}
}

func TestGetDatabaseWritesDeviceScopedBlob(t *testing.T) {
	dir := t.TempDir()
	conf := &Config{Folder: filepath.Join(dir, "root"), Database: filepath.Join(dir, "ents.gob"), Device: "Mac99,2"}
	if err := os.MkdirAll(conf.Folder, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := GetDatabase(conf); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(conf.Database); !os.IsNotExist(err) {
		t.Fatalf("unscoped cache written for a device selection: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ents.Mac99,2.gob")); err != nil {
		t.Fatalf("device-scoped cache missing: %v", err)
	}
	if _, err := GetDatabase(conf); err != nil {
		t.Fatalf("reload from device-scoped cache: %v", err)
	}
}
