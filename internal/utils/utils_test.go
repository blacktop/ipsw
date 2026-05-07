package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSanitizeArchivePath(t *testing.T) {
	tests := []struct {
		name    string
		dest    string
		entry   string
		want    string
		wantErr bool
	}{
		{"simple", "/tmp/out", "foo", filepath.Join("/tmp/out", "foo"), false},
		{"nested", "/tmp/out", "a/b/c", filepath.Join("/tmp/out", "a/b/c"), false},
		{"dotdot escape", "/tmp/out", "../../../etc/passwd", "", true},
		{"deep dotdot to cron", "/tmp/ipsw-extract/iPhone99,1_99.0_99A1", "../../../../../../../../etc/cron.d/ipsw-pwn", "", true},
		{"nested dotdot escape", "/tmp/out", "a/../../etc/passwd", "", true},
		{"dotdot to parent", "/tmp/out", "..", "", true},
		{"contained dotdot", "/tmp/out", "a/../b", filepath.Join("/tmp/out", "b"), false},
		{"sibling prefix attack", "/tmp/out", "../outx/foo", "", true},
		{"relative dest escape", "out", "../../etc", "", true},
		{"relative dest ok", "out", "foo", filepath.Join("out", "foo"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeArchivePath(tt.dest, tt.entry)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SanitizeArchivePath(%q, %q) = %q, want error", tt.dest, tt.entry, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SanitizeArchivePath(%q, %q) unexpected error: %v", tt.dest, tt.entry, err)
			}
			if got != tt.want {
				t.Fatalf("SanitizeArchivePath(%q, %q) = %q, want %q", tt.dest, tt.entry, got, tt.want)
			}
		})
	}
}

func TestMountedFilesystemRoot(t *testing.T) {
	t.Run("apfs fuse root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "root", "System"), 0755); err != nil {
			t.Fatal(err)
		}

		if got, want := MountedFilesystemRoot(root), filepath.Join(root, "root"); got != want {
			t.Fatalf("MountedFilesystemRoot() = %q, want %q", got, want)
		}
	})

	t.Run("direct system wins", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "root", "System"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "System"), 0755); err != nil {
			t.Fatal(err)
		}

		if got, want := MountedFilesystemRoot(root), filepath.Clean(root); got != want {
			t.Fatalf("MountedFilesystemRoot() = %q, want %q", got, want)
		}
	})
}

func TestDifference(t *testing.T) {
	type args struct {
		a []string
		b []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"b", "c", "d"},
			},
			want: []string{"a"},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"b", "c", "d"},
				b: []string{"a", "b", "c"},
			},
			want: []string{"d"},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"a", "b", "c"},
			},
			want: []string{},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"d", "e", "f"},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"c", "b", "a"},
			},
			want: []string{},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"c", "b", "a", "d"},
			},
			want: []string{},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"c", "b", "a", "d"},
				b: []string{"a", "b", "c"},
			},
			want: []string{"d"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Difference(tt.args.a, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				if len(got) != len(tt.want) {
					t.Errorf("Difference() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
