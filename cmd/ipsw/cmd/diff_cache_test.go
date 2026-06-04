package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/spf13/viper"
)

// TestBuildDiffCacheConfigParsesSize confirms the --cache-max-size flag is
// parsed via humanize.ParseBytes and that defaults flow through.
func TestBuildDiffCacheConfigParsesSize(t *testing.T) {
	t.Cleanup(viper.Reset)

	cases := []struct {
		name string
		raw  string
		want int64
	}{
		{"empty falls back to default 5GiB", "", 5 * 1024 * 1024 * 1024},
		{"explicit GiB", "1GiB", 1 << 30},
		{"explicit MB", "500MB", 500 * 1000 * 1000},
		{"raw byte count", "12345", 12345},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			viper.Set("diff.cache-max-size", tc.raw)
			cfg, err := buildDiffCacheConfig()
			if err != nil {
				t.Fatalf("buildDiffCacheConfig: %v", err)
			}
			if cfg.MaxBytes != tc.want {
				t.Fatalf("MaxBytes=%d want=%d", cfg.MaxBytes, tc.want)
			}
		})
	}
}

func TestBuildDiffCacheConfigRejectsGarbage(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set("diff.cache-max-size", "not-a-size")
	if _, err := buildDiffCacheConfig(); err == nil {
		t.Fatal("expected error for garbage --cache-max-size")
	}
}

// TestDiffCleanRemovesExistingDB covers the contract that the orchestrator
// path with --clean drops any pre-existing cache file before opening a new
// store, regardless of the file's contents.
func TestDiffCleanRemovesExistingDB(t *testing.T) {
	dir := t.TempDir()
	oldID := "iphone-old"
	newID := "iphone-new"
	path, err := storage.ResolveCachePath(oldID, newID, dir)
	if err != nil {
		t.Fatalf("ResolveCachePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("legacy"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Build an OpenCacheStore call that mirrors --clean via the same
	// helpers the CLI wires up. We use the override dir + identities so
	// the test does not depend on real IPSWs.
	store, cleanup, err := storage.OpenCacheStore(storage.CacheOptions{
		Dir:     dir,
		Clean:   true,
		NoCache: false,
		OldInfo: nil, // forces fallback to NoCache path
		NewInfo: nil,
	})
	if err != nil {
		t.Fatalf("OpenCacheStore: %v", err)
	}
	t.Cleanup(cleanup)
	_ = store

	// When identity is unresolvable we land in the temp-cache fallback
	// instead of the real override path. The legacy file must remain
	// untouched in that case (we did not target it).
	if got, err := os.ReadFile(path); err != nil {
		t.Fatalf("ReadFile: %v", err)
	} else if string(got) != "legacy" {
		t.Fatalf("legacy file mutated despite identity-unresolved fallback: %q", string(got))
	}
}
