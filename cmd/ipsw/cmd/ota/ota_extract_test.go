package ota

import (
	"errors"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/blacktop/ipsw/pkg/dyld"
)

func TestDyldPayloadPattern(t *testing.T) {
	t.Run("cryptex success preserves cryptex-first behavior", func(t *testing.T) {
		if got := dyldPayloadPattern("", nil); got != "" {
			t.Fatalf("dyldPayloadPattern(\"\", nil) = %q, want no payload fallback", got)
		}
	})

	t.Run("cryptex failure matches payload dyld cache paths", func(t *testing.T) {
		pattern := dyldPayloadPattern("", errors.New("no cryptexes found"))
		if pattern != dyld.CacheUberRegex {
			t.Fatalf("dyldPayloadPattern() = %q, want %q", pattern, dyld.CacheUberRegex)
		}

		re := regexp.MustCompile(pattern)
		paths := []string{
			"System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			"System/DriverKit/System/Library/dyld/dyld_shared_cache_arm64e",
			"System/Library/dyld/aot_shared_cache.0",
			"System/Library/dyld/aot_shared_cache.6",
			"System/Library/dyld/dyld_shared_cache_x86_64",
		}
		for _, path := range paths {
			if !matchesPostBOMPattern(re, path) {
				t.Errorf("fallback pattern %q does not match full path %q", pattern, path)
			}
		}

		falsePositives := []string{
			"System/Library/dyld/aot_shared_cache",
			"System/Library/dyld/aot_shared_cache.foo",
			"System/Library/dyld/aot_shared_cache.0.map",
			"System/Library/Caches/com.apple.dyld/aot_shared_cache.0",
			"usr/lib/aot_shared_cache.0",
		}
		for _, path := range falsePositives {
			if matchesPostBOMPattern(re, path) {
				t.Errorf("fallback pattern %q unexpectedly matches full path %q", pattern, path)
			}
		}
	})
}

func TestMatchesPostBOMPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name:    "matches full path",
			pattern: `^System/Library/Caches/com\.apple\.dyld/`,
			path:    "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			want:    true,
		},
		{
			name:    "matches basename",
			pattern: `^dyld_shared_cache`,
			path:    "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			want:    true,
		},
		{
			name:    "does not match",
			pattern: `^kernelcache`,
			path:    "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := regexp.MustCompile(tt.pattern)
			if got := matchesPostBOMPattern(re, tt.path); got != tt.want {
				t.Fatalf("matchesPostBOMPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestOutputPathForExtraction(t *testing.T) {
	tests := []struct {
		name      string
		outputDir string
		path      string
		flat      bool
		want      string
		wantErr   bool
	}{
		{
			name:      "preserve directory structure",
			outputDir: "/tmp/out",
			path:      "System/Library/foo",
			flat:      false,
			want:      filepath.Join("/tmp/out", "System/Library/foo"),
		},
		{
			name:      "flat output",
			outputDir: "/tmp/out",
			path:      "System/Library/foo",
			flat:      true,
			want:      filepath.Join("/tmp/out", "foo"),
		},
		{
			name:      "reject traversal",
			outputDir: "/tmp/out",
			path:      "../../../etc/passwd",
			flat:      false,
			wantErr:   true,
		},
		{
			name:      "reject nested traversal",
			outputDir: "/tmp/out",
			path:      "foo/../../../etc/passwd",
			flat:      false,
			wantErr:   true,
		},
		{
			name:      "flat mode neutralizes traversal",
			outputDir: "/tmp/out",
			path:      "../../../etc/passwd",
			flat:      true,
			want:      filepath.Join("/tmp/out", "passwd"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := outputPathForExtraction(tt.outputDir, tt.path, tt.flat)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("outputPathForExtraction(%q, %q, %t) = %q, want error", tt.outputDir, tt.path, tt.flat, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("outputPathForExtraction(%q, %q, %t) unexpected error: %v", tt.outputDir, tt.path, tt.flat, err)
			}
			if got != tt.want {
				t.Fatalf("outputPathForExtraction(%q, %q, %t) = %q, want %q", tt.outputDir, tt.path, tt.flat, got, tt.want)
			}
		})
	}
}
