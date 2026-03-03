package ota

import (
	"path/filepath"
	"regexp"
	"testing"
)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outputPathForExtraction(tt.outputDir, tt.path, tt.flat); got != tt.want {
				t.Fatalf("outputPathForExtraction(%q, %q, %t) = %q, want %q", tt.outputDir, tt.path, tt.flat, got, tt.want)
			}
		})
	}
}
