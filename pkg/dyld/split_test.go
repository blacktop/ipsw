//go:build darwin && cgo

package dyld

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
)

func srcVersion(major uint64) types.SrcVersion {
	return types.SrcVersion(major << 40)
}

func setMagic(m string) func(*CacheHeader) {
	return func(h *CacheHeader) {
		h.Magic = magic{}
		copy(h.Magic[:], m)
	}
}

func TestSplitHint(t *testing.T) {
	tests := []struct {
		name          string
		magic         string
		bundleVersion types.SrcVersion
		wantHint      bool
	}{
		{
			name:          "arm64e_x1 with Xcode 26 bundle",
			magic:         "dyld_v1arm64ex1",
			bundleVersion: srcVersion(1378),
			wantHint:      true,
		},
		{
			name:          "arm64e_x1 with Xcode 27 bundle",
			magic:         "dyld_v1arm64ex1",
			bundleVersion: srcVersion(27062),
			wantHint:      false,
		},
		{
			name:          "arm64e with Xcode 26 bundle",
			magic:         "dyld_v1  arm64e",
			bundleVersion: srcVersion(1378),
			wantHint:      false,
		},
		{
			name:          "garbage magic with Xcode 26 bundle",
			magic:         "not a cache",
			bundleVersion: srcVersion(1378),
			wantHint:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := splitHint(tt.magic, tt.bundleVersion)
			if got := strings.Contains(hint, "predates Xcode 27"); got != tt.wantHint {
				t.Errorf("splitHint(%q, %s) = %q, want hint = %v",
					tt.magic, tt.bundleVersion, hint, tt.wantHint)
			}
		})
	}
}

func TestReadCacheMagic(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "dyld_shared_cache_arm64e_x1")
	writeSyntheticMember(t, valid, 1, nil)
	got, err := readCacheMagic(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got != "dyld_v1arm64ex1" {
		t.Errorf("magic = %q, want dyld_v1arm64ex1", got)
	}

	truncated := filepath.Join(dir, "truncated")
	if err := os.WriteFile(truncated, []byte("dyld_v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCacheMagic(truncated); err == nil {
		t.Error("truncated cache: want error, got nil")
	}
	if _, err := readCacheMagic(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing cache: want error, got nil")
	}
}

// TestSplitCacheModeWritesNothingOnExtractorFailure drives the real dsc_extractor.bundle from the
// selected Xcode with an unsplittable cache and checks that no DeviceSupport artifacts are left.
func TestSplitCacheModeWritesNothingOnExtractorFailure(t *testing.T) {
	xcode, err := utils.GetXCodePath()
	if err != nil {
		t.Skipf("no Xcode selected: %v", err)
	}
	bundle := filepath.Join(xcode, "Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle")
	if _, err := os.Stat(bundle); err != nil {
		t.Skipf("no dsc_extractor.bundle: %v", err)
	}

	cacheDir := t.TempDir()
	dsc := filepath.Join(cacheDir, "dyld_shared_cache_bogus")
	writeSyntheticMember(t, dsc, 1, setMagic("dyld_v1  bogus"))
	writeSyntheticMember(t, dsc+".01", 2, setMagic("dyld_v1  bogus"))

	dest := filepath.Join(t.TempDir(), "DeviceSupport")
	err = Split(dsc, dest, "", true)
	if err == nil {
		t.Fatal("Split() of a bogus cache succeeded, want error")
	}
	wants := []string{"failed to split " + dsc, `magic "dyld_v1  bogus"`, bundle, "bundle version "}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Split() error %q missing %q", err, want)
		}
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("Split() left %s behind after failing (stat err = %v)", dest, err)
	}
}
