package xcode

import (
	"os"
	"path/filepath"
	"testing"
)

// writeDSC creates a fake DeviceSupport dump under xcodeDir for the given
// platform/device dir, placing main + subcache files in the cache dir. It
// returns the path to the main cache file that the locator should return.
func writeDSC(t *testing.T, xcodeDir, platformDir, deviceDir string, withSymbols bool) string {
	t.Helper()
	return writeDSCAt(t, xcodeDir, platformDir, deviceDir, deviceSupportSystemCacheDir, withSymbols)
}

func writeDSCAt(t *testing.T, xcodeDir, platformDir, deviceDir, cacheRel string, withSymbols bool) string {
	t.Helper()
	root := filepath.Join(xcodeDir, platformDir, deviceDir)
	if withSymbols {
		root = filepath.Join(root, "Symbols")
	}
	cacheDir := filepath.Join(root, cacheRel)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", cacheDir, err)
	}
	main := filepath.Join(cacheDir, "dyld_shared_cache_arm64e")
	for _, name := range []string{
		"dyld_shared_cache_arm64e",
		"dyld_shared_cache_arm64e.01",
		"dyld_shared_cache_arm64e.symbols",
	} {
		if err := os.WriteFile(filepath.Join(cacheDir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return main
}

func TestFindDeviceSupportDSCsCryptexLayout(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	want := writeDSCAt(t, xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)",
		deviceSupportCryptexCacheDir, true)

	got, err := findDeviceSupportDSCs(xcodeDir, "iPhone12,1", "26.5", "23F77")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.DSCs) != 1 || got.DSCs[0] != want {
		t.Fatalf("DSCs = %v, want [%s]", got.DSCs, want)
	}
}

func TestFindDeviceSupportDSCsModernLayout(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	want := writeDSC(t, xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", true)

	got, err := findDeviceSupportDSCs(xcodeDir, "iPhone12,1", "26.5", "23F77")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.DSCs) != 1 || got.DSCs[0] != want {
		t.Fatalf("DSCs = %v, want [%s]", got.DSCs, want)
	}
}

func TestFindDeviceSupportDSCsLegacyLayout(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	// Older Xcode: no device prefix, no Symbols subdir.
	want := writeDSC(t, xcodeDir, "iOS DeviceSupport", "14.5 (18E5154f)", false)

	got, err := findDeviceSupportDSCs(xcodeDir, "iPhone13,3", "14.5", "18E5154f")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.DSCs) != 1 || got.DSCs[0] != want {
		t.Fatalf("DSCs = %v, want [%s]", got.DSCs, want)
	}
}

func TestFindDeviceSupportDSCsDisambiguatesByProduct(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	writeDSC(t, xcodeDir, "iOS DeviceSupport", "iPhone14,2 23F77 (23F77)", true)
	want := writeDSC(t, xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", true)

	got, err := findDeviceSupportDSCs(xcodeDir, "iPhone12,1", "26.5", "23F77")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DSCs[0] != want {
		t.Fatalf("DSCs[0] = %s, want %s (product should disambiguate)", got.DSCs[0], want)
	}
}

func TestFindDeviceSupportDSCsNoBuild(t *testing.T) {
	t.Parallel()
	if _, err := findDeviceSupportDSCs(t.TempDir(), "iPhone12,1", "26.5", ""); err == nil {
		t.Fatal("expected error for empty build, got nil")
	}
}

func TestFindDeviceSupportDSCsNoMatch(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	writeDSC(t, xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", true)

	if _, err := findDeviceSupportDSCs(xcodeDir, "iPhone12,1", "26.4", "23E224"); err == nil {
		t.Fatal("expected error for unknown build, got nil")
	}
}

func TestFindDeviceSupportDSCsResolvesHome(t *testing.T) {
	// not parallel: mutates HOME via t.Setenv
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := writeDSC(t, filepath.Join(home, "Library", "Developer", "Xcode"), "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", true)

	got, err := FindDeviceSupportDSCs("iPhone12,1", "26.5", "23F77")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.DSCs) != 1 || got.DSCs[0] != want {
		t.Fatalf("DSCs = %v, want [%s]", got.DSCs, want)
	}
}

func TestFindDeviceSupportDSCsDirWithoutCache(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	// Matching device dir exists but contains no dyld_shared_cache.
	if err := os.MkdirAll(filepath.Join(xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", "Symbols"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := findDeviceSupportDSCs(xcodeDir, "iPhone12,1", "26.5", "23F77"); err == nil {
		t.Fatal("expected error when dump has no DSC, got nil")
	}
}
