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

	got, err := findDeviceSupport(xcodeDir, "iPhone12,1", "26.5", "23F77")
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

	got, err := findDeviceSupport(xcodeDir, "iPhone12,1", "26.5", "23F77")
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

	got, err := findDeviceSupport(xcodeDir, "iPhone13,3", "14.5", "18E5154f")
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

	got, err := findDeviceSupport(xcodeDir, "iPhone12,1", "26.5", "23F77")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DSCs[0] != want {
		t.Fatalf("DSCs[0] = %s, want %s (product should disambiguate)", got.DSCs[0], want)
	}
}

func TestFindDeviceSupportDSCsNoBuild(t *testing.T) {
	t.Parallel()
	if _, err := findDeviceSupport(t.TempDir(), "iPhone12,1", "26.5", ""); err == nil {
		t.Fatal("expected error for empty build, got nil")
	}
}

func TestFindDeviceSupportDSCsNoMatch(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	writeDSC(t, xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", true)

	if _, err := findDeviceSupport(xcodeDir, "iPhone12,1", "26.4", "23E224"); err == nil {
		t.Fatal("expected error for unknown build, got nil")
	}
}

func TestFindDeviceSupportDSCsResolvesHome(t *testing.T) {
	// not parallel: mutates HOME via t.Setenv
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := writeDSC(t, filepath.Join(home, "Library", "Developer", "Xcode"), "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", true)

	got, err := FindDeviceSupport("iPhone12,1", "26.5", "23F77")
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
	// Empty dump: no dyld_shared_cache and no extracted dylibs.
	if err := os.MkdirAll(filepath.Join(xcodeDir, "iOS DeviceSupport", "iPhone12,1 26.5 (23F77)", "Symbols"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := findDeviceSupport(xcodeDir, "iPhone12,1", "26.5", "23F77"); err == nil {
		t.Fatal("expected error when dump has neither DSC nor dylibs, got nil")
	}
}

func TestFindDeviceSupportLooseDylibsOnly(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	// Modern Xcode: extracted dylibs under Symbols/System, NO dyld_shared_cache.
	symbols := filepath.Join(xcodeDir, "iOS DeviceSupport", "iPhone18,4 26.4.2 (23E261)", "Symbols")
	fw := filepath.Join(symbols, "System", "Library", "Frameworks", "Foundation.framework")
	if err := os.MkdirAll(fw, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fw, "Foundation"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := findDeviceSupport(xcodeDir, "iPhone18,4", "26.4.2", "23E261")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.DSCs) != 0 {
		t.Fatalf("DSCs = %v, want empty (loose-dylib dump)", got.DSCs)
	}
	if got.Symbols != symbols {
		t.Fatalf("Symbols = %q, want %q", got.Symbols, symbols)
	}
}

func TestFindDeviceSupportLooseDylibsUsrOnly(t *testing.T) {
	t.Parallel()
	xcodeDir := t.TempDir()
	// Dump with extracted dylibs only under usr/ (no System/), no dyld_shared_cache.
	symbols := filepath.Join(xcodeDir, "iOS DeviceSupport", "iPhone18,4 26.4.2 (23E261)", "Symbols")
	libDir := filepath.Join(symbols, "usr", "lib", "system")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libsystem_kernel.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := findDeviceSupport(xcodeDir, "iPhone18,4", "26.4.2", "23E261")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.DSCs) != 0 || got.Symbols != symbols {
		t.Fatalf("got DSCs=%v Symbols=%q, want empty DSCs and Symbols=%q", got.DSCs, got.Symbols, symbols)
	}
}
