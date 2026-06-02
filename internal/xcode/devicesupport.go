// Package xcode locates artifacts that Xcode stores on the local machine, such
// as the on-device symbol dumps under "<Platform> DeviceSupport".
package xcode

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	deviceSupportCryptexCacheDir = "private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld"
	deviceSupportSystemCacheDir  = "System/Library/Caches/com.apple.dyld"
	deviceSupportDyldCacheDir    = "System/Library/dyld"
)

// deviceSupportCacheGlobs are the locations of the main dyld_shared_cache file
// inside a DeviceSupport "Symbols" dump, relative to the dump root. The layouts
// mirror the on-device filesystem. Modern Xcode no longer ships the cache here
// (only the extracted dylibs), so a dump may match none of these.
var deviceSupportCacheGlobs = []string{
	filepath.Join(deviceSupportCryptexCacheDir, "dyld_shared_cache_*"),
	filepath.Join(deviceSupportSystemCacheDir, "dyld_shared_cache_*"),
	filepath.Join(deviceSupportDyldCacheDir, "dyld_shared_cache_*"),
}

// DeviceSupport describes a matched Xcode DeviceSupport symbol dump.
type DeviceSupport struct {
	Dir     string   // the matched "<Platform> DeviceSupport/<device dir>" directory
	Symbols string   // the symbol-dump root inside Dir (loose dylibs under System/, usr/)
	DSCs    []string // main dyld_shared_cache files found inside it (empty on modern dumps)
}

// FindDeviceSupport locates the Xcode DeviceSupport symbol dump matching the
// given device build (and, when available, product and version). Xcode
// populates these dumps automatically when a device is connected, e.g.:
//
//	~/Library/Developer/Xcode/iOS DeviceSupport/iPhone12,1 26.4.2 (23E261)/Symbols
//
// On success the dump always has either a dyld_shared_cache (DSCs) or a loose
// dylib tree (Symbols/System or Symbols/usr); modern Xcode ships only the
// latter. product and version disambiguate when multiple dumps share a build;
// build is required because it uniquely identifies a firmware.
func FindDeviceSupport(product, version, build string) (*DeviceSupport, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve home directory: %w", err)
	}
	return findDeviceSupport(filepath.Join(home, "Library", "Developer", "Xcode"), product, version, build)
}

func findDeviceSupport(xcodeDir, product, version, build string) (*DeviceSupport, error) {
	if build == "" {
		return nil, fmt.Errorf("crashlog has no build identifier; cannot locate an Xcode DeviceSupport dump")
	}

	supportDirs, err := filepath.Glob(filepath.Join(xcodeDir, "*DeviceSupport"))
	if err != nil {
		return nil, fmt.Errorf("failed to search %s for DeviceSupport directories: %w", xcodeDir, err)
	}

	var candidates []string
	for _, sd := range supportDirs {
		entries, err := os.ReadDir(sd)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.Contains(e.Name(), build) {
				candidates = append(candidates, filepath.Join(sd, e.Name()))
			}
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no Xcode DeviceSupport dump found for build %s under %s", build, xcodeDir)
	}

	// Narrow by product, then version, when those let us pick a single dump.
	candidates = preferContaining(candidates, product)
	candidates = preferContaining(candidates, version)

	// Prefer a dump with a real dyld_shared_cache over a loose-dylib-only dump,
	// regardless of scan order; fall back to the first loose-only dump.
	var looseOnly *DeviceSupport
	for _, dir := range candidates {
		symbols := dir
		if st, err := os.Stat(filepath.Join(dir, "Symbols")); err == nil && st.IsDir() {
			symbols = filepath.Join(dir, "Symbols")
		}
		if dscs := findMainCaches(symbols); len(dscs) > 0 {
			return &DeviceSupport{Dir: dir, Symbols: symbols, DSCs: dscs}, nil
		}
		if looseOnly == nil && hasLooseDylibs(symbols) {
			looseOnly = &DeviceSupport{Dir: dir, Symbols: symbols}
		}
	}
	if looseOnly != nil {
		return looseOnly, nil
	}

	return nil, fmt.Errorf("found Xcode DeviceSupport dump for build %s but it has no dyld_shared_cache or extracted dylibs (%s)", build, strings.Join(candidates, ", "))
}

// preferContaining keeps only the dirs whose base name contains want; if none
// match (or want is empty) the input is returned unchanged so a weaker match
// still wins over no match.
func preferContaining(dirs []string, want string) []string {
	if want == "" {
		return dirs
	}
	var preferred []string
	for _, d := range dirs {
		if strings.Contains(filepath.Base(d), want) {
			preferred = append(preferred, d)
		}
	}
	if len(preferred) == 0 {
		return dirs
	}
	return preferred
}

// findMainCaches returns the main dyld_shared_cache files under root, excluding
// subcaches (".01", ".symbols", …) which dyld.Open loads from the main file.
func findMainCaches(root string) []string {
	var mains []string
	for _, glob := range deviceSupportCacheGlobs {
		matches, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if filepath.Ext(m) == "" {
				mains = append(mains, m)
			}
		}
	}
	slices.Sort(mains)
	return slices.Compact(mains)
}

// hasLooseDylibs reports whether root contains an extracted on-device file tree
// (the System or usr directories hold the split dylibs/frameworks).
func hasLooseDylibs(root string) bool {
	for _, sub := range []string{"System", "usr"} {
		if st, err := os.Stat(filepath.Join(root, sub)); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}
