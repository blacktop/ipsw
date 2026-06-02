package crashlog

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
)

// looseCache resolves shared-cache VM addresses against a set of loose,
// extracted dylibs — an Xcode DeviceSupport "Symbols" dump that no longer ships
// the dyld_shared_cache itself. The extracted dylibs retain their cache VM
// addresses, so this mirrors what the DSC provides for userspace symbolication:
// a cache address resolves to an image name + symbol.
type looseCache struct {
	images []looseImage           // sorted by start, by __TEXT cache range
	open   map[string]*macho.File // path -> lazily opened macho
	fats   []*macho.FatFile       // universal files kept open to back open[...] arches
}

type looseImage struct {
	name  string // base name, e.g. libsystem_kernel.dylib
	path  string
	start uint64 // __TEXT vmaddr (cache address)
	end   uint64
}

// newLooseCache indexes every Mach-O under symbolsDir by its __TEXT cache range.
func newLooseCache(symbolsDir string) (*looseCache, error) {
	lc := &looseCache{open: make(map[string]*macho.File)}
	if err := search.ForEachMacho(symbolsDir, func(path string, m *macho.File) error {
		if seg := m.Segment("__TEXT"); seg != nil && seg.Memsz > 0 {
			lc.images = append(lc.images, looseImage{
				name:  filepath.Base(path),
				path:  path,
				start: seg.Addr,
				end:   seg.Addr + seg.Memsz,
			})
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to scan dylibs in %s: %w", symbolsDir, err)
	}
	if len(lc.images) == 0 {
		return nil, fmt.Errorf("no dylibs found in %s", symbolsDir)
	}
	sort.Slice(lc.images, func(i, j int) bool { return lc.images[i].start < lc.images[j].start })
	return lc, nil
}

// Close releases any machos opened during resolution.
func (lc *looseCache) Close() {
	for _, f := range lc.fats {
		f.Close()
	}
	for _, m := range lc.open {
		m.Close()
	}
}

// imageContaining returns the dylib whose __TEXT range contains addr, or nil.
func (lc *looseCache) imageContaining(addr uint64) *looseImage {
	i := sort.Search(len(lc.images), func(i int) bool { return lc.images[i].start > addr })
	if i == 0 {
		return nil
	}
	if img := &lc.images[i-1]; addr < img.end {
		return img
	}
	return nil
}

func (lc *looseCache) machoFor(img *looseImage) (*macho.File, error) {
	if m, ok := lc.open[img.path]; ok {
		return m, nil
	}
	m, err := macho.Open(img.path)
	if err != nil {
		// Universal/fat dylib: use the last arch, matching how
		// search.ForEachMacho indexed it in newLooseCache.
		fat, ferr := macho.OpenFat(img.path)
		if ferr != nil {
			return nil, err
		}
		lc.fats = append(lc.fats, fat)
		m = fat.Arches[len(fat.Arches)-1].File
	}
	lc.open[img.path] = m
	return m, nil
}

// symbolicate resolves a shared-cache VM address to an image name, symbol and
// the symbol's start address. ok is false when addr is in no indexed dylib.
func (lc *looseCache) symbolicate(addr uint64) (image, symbol string, symStart uint64, ok bool) {
	img := lc.imageContaining(addr)
	if img == nil {
		return "", "", 0, false
	}
	m, err := lc.machoFor(img)
	if err != nil {
		return "", "", 0, false
	}
	fn, err := m.GetFunctionForVMAddr(addr)
	if err != nil {
		return img.name, "", 0, true // image known, function boundaries unavailable
	}
	if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
		for _, s := range syms {
			if s.Name != "" {
				return img.name, s.Name, fn.StartAddr, true
			}
		}
	}
	return img.name, fmt.Sprintf("func_%x", fn.StartAddr), fn.StartAddr, true
}
