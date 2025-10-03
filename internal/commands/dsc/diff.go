package dsc

import (
	"runtime"

	"github.com/apex/log"

	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// Diff compares two DSC files using a streaming approach.
//
// This implementation processes images one pair at a time to minimize memory usage.
// Instead of loading all ~3,000 images into memory (1TB+), we only keep 2 images
// in memory at any given time (~300MB max).
func Diff(f1 *dyld.File, f2 *dyld.File, conf *mcmd.DiffConfig) (*mcmd.MachoDiff, error) {
	diff := &mcmd.MachoDiff{
		Updated: make(map[string]string),
	}

	// Step 1: Build image name sets to determine added/removed/common
	oldImages := make(map[string]*dyld.CacheImage, len(f1.Images))
	newImages := make(map[string]*dyld.CacheImage, len(f2.Images))

	for i := range f1.Images {
		oldImages[f1.Images[i].Name] = f1.Images[i]
	}

	for i := range f2.Images {
		newImages[f2.Images[i].Name] = f2.Images[i]
	}

	// Step 2: Determine which images are common (exist in both DSCs)
	commonNames := make([]string, 0, len(oldImages))
	for name := range oldImages {
		if _, exists := newImages[name]; exists {
			commonNames = append(commonNames, name)
		}
	}

	log.Debugf("DSC comparison: %d common images, %d removed, %d added",
		len(commonNames), len(oldImages)-len(commonNames), len(newImages)-len(commonNames))

	// Step 3: Process common images one pair at a time (streaming + immediate diff)
	// This is the key optimization: compute diff immediately and discard DiffInfo
	for i, name := range commonNames {
		if conf.Verbose && i%100 == 0 {
			log.Debugf("Processing common images: %d/%d", i, len(commonNames))
		}

		// Load old image
		oldImg := oldImages[name]
		oldMacho, err := extractImageWithSymbols(oldImg)
		if err != nil {
			log.Errorf("failed to extract old image %s: %v", name, err)
			continue
		}

		// Load new image
		newImg := newImages[name]
		newMacho, err := extractImageWithSymbols(newImg)
		if err != nil {
			log.Errorf("failed to extract new image %s: %v", name, err)
			oldMacho.Close() // Clean up old before continuing
			continue
		}

		// Generate TEMPORARY DiffInfo for comparison
		oldInfo := mcmd.GenerateDiffInfo(oldMacho, conf)
		newInfo := mcmd.GenerateDiffInfo(newMacho, conf)

		// Immediately close MachO files to release memory
		oldMacho.Close()
		newMacho.Close()

		// IMMEDIATELY compute diff and store ONLY the result
		diffStr, err := mcmd.ComputePairDiff(oldInfo, newInfo, conf)
		if err != nil {
			log.Errorf("failed to compute diff for %s: %v", name, err)
			continue
		}

		if len(diffStr) > 0 {
			diff.Updated[name] = diffStr
		}

		// oldInfo and newInfo go out of scope here → automatic GC can reclaim

		// Force GC every 50 images to keep memory under control
		// Testing showed this is necessary: without it, peak memory grows from 8.1 → 13.9 GiB
		// Go's automatic GC is too conservative for streaming workloads
		if i%50 == 0 && i > 0 {
			runtime.GC()
		}
	}

	// Step 4: Populate removed images list (only in old DSC)
	// We only need the image names, not the full DiffInfo
	for name := range oldImages {
		if _, exists := newImages[name]; !exists {
			diff.Removed = append(diff.Removed, name)
		}
	}

	// Step 5: Populate new images list (only in new DSC)
	// We only need the image names, not the full DiffInfo
	for name := range newImages {
		if _, exists := oldImages[name]; !exists {
			diff.New = append(diff.New, name)
		}
	}

	// Final GC to clean up before returning
	runtime.GC()

	return diff, nil
}

// extractImageWithSymbols extracts a MachO from a DSC image and adds local symbols.
func extractImageWithSymbols(img *dyld.CacheImage) (*macho.File, error) {
	m, err := img.GetMacho()
	if err != nil {
		return nil, err
	}

	// Add private symbols to the macho
	if err := img.ParseLocalSymbols(false); err == nil {
		for _, lsym := range img.LocalSymbols {
			m.Symtab.Syms = append(m.Symtab.Syms, macho.Symbol{
				Name:  lsym.Name,
				Value: lsym.Value,
				Type:  lsym.Type,
				Desc:  lsym.Desc,
				Sect:  lsym.Sect,
			})
		}
	}

	return m, nil
}
