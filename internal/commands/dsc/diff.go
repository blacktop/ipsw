package dsc

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/apex/log"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

const (
	// MaxConcurrentImages is the maximum number of image pairs to process concurrently.
	// Each pair requires ~4.6 MB for DiffInfo objects.
	// With 8 workers: 8 × 4.6 MB = ~37 MB peak (well under 1 GB target)
	MaxConcurrentImages = 8
)

// Diff compares two DSC files using a parallel streaming approach.
//
// This implementation processes images using a worker pool to balance speed and memory:
// - Sequential: 5m36s, 721 MB peak (12.4 img/s)
// - Parallel (8 workers): Target 1-2m, <1 GB peak (50+ img/s)
//
// Memory safety: Semaphore limits concurrent workers to prevent memory explosion.
//
// Thread safety: ParseLocalSymbols() is protected by mutexes since it modifies
// shared state in the DSC file's AddressToSymbol map.
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

	// Step 3: Process common images using parallel worker pool
	// Memory safety: Semaphore limits concurrent workers
	startTime := time.Now()
	var (
		mu             sync.Mutex  // Protects diff.Updated and progress counters
		f1SymMu        sync.Mutex  // Protects f1.AddressToSymbol map (shared by all f1 images)
		f2SymMu        sync.Mutex  // Protects f2.AddressToSymbol map (shared by all f2 images)
		processedCount int
		lastLogTime    time.Time
	)

	// Create semaphore to limit concurrent workers
	sem := semaphore.NewWeighted(MaxConcurrentImages)
	g, ctx := errgroup.WithContext(context.Background())

	// Process images in parallel with concurrency limit
	for i, name := range commonNames {
		// Capture loop variables
		idx := i
		imageName := name

		// Acquire semaphore (blocks if MaxConcurrentImages workers are active)
		if err := sem.Acquire(ctx, 1); err != nil {
			return nil, err
		}

		// Launch worker goroutine
		g.Go(func() error {
			defer sem.Release(1)

			// Load old image (with mutex protection for symbol parsing)
			oldImg := oldImages[imageName]
			oldMacho, err := extractImageWithSymbols(oldImg, &f1SymMu)
			if err != nil {
				log.Errorf("failed to extract old image %s: %v", imageName, err)
				return nil // Non-fatal: continue processing other images
			}

			// Load new image (with mutex protection for symbol parsing)
			newImg := newImages[imageName]
			newMacho, err := extractImageWithSymbols(newImg, &f2SymMu)
			if err != nil {
				log.Errorf("failed to extract new image %s: %v", imageName, err)
				oldMacho.Close()
				return nil
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
				log.Errorf("failed to compute diff for %s: %v", imageName, err)
				return nil
			}

			if len(diffStr) > 0 {
				mu.Lock()
				diff.Updated[imageName] = diffStr
				mu.Unlock()
			}

			// Progress reporting with ETA
			mu.Lock()
			processedCount++
			shouldLog := conf.Verbose && processedCount%100 == 0 && time.Since(lastLogTime) >= 10*time.Second
			if shouldLog {
				elapsed := time.Since(startTime)
				rate := float64(processedCount) / elapsed.Seconds()
				remaining := len(commonNames) - processedCount
				eta := time.Duration(float64(remaining)/rate) * time.Second

				log.Debugf("Processing common images: %d/%d (%.1f img/s, %d workers, ETA: %v)",
					processedCount, len(commonNames), rate, MaxConcurrentImages, eta.Round(time.Second))
				lastLogTime = time.Now()
			}
			mu.Unlock()

			// Force GC periodically to keep memory under control
			// In parallel mode, we GC less frequently since workers already limit memory
			if idx%200 == 0 && idx > 0 {
				runtime.GC()
			}

			return nil
		})
	}

	// Wait for all workers to complete
	if err := g.Wait(); err != nil {
		return nil, err
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
// The symMu mutex protects ParseLocalSymbols() which modifies shared DSC file state.
func extractImageWithSymbols(img *dyld.CacheImage, symMu *sync.Mutex) (*macho.File, error) {
	m, err := img.GetMacho()
	if err != nil {
		return nil, err
	}

	// Add private symbols to the macho
	// THREAD SAFETY: ParseLocalSymbols() writes to shared DSC cache.AddressToSymbol map
	// Must be protected with mutex when called from parallel workers
	symMu.Lock()
	err = img.ParseLocalSymbols(false)
	symMu.Unlock()

	if err == nil {
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
