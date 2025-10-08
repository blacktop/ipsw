package pipeline

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"golang.org/x/sync/errgroup"
)

// Executor orchestrates the pipeline execution.
//
// It manages the lifecycle of diff operations:
//  1. Parse IPSW metadata
//  2. Group handlers by DMG requirements
//  3. For each group: mount DMGs → run handlers concurrently → unmount
//  4. Collect and aggregate results
type Executor struct {
	OldCtx   *Context
	NewCtx   *Context
	Config   *Config
	handlers []Handler
	results  []*Result
	stats    *ExecutionStats
	tmpDir   string
	pemDB    string
	profiler *Profiler

	mu sync.RWMutex
}

// NewExecutor creates a new pipeline executor.
func NewExecutor(oldIPSW, newIPSW string, cfg *Config) *Executor {
	return &Executor{
		OldCtx: &Context{
			IPSWPath:   oldIPSW,
			Mounts:     make(map[DMGType]*Mount),
			MachoCache: NewMachoCache(),
		},
		NewCtx: &Context{
			IPSWPath:   newIPSW,
			Mounts:     make(map[DMGType]*Mount),
			MachoCache: NewMachoCache(),
		},
		Config: cfg,
		pemDB:  cfg.PemDB,
		stats: &ExecutionStats{
			HandlerTimes: make(map[string]time.Duration),
		},
		profiler: NewProfiler(&ProfileConfig{
			Enabled:      cfg.Profile,
			EnableMemory: cfg.MemProfile,
			OutputDir:    cfg.ProfileDir,
		}),
	}
}

// Register adds a handler to the pipeline.
func (e *Executor) Register(h Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers = append(e.handlers, h)
}

// RegisterAll adds multiple handlers to the pipeline.
func (e *Executor) RegisterAll(handlers ...Handler) {
	for h := range handlers {
		e.Register(handlers[h])
	}
}

// Execute runs the pipeline with the given context.
//
// Returns an error if initialization fails or if context is canceled.
// Individual handler errors are collected in stats but don't stop execution.
func (e *Executor) Execute(ctx context.Context) error {
	e.stats.StartTime = time.Now()
	defer func() {
		e.stats.EndTime = time.Now()

		// Capture final memory and GC stats
		e.mu.Lock()
		e.stats.EndMemory = e.captureMemoryStats()
		e.stats.NumGC, e.stats.TotalGCPause = e.captureGCStats()
		e.mu.Unlock()

		// Log summary if verbose
		if e.Config.Verbose {
			log.Info("Execution statistics:")
			log.Info(e.stats.Summary())
		}
	}()

	// Capture initial memory stats
	e.mu.Lock()
	e.stats.StartMemory = e.captureMemoryStats()
	e.stats.PeakMemory = e.stats.StartMemory
	e.mu.Unlock()

	// Start profiling if enabled (Go 1.25+ flight recorder)
	if err := e.profiler.Start(ctx); err != nil {
		log.WithError(err).Warn("Failed to start profiling")
	}
	defer e.profiler.StopOnPanic()

	// Create temp directory
	tmpDir, err := os.MkdirTemp(os.TempDir(), "ipsw-diff")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	e.tmpDir = tmpDir
	defer os.RemoveAll(tmpDir)

	// Parse IPSW metadata
	log.Info("Parsing IPSW metadata")
	if err := e.parseIPSWInfo(); err != nil {
		return fmt.Errorf("failed to parse IPSW info: %w", err)
	}

	// Group handlers by DMG requirements
	groups := e.groupHandlers()
	log.Infof("Grouped %d enabled handlers into %d groups", e.stats.HandlersRun+e.stats.HandlersSkipped-e.stats.HandlersSkipped, len(groups))

	// Execute each group
	for _, group := range groups {
		if err := e.executeGroup(ctx, group); err != nil {
			e.stats.Errors = append(e.stats.Errors, err)
			if errors.Is(err, ErrContextCanceled) {
				return err
			}
			// Continue with other groups on non-fatal errors
			log.WithError(err).Warnf("Handler group for %v failed", group.DMGTypes)
		}
	}

	return nil
}

// groupHandlers organizes handlers by their DMG requirements.
//
// Handlers with the same DMG type combination are grouped together so they
// can share the same mount session and run concurrently.
func (e *Executor) groupHandlers() []*HandlerGroup {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Group handlers by DMG type combinations
	groupMap := make(map[string]*HandlerGroup)

	for h := range e.handlers {
		handler := e.handlers[h]
		if !handler.Enabled(e.Config) {
			e.stats.HandlersSkipped++
			continue
		}

		// Create a key from DMG types
		dmgTypes := handler.DMGTypes()
		key := dmgTypesKey(dmgTypes)

		if _, exists := groupMap[key]; !exists {
			groupMap[key] = &HandlerGroup{
				DMGTypes: dmgTypes,
				Handlers: []Handler{},
			}
		}
		groupMap[key].Handlers = append(groupMap[key].Handlers, handler)
	}

	// Convert map to slice
	var groups []*HandlerGroup
	for _, group := range groupMap {
		groups = append(groups, group)
	}

	return groups
}

// executeGroup runs all handlers in a group with the required DMGs mounted.
func (e *Executor) executeGroup(ctx context.Context, group *HandlerGroup) error {
	// Mount required DMGs
	if err := e.mountDMGs(group.DMGTypes); err != nil {
		return fmt.Errorf("%w: %v", ErrDMGMountFailed, err)
	}
	defer e.unmountDMGs(group.DMGTypes)

	// Populate MachO caches after mounting but before handlers run
	// This scans all MachO files once and caches the data for handlers to consume
	if err := e.populateMachoCaches(ctx); err != nil {
		return fmt.Errorf("failed to populate MachO caches: %w", err)
	}

	// Execute handlers concurrently within the group
	g, gctx := errgroup.WithContext(ctx)
	resultsChan := make(chan *Result, len(group.Handlers))

	for h := range group.Handlers {
		handler := group.Handlers[h] // capture for goroutine
		g.Go(func() error {
			// Track handler execution time
			startTime := time.Now()
			defer func() {
				duration := time.Since(startTime)
				e.mu.Lock()
				e.stats.HandlerTimes[handler.Name()] = duration
				e.mu.Unlock()
				log.Infof("Handler %s completed in %s", handler.Name(), duration)
			}()

			log.Infof("Running %s", handler.Name())
			result, err := handler.Execute(gctx, e)
			if err != nil {
				log.WithError(err).Errorf("Handler %s failed", handler.Name())
				return fmt.Errorf("%w: %s: %v", ErrHandlerFailed, handler.Name(), err)
			}

			// Update peak memory after handler execution
			e.updatePeakMemory()

			if result != nil {
				resultsChan <- result
			}
			e.mu.Lock()
			e.stats.HandlersRun++
			e.mu.Unlock()
			return nil
		})
	}

	// Collect errors (don't fail on first error, collect all)
	var errs []error
	if err := g.Wait(); err != nil {
		errs = append(errs, err)
	}
	close(resultsChan)

	// Collect results
	for result := range resultsChan {
		e.mu.Lock()
		e.results = append(e.results, result)
		e.stats.Warnings = append(e.stats.Warnings, result.Warnings...)
		e.mu.Unlock()
	}

	return errors.Join(errs...)
}

// mountDMGs mounts the required DMG types for both old and new contexts.
func (e *Executor) mountDMGs(dmgTypes []DMGType) error {
	startTime := time.Now()
	defer func() {
		e.mu.Lock()
		e.stats.MountTime += time.Since(startTime)
		e.mu.Unlock()
	}()

	for dmgType := range dmgTypes {
		if dmgTypes[dmgType] == DMGTypeNone {
			continue
		}

		// Mount for old context
		if err := e.mountDMG(e.OldCtx, dmgTypes[dmgType]); err != nil {
			return fmt.Errorf("failed to mount old %s: %w", dmgTypes[dmgType], err)
		}

		// Mount for new context
		if err := e.mountDMG(e.NewCtx, dmgTypes[dmgType]); err != nil {
			return fmt.Errorf("failed to mount new %s: %w", dmgTypes[dmgType], err)
		}
	}
	return nil
}

// mountDMG mounts a specific DMG type for a context.
func (e *Executor) mountDMG(ctx *Context, dmgType DMGType) error {
	// Check if already mounted
	if mount, ok := ctx.GetMount(dmgType); ok && mount.IsMounted {
		log.Debugf("%s already mounted for %s", dmgType, ctx.IPSWPath)
		return nil
	}

	// Get DMG path based on type (relative path from IPSW metadata)
	dmgPath, err := e.getDMGPath(ctx, dmgType)
	if err != nil {
		return fmt.Errorf("failed to get DMG path: %w", err)
	}

	// Extract DMG from IPSW if not already extracted
	if err := e.extractDMG(ctx, &dmgPath); err != nil {
		return fmt.Errorf("failed to extract DMG: %w", err)
	}

	// Handle AEA encryption if needed
	if err := e.handleAEADecryption(&dmgPath); err != nil {
		return err
	}

	// Mount the DMG
	log.Infof("Mounting %s: %s", dmgType, dmgPath)
	mountPath, alreadyMounted, err := utils.MountDMG(dmgPath, "")
	if err != nil && !errors.Is(err, utils.ErrMountResourceBusy) {
		return fmt.Errorf("failed to mount: %w", err)
	}

	// Increment mount counter if we actually mounted (not already mounted)
	if !alreadyMounted {
		e.mu.Lock()
		e.stats.MountCount++
		e.mu.Unlock()
	}

	ctx.SetMount(dmgType, &Mount{
		DMGPath:   dmgPath,
		MountPath: mountPath,
		IsMounted: !alreadyMounted,
		Type:      dmgType,
	})

	return nil
}

// unmountDMGs unmounts all DMG types for both contexts.
func (e *Executor) unmountDMGs(dmgTypes []DMGType) {
	startTime := time.Now()
	defer func() {
		e.mu.Lock()
		e.stats.UnmountTime += time.Since(startTime)
		e.mu.Unlock()
	}()

	for dmgType := range dmgTypes {
		if dmgTypes[dmgType] == DMGTypeNone {
			continue
		}
		e.unmountDMG(e.OldCtx, dmgTypes[dmgType])
		e.unmountDMG(e.NewCtx, dmgTypes[dmgType])
	}
}

// unmountDMG unmounts a specific DMG for a context.
func (e *Executor) unmountDMG(ctx *Context, dmgType DMGType) {
	mount, ok := ctx.GetMount(dmgType)
	if !ok || !mount.IsMounted {
		return
	}

	log.Infof("Unmounting %s: %s", dmgType, mount.MountPath)
	if err := utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(mount.MountPath, true)
	}); err != nil {
		log.WithError(err).Errorf("Failed to unmount %s", dmgType)
	} else {
		// Increment unmount counter on success
		e.mu.Lock()
		e.stats.UnmountCount++
		e.mu.Unlock()
	}

	// Clean up extracted DMG
	if err := os.Remove(mount.DMGPath); err != nil {
		log.WithError(err).Debugf("Failed to remove DMG %s", mount.DMGPath)
	}
}

// Results returns all collected results.
func (e *Executor) Results() []*Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// Return a copy to prevent external modification
	results := make([]*Result, len(e.results))
	copy(results, e.results)
	return results
}

// Stats returns the execution statistics.
func (e *Executor) Stats() *ExecutionStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// Return a copy to prevent external modification
	statsCopy := *e.stats
	return &statsCopy
}

// GetResult returns the result from a specific handler by name.
func (e *Executor) GetResult(handlerName string) (*Result, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for result := range e.results {
		if e.results[result].HandlerName == handlerName {
			return e.results[result], true
		}
	}
	return nil, false
}

// TempDir returns the temporary directory path.
func (e *Executor) TempDir() string {
	return e.tmpDir
}

// captureMemoryStats captures current memory statistics.
func (e *Executor) captureMemoryStats() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc // Bytes allocated and still in use
}

// captureGCStats captures garbage collection statistics.
func (e *Executor) captureGCStats() (numGC uint32, totalPause time.Duration) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Calculate total GC pause time
	for i := range m.PauseNs {
		totalPause += time.Duration(m.PauseNs[i])
	}

	return m.NumGC, totalPause
}

// updatePeakMemory updates the peak memory usage if current usage is higher.
func (e *Executor) updatePeakMemory() {
	current := e.captureMemoryStats()
	e.mu.Lock()
	defer e.mu.Unlock()
	if current > e.stats.PeakMemory {
		e.stats.PeakMemory = current
	}
}

// Helper functions

// dmgTypesKey creates a unique key from DMG types for grouping.
func dmgTypesKey(types []DMGType) string {
	if len(types) == 0 {
		return "none"
	}
	// Sort for consistent keys
	sorted := make([]DMGType, len(types))
	copy(sorted, types)
	slices.SortFunc(sorted, func(a, b DMGType) int {
		return int(a) - int(b)
	})

	var key strings.Builder
	for i, t := range sorted {
		if i > 0 {
			key.WriteString(",")
		}
		key.WriteString(t.String())
	}
	return key.String()
}

// parseIPSWInfo parses metadata for both old and new IPSWs.
func (e *Executor) parseIPSWInfo() error {
	// Parse old IPSW
	oldInfo, err := info.Parse(e.OldCtx.IPSWPath)
	if err != nil {
		return fmt.Errorf("failed to parse old IPSW: %w", err)
	}
	e.OldCtx.Info = oldInfo
	e.OldCtx.Version = oldInfo.Plists.BuildManifest.ProductVersion
	e.OldCtx.Build = oldInfo.Plists.BuildManifest.ProductBuildVersion
	folder, err := oldInfo.GetFolder()
	if err != nil {
		log.WithError(err).Warn("failed to get old IPSW folder")
	}
	e.OldCtx.Folder = filepath.Join(e.tmpDir, folder)

	// Parse new IPSW
	newInfo, err := info.Parse(e.NewCtx.IPSWPath)
	if err != nil {
		return fmt.Errorf("failed to parse new IPSW: %w", err)
	}
	e.NewCtx.Info = newInfo
	e.NewCtx.Version = newInfo.Plists.BuildManifest.ProductVersion
	e.NewCtx.Build = newInfo.Plists.BuildManifest.ProductBuildVersion
	folder, err = newInfo.GetFolder()
	if err != nil {
		log.WithError(err).Warn("failed to get new IPSW folder")
	}
	e.NewCtx.Folder = filepath.Join(e.tmpDir, folder)

	log.Infof("Old: %s (%s)", e.OldCtx.Version, e.OldCtx.Build)
	log.Infof("New: %s (%s)", e.NewCtx.Version, e.NewCtx.Build)

	return nil
}

// getDMGPath returns the path to a specific DMG type within an IPSW.
func (e *Executor) getDMGPath(ctx *Context, dmgType DMGType) (string, error) {
	var dmgPath string
	var err error

	switch dmgType {
	case DMGTypeSystemOS:
		dmgPath, err = ctx.Info.GetSystemOsDmg()
		if err != nil {
			if errors.Is(err, info.ErrorCryptexNotFound) {
				// Fallback to filesystem DMG
				log.Debug("SystemOS DMG not found, trying filesystem DMG")
				dmgPath, err = ctx.Info.GetFileSystemOsDmg()
				if err != nil {
					return "", fmt.Errorf("failed to get filesystem DMG: %w", err)
				}
			} else {
				return "", fmt.Errorf("failed to get SystemOS DMG: %w", err)
			}
		}
	case DMGTypeFileSystem:
		dmgPath, err = ctx.Info.GetFileSystemOsDmg()
		if err != nil {
			return "", fmt.Errorf("failed to get FileSystem DMG: %w", err)
		}
	case DMGTypeAppOS, DMGTypeExclave:
		// TODO: implement when these DMG types are needed
		return "", fmt.Errorf("DMG type %s not yet implemented", dmgType)
	default:
		return "", fmt.Errorf("unsupported DMG type: %s", dmgType)
	}

	return dmgPath, nil
}

// extractDMG extracts a DMG from the IPSW zip if not already extracted.
func (e *Executor) extractDMG(ctx *Context, dmgPath *string) error {
	// Check if DMG already exists
	if _, err := os.Stat(*dmgPath); err == nil {
		log.Debugf("Found extracted %s", *dmgPath)
		return nil
	}

	// Extract from IPSW
	log.Infof("Extracting %s from IPSW", filepath.Base(*dmgPath))
	dmgs, err := utils.Unzip(ctx.IPSWPath, "", func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), *dmgPath)
	})
	if err != nil {
		return fmt.Errorf("failed to extract %s from IPSW: %w", *dmgPath, err)
	}
	if len(dmgs) == 0 {
		return fmt.Errorf("failed to find %s in IPSW", *dmgPath)
	}

	// Update path to extracted file (utils.Unzip returns full paths)
	*dmgPath = dmgs[0]
	return nil
}

// handleAEADecryption decrypts an AEA-encrypted DMG if needed.
func (e *Executor) handleAEADecryption(dmgPath *string) error {
	if filepath.Ext(*dmgPath) != ".aea" {
		return nil
	}

	aeaPath := *dmgPath
	log.Infof("Decrypting AEA: %s", filepath.Base(aeaPath))

	decrypted, err := aea.Decrypt(&aea.DecryptConfig{
		Input:    aeaPath,
		Output:   filepath.Dir(aeaPath),
		PemDB:    e.pemDB,
		Insecure: false,
	})
	if err != nil {
		return fmt.Errorf("failed to decrypt AEA: %w", err)
	}

	// Verify decrypted file exists
	if _, err := os.Stat(decrypted); err != nil {
		return fmt.Errorf("decrypted DMG not found: %w", err)
	}

	// Remove original .aea file to save space
	if err := os.Remove(aeaPath); err != nil {
		log.WithError(err).Warnf("failed to remove original .aea file: %s", aeaPath)
	}

	*dmgPath = decrypted
	return nil
}

// populateMachoCaches scans all MachO files in both IPSWs and populates the caches.
//
// This is called ONCE after DMG mounting but BEFORE handlers run. It eliminates
// redundant file parsing by scanning each MachO file once and storing all extracted
// data in memory for handlers to consume.
//
// Expected memory usage: ~840MB for 30,000 files (~28KB per file)
func (e *Executor) populateMachoCaches(ctx context.Context) error {
	// Check if we need to populate caches (only for SystemOS group)
	// Other groups don't need MachO scanning
	_, hasOldMount := e.OldCtx.GetMount(DMGTypeSystemOS)
	_, hasNewMount := e.NewCtx.GetMount(DMGTypeSystemOS)

	if !hasOldMount && !hasNewMount {
		// No SystemOS DMGs mounted, skip cache population
		return nil
	}

	// Track cache population time
	startTime := time.Now()
	log.Info("Populating MachO caches...")

	// Scan both IPSWs in parallel
	var wg sync.WaitGroup
	var oldErr, newErr error

	if hasOldMount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Debug("Scanning MachO files in old IPSW...")
			oldErr = e.scanMachOs(ctx, e.OldCtx)
		}()
	}

	if hasNewMount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Debug("Scanning MachO files in new IPSW...")
			newErr = e.scanMachOs(ctx, e.NewCtx)
		}()
	}

	wg.Wait()

	// Check for errors
	if oldErr != nil {
		return fmt.Errorf("failed to scan old IPSW: %w", oldErr)
	}
	if newErr != nil {
		return fmt.Errorf("failed to scan new IPSW: %w", newErr)
	}

	// Record cache metrics
	e.mu.Lock()
	e.stats.CachePopulated = true
	e.stats.CachePopulateTime = time.Since(startTime)
	e.stats.OldCacheSize = e.OldCtx.MachoCache.Len()
	e.stats.NewCacheSize = e.NewCtx.MachoCache.Len()
	e.stats.OldCacheErrors = e.OldCtx.MachoCache.ErrorCount()
	e.stats.NewCacheErrors = e.NewCtx.MachoCache.ErrorCount()
	e.mu.Unlock()

	// Log summary
	log.Infof("MachO cache populated: %d files (old), %d files (new) in %s",
		e.stats.OldCacheSize, e.stats.NewCacheSize, e.stats.CachePopulateTime)

	if e.stats.OldCacheErrors > 0 || e.stats.NewCacheErrors > 0 {
		log.Warnf("Cache population errors: %d (old), %d (new)",
			e.stats.OldCacheErrors, e.stats.NewCacheErrors)
	}

	return nil
}

// scanMachOs scans all MachO files in the IPSW and populates the cache.
func (e *Executor) scanMachOs(ctx context.Context, ipswCtx *Context) error {
	return search.ForEachMachoInIPSW(ipswCtx.IPSWPath, e.pemDB, func(path string, m *macho.File) error {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Extract all metadata from this MachO file
		metadata := e.extractMachoMetadata(path, m)

		// Store in cache
		ipswCtx.MachoCache.Set(path, metadata)

		return nil
	})
}

// extractMachoMetadata extracts all relevant data from a MachO file.
//
// This is the single point where we parse each file. All data needed by
// any handler is extracted here to avoid redundant parsing.
func (e *Executor) extractMachoMetadata(path string, m *macho.File) *MachoMetadata {
	metadata := &MachoMetadata{
		Path:     path,
		ParsedAt: time.Now(),
	}

	// Extract UUID
	if m.UUID() != nil {
		metadata.UUID = m.UUID().String()
	}

	// Extract version
	if m.SourceVersion() != nil {
		metadata.Version = m.SourceVersion().Version.String()
	}

	// Extract file size
	if stat, err := os.Stat(path); err == nil {
		metadata.Size = stat.Size()
	}

	// Extract sections (applying allow/block lists)
	for _, s := range m.Sections {
		sectionName := s.Seg + "." + s.Name

		// Apply allow list
		if len(e.Config.AllowList) > 0 {
			if !slices.Contains(e.Config.AllowList, sectionName) {
				continue
			}
		}

		// Apply block list
		if len(e.Config.BlockList) > 0 {
			if slices.Contains(e.Config.BlockList, sectionName) {
				continue
			}
		}

		metadata.Sections = append(metadata.Sections, SectionInfo{
			Name: sectionName,
			Size: s.Size,
		})
	}

	// Extract symbols
	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			metadata.Symbols = append(metadata.Symbols, sym.Name)
		}
		slices.Sort(metadata.Symbols)
	}

	// Extract functions
	if fns := m.GetFunctions(); fns != nil {
		metadata.Functions = len(fns)
	}

	// Extract imported libraries
	if imports := m.ImportedLibraries(); len(imports) > 0 {
		metadata.Imports = append(metadata.Imports, imports...)
	}

	// Extract C strings (expensive, only if enabled)
	if e.Config.CStrings {
		if cs, err := m.GetCStrings(); err == nil {
			for _, val := range cs {
				for str := range val {
					metadata.CStrings = append(metadata.CStrings, str)
				}
			}
			slices.Sort(metadata.CStrings)
		}

		if cfstrs, err := m.GetCFStrings(); err == nil {
			for _, val := range cfstrs {
				metadata.CStrings = append(metadata.CStrings, val.Name)
			}
			slices.Sort(metadata.CStrings)
		}
	}

	// Extract load commands
	for _, lc := range m.Loads {
		metadata.LoadCommands = append(metadata.LoadCommands, lc.Command().String())
	}

	// Extract entitlements (if code signature exists)
	if m.CodeSignature() != nil {
		// Try normal entitlements first
		if len(m.CodeSignature().Entitlements) > 0 {
			metadata.Entitlements = m.CodeSignature().Entitlements
		} else if len(m.CodeSignature().EntitlementsDER) > 0 {
			// Fallback to DER entitlements
			if decoded, err := ents.DerDecode(m.CodeSignature().EntitlementsDER); err == nil {
				metadata.Entitlements = decoded
			}
		}
	}

	return metadata
}
