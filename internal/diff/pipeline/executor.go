package pipeline

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
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
		stats:  &ExecutionStats{},
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
	defer func() { e.stats.EndTime = time.Now() }()

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

	// Execute handlers concurrently within the group
	g, gctx := errgroup.WithContext(ctx)
	resultsChan := make(chan *Result, len(group.Handlers))

	for h := range group.Handlers {
		handler := group.Handlers[h] // capture for goroutine
		g.Go(func() error {
			log.Infof("Running %s", handler.Name())
			result, err := handler.Execute(gctx, e)
			if err != nil {
				log.WithError(err).Errorf("Handler %s failed", handler.Name())
				return fmt.Errorf("%w: %s: %v", ErrHandlerFailed, handler.Name(), err)
			}
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

// Stats returns execution statistics.
func (e *Executor) Stats() *ExecutionStats {
	return e.stats
}

// TempDir returns the temporary directory path.
func (e *Executor) TempDir() string {
	return e.tmpDir
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
