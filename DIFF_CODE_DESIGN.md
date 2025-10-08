# IPSW Diff Pipeline Code Design

## Package Structure

```
internal/diff/
├── diff.go                 # Main diff logic (updated)
├── adapter.go              # Legacy adapter
├── pipeline/
│   ├── types.go           # Core types and interfaces
│   ├── executor.go        # Pipeline executor
│   ├── registry.go        # Handler registry
│   ├── scheduler.go       # Stage scheduler
│   ├── resources.go       # Resource manager
│   ├── results.go         # Result collector
│   ├── concurrent.go      # Concurrent execution
│   ├── progress.go        # Progress tracking
│   └── handlers/
│       ├── base.go        # Base handler implementation
│       ├── ipsw/          # IPSW-direct handlers
│       ├── systemos/      # SystemOS DMG handlers
│       ├── filesystem/    # FileSystem DMG handlers
│       └── multi/         # Multi-DMG handlers
```

## Core Types and Interfaces

### types.go

```go
package pipeline

import (
    "context"
    "sync"
)

// DMGType represents the type of DMG resource required
type DMGType string

const (
    DMGTypeIPSW       DMGType = "ipsw"       // Direct IPSW operations
    DMGTypeSystemOS   DMGType = "systemos"   // System OS DMG
    DMGTypeFileSystem DMGType = "filesystem" // FileSystem DMG
    DMGTypeAppOS      DMGType = "appos"      // App OS DMG
    DMGTypeExclave    DMGType = "exclave"    // Exclave OS DMG
    DMGTypeMultiple   DMGType = "multiple"   // Multiple DMGs
)

// HandlerResult represents the output of a diff handler
type HandlerResult interface {
    // Name returns the handler name that produced this result
    Name() string
    // Merge combines this result with the main diff
    Merge(diff *diff.Diff) error
    // Summary returns a human-readable summary
    Summary() string
}

// DiffHandler defines the interface for all diff operations
type DiffHandler interface {
    // Name returns a unique identifier for the handler
    Name() string

    // RequiredResources returns the DMG types this handler needs
    RequiredResources() []DMGType

    // IsEnabled checks if this handler should run based on config
    IsEnabled(conf *diff.Config) bool

    // Validate performs pre-execution validation
    Validate(ctx context.Context, old, new *diff.Context) error

    // Execute runs the diff operation
    Execute(ctx context.Context, old, new *diff.Context) (HandlerResult, error)

    // Priority returns execution priority (lower = higher priority)
    Priority() int
}

// Resources represents acquired DMG resources
type Resources struct {
    Type   DMGType
    Mounts map[string]*MountInfo // keyed by "old" or "new"
}

// MountInfo contains mount point information
type MountInfo struct {
    DmgPath   string
    MountPath string
    IsMounted bool
    RefCount  int32
    mu        sync.RWMutex
}

// PipelineConfig contains pipeline configuration
type PipelineConfig struct {
    MaxConcurrency int
    Timeout        time.Duration
    FailFast       bool
    Debug          bool
}
```

### Handler Registry

```go
// registry.go
package pipeline

import (
    "fmt"
    "sort"
    "sync"
)

type Registry struct {
    handlers map[string]DiffHandler
    mu       sync.RWMutex
}

func NewRegistry() *Registry {
    return &Registry{
        handlers: make(map[string]DiffHandler),
    }
}

func (r *Registry) Register(handler DiffHandler) error {
    r.mu.Lock()
    defer r.mu.Unlock()

    name := handler.Name()
    if _, exists := r.handlers[name]; exists {
        return fmt.Errorf("handler %s already registered", name)
    }

    r.handlers[name] = handler
    return nil
}

func (r *Registry) GroupByResource(conf *diff.Config) map[DMGType][]DiffHandler {
    r.mu.RLock()
    defer r.mu.RUnlock()

    groups := make(map[DMGType][]DiffHandler)

    for _, handler := range r.handlers {
        if !handler.IsEnabled(conf) {
            continue
        }

        resources := handler.RequiredResources()
        if len(resources) == 0 {
            resources = []DMGType{DMGTypeIPSW}
        }

        for _, resource := range resources {
            groups[resource] = append(groups[resource], handler)
        }
    }

    // Sort handlers within each group by priority
    for _, handlers := range groups {
        sort.Slice(handlers, func(i, j int) bool {
            return handlers[i].Priority() < handlers[j].Priority()
        })
    }

    return groups
}
```

### Resource Manager

```go
// resources.go
package pipeline

import (
    "context"
    "fmt"
    "sync"
    "sync/atomic"

    "github.com/blacktop/ipsw/internal/utils"
)

type ResourceManager struct {
    oldContext *diff.Context
    newContext *diff.Context
    mounts     map[DMGType]*Resources
    mu         sync.Mutex
    pemDB      string
}

func NewResourceManager(old, new *diff.Context, pemDB string) *ResourceManager {
    return &ResourceManager{
        oldContext: old,
        newContext: new,
        mounts:     make(map[DMGType]*Resources),
        pemDB:      pemDB,
    }
}

func (rm *ResourceManager) Acquire(ctx context.Context, dmgType DMGType) (*Resources, error) {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    // Check if already acquired
    if res, exists := rm.mounts[dmgType]; exists {
        // Increment reference count
        for _, mi := range res.Mounts {
            atomic.AddInt32(&mi.RefCount, 1)
        }
        return res, nil
    }

    switch dmgType {
    case DMGTypeIPSW:
        // No mounting needed
        return &Resources{Type: dmgType}, nil

    case DMGTypeSystemOS:
        res, err := rm.mountSystemOS(ctx)
        if err != nil {
            return nil, err
        }
        rm.mounts[dmgType] = res
        return res, nil

    case DMGTypeFileSystem:
        res, err := rm.mountFileSystem(ctx)
        if err != nil {
            return nil, err
        }
        rm.mounts[dmgType] = res
        return res, nil

    case DMGTypeMultiple:
        // Mount all available DMGs
        res := &Resources{
            Type:   dmgType,
            Mounts: make(map[string]*MountInfo),
        }

        // Try to mount each type, don't fail if one doesn't exist
        if sysRes, err := rm.mountSystemOS(ctx); err == nil {
            for k, v := range sysRes.Mounts {
                res.Mounts["systemos_"+k] = v
            }
        }

        if fsRes, err := rm.mountFileSystem(ctx); err == nil {
            for k, v := range fsRes.Mounts {
                res.Mounts["filesystem_"+k] = v
            }
        }

        rm.mounts[dmgType] = res
        return res, nil

    default:
        return nil, fmt.Errorf("unsupported DMG type: %s", dmgType)
    }
}

func (rm *ResourceManager) Release(dmgType DMGType) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    res, exists := rm.mounts[dmgType]
    if !exists {
        return nil
    }

    // Decrement reference count
    for _, mi := range res.Mounts {
        if atomic.AddInt32(&mi.RefCount, -1) <= 0 {
            // Actually unmount
            if err := utils.Unmount(mi.MountPath, true); err != nil {
                log.Errorf("failed to unmount %s: %v", mi.MountPath, err)
            }
        }
    }

    delete(rm.mounts, dmgType)
    return nil
}

func (rm *ResourceManager) mountSystemOS(ctx context.Context) (*Resources, error) {
    oldMount, err := rm.mountDMG(ctx, rm.oldContext, "systemos")
    if err != nil {
        return nil, fmt.Errorf("failed to mount old SystemOS: %w", err)
    }

    newMount, err := rm.mountDMG(ctx, rm.newContext, "systemos")
    if err != nil {
        // Cleanup old mount
        utils.Unmount(oldMount.MountPath, true)
        return nil, fmt.Errorf("failed to mount new SystemOS: %w", err)
    }

    return &Resources{
        Type: DMGTypeSystemOS,
        Mounts: map[string]*MountInfo{
            "old": oldMount,
            "new": newMount,
        },
    }, nil
}
```

### Pipeline Executor

```go
// executor.go
package pipeline

import (
    "context"
    "fmt"
    "runtime"
    "sync"

    "golang.org/x/sync/errgroup"
)

type Pipeline struct {
    config      *PipelineConfig
    registry    *Registry
    resources   *ResourceManager
    results     *ResultCollector
    oldContext  *diff.Context
    newContext  *diff.Context
}

func NewPipeline(conf *diff.Config, old, new *diff.Context) *Pipeline {
    pipelineConf := &PipelineConfig{
        MaxConcurrency: runtime.NumCPU(),
        Timeout:        30 * time.Minute,
        FailFast:       false,
        Debug:          conf.Verbose,
    }

    registry := NewRegistry()
    RegisterHandlers(registry) // Register all handlers

    return &Pipeline{
        config:     pipelineConf,
        registry:   registry,
        resources:  NewResourceManager(old, new, conf.PemDB),
        results:    NewResultCollector(),
        oldContext: old,
        newContext: new,
    }
}

func (p *Pipeline) Execute(ctx context.Context) (*diff.Diff, error) {
    // Group handlers by resource type
    groups := p.registry.GroupByResource(p.config)

    // Define execution order
    stageOrder := []DMGType{
        DMGTypeIPSW,       // No mounting required
        DMGTypeSystemOS,   // Mount once, run multiple
        DMGTypeFileSystem, // Mount separately
        DMGTypeMultiple,   // Complex operations
    }

    // Execute each stage
    for _, dmgType := range stageOrder {
        handlers, exists := groups[dmgType]
        if !exists || len(handlers) == 0 {
            continue
        }

        log.Infof("Executing %s stage with %d handlers", dmgType, len(handlers))

        if err := p.executeStage(ctx, dmgType, handlers); err != nil {
            if p.config.FailFast {
                return nil, fmt.Errorf("stage %s failed: %w", dmgType, err)
            }
            log.Errorf("stage %s had errors: %v", dmgType, err)
        }
    }

    // Aggregate results
    return p.results.ToDiff()
}

func (p *Pipeline) executeStage(ctx context.Context, dmgType DMGType, handlers []DiffHandler) error {
    // Acquire resources
    resources, err := p.resources.Acquire(ctx, dmgType)
    if err != nil {
        return fmt.Errorf("failed to acquire resources: %w", err)
    }
    defer p.resources.Release(dmgType)

    // Update contexts with mount paths if needed
    if resources.Mounts != nil {
        if oldMount, ok := resources.Mounts["old"]; ok {
            p.oldContext.MountPath = oldMount.MountPath
        }
        if newMount, ok := resources.Mounts["new"]; ok {
            p.newContext.MountPath = newMount.MountPath
        }
    }

    // Execute handlers concurrently
    g, gctx := errgroup.WithContext(ctx)
    g.SetLimit(p.config.MaxConcurrency)

    for _, handler := range handlers {
        handler := handler // capture

        g.Go(func() error {
            // Validate first
            if err := handler.Validate(gctx, p.oldContext, p.newContext); err != nil {
                return fmt.Errorf("%s validation failed: %w", handler.Name(), err)
            }

            // Execute handler
            log.Debugf("Executing handler: %s", handler.Name())

            result, err := handler.Execute(gctx, p.oldContext, p.newContext)
            if err != nil {
                if p.config.FailFast {
                    return err
                }
                log.Errorf("handler %s failed: %v", handler.Name(), err)
                return nil // Continue with other handlers
            }

            // Store result
            p.results.Add(result)
            return nil
        })
    }

    return g.Wait()
}
```

### Example Handler Implementation

```go
// handlers/systemos/dsc.go
package systemos

import (
    "context"
    "fmt"

    "github.com/blacktop/ipsw/pkg/dyld"
    dcmd "github.com/blacktop/ipsw/internal/commands/dsc"
)

type DSCHandler struct {
    config *diff.Config
}

func NewDSCHandler(conf *diff.Config) *DSCHandler {
    return &DSCHandler{config: conf}
}

func (h *DSCHandler) Name() string {
    return "dyld_shared_cache"
}

func (h *DSCHandler) RequiredResources() []pipeline.DMGType {
    return []pipeline.DMGType{pipeline.DMGTypeSystemOS}
}

func (h *DSCHandler) IsEnabled(conf *diff.Config) bool {
    return true // Always enabled
}

func (h *DSCHandler) Priority() int {
    return 3 // High priority
}

func (h *DSCHandler) Validate(ctx context.Context, old, new *diff.Context) error {
    if old.MountPath == "" || new.MountPath == "" {
        return fmt.Errorf("mount paths not set")
    }
    return nil
}

func (h *DSCHandler) Execute(ctx context.Context, old, new *diff.Context) (pipeline.HandlerResult, error) {
    // Get DSC paths
    oldDSCs, err := dyld.GetDscPathsInMount(old.MountPath, false, false)
    if err != nil {
        return nil, fmt.Errorf("failed to get old DSC paths: %w", err)
    }

    newDSCs, err := dyld.GetDscPathsInMount(new.MountPath, false, false)
    if err != nil {
        return nil, fmt.Errorf("failed to get new DSC paths: %w", err)
    }

    // Open DSCs
    dscOld, err := dyld.Open(oldDSCs[0])
    if err != nil {
        return nil, fmt.Errorf("failed to open old DSC: %w", err)
    }
    defer dscOld.Close()

    dscNew, err := dyld.Open(newDSCs[0])
    if err != nil {
        return nil, fmt.Errorf("failed to open new DSC: %w", err)
    }
    defer dscNew.Close()

    // Perform diff
    diffResult, err := dcmd.Diff(dscOld, dscNew, &mcmd.DiffConfig{
        Markdown:   true,
        Color:      false,
        DiffTool:   "git",
        AllowList:  h.config.AllowList,
        BlockList:  h.config.BlockList,
        CStrings:   h.config.CStrings,
        FuncStarts: h.config.FuncStarts,
        Verbose:    h.config.Verbose,
    })
    if err != nil {
        return nil, err
    }

    // Get WebKit versions
    oldWebkit, _ := dcmd.GetWebkitVersion(dscOld)
    newWebkit, _ := dcmd.GetWebkitVersion(dscNew)

    return &DSCResult{
        name:      h.Name(),
        dylibs:    diffResult,
        oldWebkit: oldWebkit,
        newWebkit: newWebkit,
    }, nil
}

// DSCResult implements HandlerResult
type DSCResult struct {
    name      string
    dylibs    *mcmd.MachoDiff
    oldWebkit string
    newWebkit string
}

func (r *DSCResult) Name() string {
    return r.name
}

func (r *DSCResult) Merge(diff *diff.Diff) error {
    diff.Dylibs = r.dylibs
    diff.Old.Webkit = r.oldWebkit
    diff.New.Webkit = r.newWebkit
    return nil
}

func (r *DSCResult) Summary() string {
    return fmt.Sprintf("DSC diff complete. WebKit: %s -> %s", r.oldWebkit, r.newWebkit)
}
```

### Handler Registration

```go
// handlers/register.go
package handlers

import (
    "github.com/blacktop/ipsw/internal/diff/pipeline"
    "github.com/blacktop/ipsw/internal/diff/pipeline/handlers/ipsw"
    "github.com/blacktop/ipsw/internal/diff/pipeline/handlers/systemos"
    "github.com/blacktop/ipsw/internal/diff/pipeline/handlers/filesystem"
)

func RegisterHandlers(registry *pipeline.Registry, conf *diff.Config) {
    // IPSW-direct handlers
    registry.Register(ipsw.NewKernelcacheHandler(conf))
    registry.Register(ipsw.NewKDKHandler(conf))
    registry.Register(ipsw.NewFirmwareHandler(conf))
    registry.Register(ipsw.NewIBootHandler(conf))
    registry.Register(ipsw.NewEntitlementHandler(conf))

    // SystemOS handlers
    registry.Register(systemos.NewDSCHandler(conf))
    registry.Register(systemos.NewMachoHandler(conf))
    registry.Register(systemos.NewLaunchdHandler(conf))

    // FileSystem handlers
    registry.Register(filesystem.NewFileHandler(conf))

    // Multi-DMG handlers
    registry.Register(multi.NewFeatureFlagHandler(conf))
}
```

### Integration with Existing Code

```go
// diff.go (updated Diff method)
func (d *Diff) Diff() error {
    // Create contexts
    oldCtx := &Context{
        IPSWPath: d.Old.IPSWPath,
        Info:     d.Old.Info,
        // ... other fields
    }

    newCtx := &Context{
        IPSWPath: d.New.IPSWPath,
        Info:     d.New.Info,
        // ... other fields
    }

    // Use pipeline if enabled
    if d.conf.UsePipeline {
        pipeline := pipeline.NewPipeline(d.conf, oldCtx, newCtx)

        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
        defer cancel()

        result, err := pipeline.Execute(ctx)
        if err != nil {
            return fmt.Errorf("pipeline execution failed: %w", err)
        }

        // Copy results back
        d.Kexts = result.Kexts
        d.Dylibs = result.Dylibs
        // ... etc

        return nil
    }

    // Fall back to legacy sequential execution
    return d.legacyDiff()
}
```

## Testing Strategy

### Unit Tests

```go
// pipeline/executor_test.go
func TestPipelineExecution(t *testing.T) {
    // Create mock handlers
    mockHandler := &MockHandler{
        name:      "test_handler",
        resources: []DMGType{DMGTypeIPSW},
        result:    &MockResult{},
    }

    registry := NewRegistry()
    registry.Register(mockHandler)

    // Create pipeline with mocked resources
    pipeline := &Pipeline{
        registry:  registry,
        resources: NewMockResourceManager(),
        results:   NewResultCollector(),
    }

    // Execute
    ctx := context.Background()
    diff, err := pipeline.Execute(ctx)

    assert.NoError(t, err)
    assert.NotNil(t, diff)
    assert.True(t, mockHandler.executed)
}
```

### Integration Tests

```go
// pipeline/integration_test.go
func TestFullPipeline(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Use test IPSWs
    conf := &diff.Config{
        IpswOld: "testdata/old.ipsw",
        IpswNew: "testdata/new.ipsw",
        UsePipeline: true,
    }

    d := diff.New(conf)
    err := d.Diff()

    assert.NoError(t, err)
    assert.NotNil(t, d.Kexts)
    assert.NotNil(t, d.Dylibs)
}
```

## Migration Path

1. **Feature Flag**: Add `--pipeline` flag to enable new mode
2. **Parallel Testing**: Run both old and new implementations, compare results
3. **Gradual Rollout**: Enable by default for specific operations first
4. **Full Migration**: Remove legacy code after validation period

## Performance Considerations

- **Memory**: Stream large files instead of loading into memory
- **Concurrency**: Limit based on available CPU cores
- **I/O**: Use buffered I/O for file operations
- **Caching**: Cache extracted DMGs between runs

## Error Recovery

- **Partial Failures**: Continue with remaining handlers
- **Resource Cleanup**: Always unmount DMGs in defer blocks
- **Retry Logic**: Exponential backoff for transient failures
- **Detailed Logging**: Track each handler's execution

## Monitoring

```go
// Metrics to track
type PipelineMetrics struct {
    TotalHandlers   int
    SuccessfulCount int
    FailedCount     int
    SkippedCount    int
    ExecutionTime   map[string]time.Duration
    ResourceWaitTime time.Duration
}
```