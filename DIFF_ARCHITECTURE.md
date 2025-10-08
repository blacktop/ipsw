# IPSW Diff Pipeline Architecture

## Executive Summary

This document outlines a pipeline-based architecture for the `ipsw diff` command that optimizes DMG mount/unmount operations by grouping operations by their DMG requirements and executing them in an efficient, concurrent pipeline.

## Current Issues

The existing implementation inefficiently:
- Mounts SystemOS DMGs once and runs multiple operations sequentially
- Doesn't group operations by their DMG requirements
- Misses opportunities for parallelization
- Doesn't handle different DMG types (AppOS, FileSystem, Exclave)

## Proposed Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         Pipeline Executor                         │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Scheduler  │  │    Handler   │  │    Result    │          │
│  │              │──│    Registry  │──│   Collector  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────────────────────────────────────────┐            │
│  │              DMG Resource Manager                │            │
│  └─────────────────────────────────────────────────┘            │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  IPSW-Direct │  │   SystemOS   │  │  FileSystem  │  ...     │
│  │   Handlers   │  │   Handlers   │  │   Handlers   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Handler Interface

```go
type DiffHandler interface {
    // Name returns a unique identifier for the handler
    Name() string

    // RequiredResources returns the DMG types this handler needs
    RequiredResources() []DMGType

    // IsEnabled checks if this handler should run based on config
    IsEnabled(conf *Config) bool

    // Validate performs pre-execution validation
    Validate(ctx context.Context, old, new *Context) error

    // Execute runs the diff operation
    Execute(ctx context.Context, old, new *Context) (Result, error)

    // Priority returns execution priority (lower = higher priority)
    Priority() int
}
```

### DMG Type System

```go
type DMGType string

const (
    DMGTypeIPSW      DMGType = "ipsw"      // Direct IPSW operations (no mount)
    DMGTypeSystemOS  DMGType = "systemos"  // System OS DMG
    DMGTypeFileSystem DMGType = "filesystem" // FileSystem DMG
    DMGTypeAppOS     DMGType = "appos"     // App OS DMG
    DMGTypeExclave   DMGType = "exclave"   // Exclave OS DMG
    DMGTypeMultiple  DMGType = "multiple"  // Requires multiple DMGs
)
```

### Handler Categorization

| Handler | DMG Type | Description | Priority |
|---------|----------|-------------|----------|
| **IPSW-Direct** (No mounting required) |||
| parseKernelcache | IPSW | Extract & diff kernelcaches | 1 |
| parseKDKs | IPSW | Process KDK symbols | 2 |
| parseFirmwares | IPSW | Extract & diff firmwares | 7 |
| parseIBoot | IPSW | Extract & diff iBoot | 8 |
| parseEntitlements | IPSW | Extract & diff entitlements | 10 |
| **SystemOS DMG** |||
| parseDSC | SystemOS | Diff dyld_shared_cache | 3 |
| parseMachos | SystemOS | Diff MachO binaries | 4 |
| parseLaunchdPlists | SystemOS | Diff launchd configs | 5 |
| **FileSystem DMG** |||
| parseFiles | FileSystem | Diff filesystem contents | 9 |
| **Multiple DMGs** |||
| parseFeatureFlags | Multiple | Search across all DMGs | 6 |

### Pipeline Execution Flow

```
1. Initialize Pipeline
   ├── Load configuration
   ├── Register all handlers
   └── Initialize contexts (Old/New)

2. Group Handlers by Resource
   ├── Group 1: IPSW-Direct handlers
   ├── Group 2: SystemOS handlers
   ├── Group 3: FileSystem handlers
   └── Group 4: Multi-DMG handlers

3. Execute Pipeline Stages
   For each resource group:
   ├── Acquire resources (mount DMGs if needed)
   ├── Execute handlers concurrently (using errgroup)
   ├── Collect results
   └── Release resources (unmount DMGs)

4. Aggregate Results
   └── Combine all handler results into final Diff
```

### Concurrency Model

```go
func (p *Pipeline) executeStage(ctx context.Context, dmgType DMGType, handlers []DiffHandler) error {
    // Acquire resources
    resources, err := p.resourceManager.Acquire(ctx, dmgType)
    if err != nil {
        return err
    }
    defer p.resourceManager.Release(dmgType)

    // Execute handlers concurrently
    g, gctx := errgroup.WithContext(ctx)
    g.SetLimit(runtime.NumCPU()) // Limit concurrent operations

    for _, handler := range handlers {
        handler := handler // capture loop variable
        g.Go(func() error {
            result, err := handler.Execute(gctx, p.oldCtx, p.newCtx)
            if err != nil {
                // Log error but don't fail entire pipeline
                p.logger.WithError(err).Errorf("handler %s failed", handler.Name())
                return nil // Continue with other handlers
            }
            p.results.Store(handler.Name(), result)
            return nil
        })
    }

    return g.Wait()
}
```

### Resource Management

The DMG Resource Manager ensures efficient mount/unmount operations:

```go
type ResourceManager struct {
    mounts   map[DMGType]*MountInfo
    mu       sync.RWMutex
    pemDB    string
}

type MountInfo struct {
    OldMount mount
    NewMount mount
    RefCount int32 // For shared resources
}

func (rm *ResourceManager) Acquire(ctx context.Context, dmgType DMGType) (*Resources, error) {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    switch dmgType {
    case DMGTypeIPSW:
        // No mounting needed, return IPSW paths
        return &Resources{Type: dmgType}, nil

    case DMGTypeSystemOS:
        if mi, exists := rm.mounts[dmgType]; exists {
            atomic.AddInt32(&mi.RefCount, 1)
            return &Resources{Type: dmgType, Mounts: mi}, nil
        }
        // Mount SystemOS DMGs
        mi := rm.mountSystemOS(ctx)
        rm.mounts[dmgType] = mi
        return &Resources{Type: dmgType, Mounts: mi}, nil

    case DMGTypeMultiple:
        // Mount all required DMGs
        return rm.mountAll(ctx)
    }
}
```

### Error Handling Strategy

1. **Handler-level errors**: Log but continue pipeline
2. **Resource errors**: Fail fast (can't proceed without DMG)
3. **Critical errors**: Stop pipeline with context cancellation
4. **Validation errors**: Fail before execution begins

### Context Propagation

Each handler receives a context with:
- Cancellation support
- Timeout configuration
- Shared resources (mounts, paths)
- Configuration flags
- Progress tracking

## Benefits

### Performance Improvements
- **Reduced mount operations**: Mount each DMG once per pipeline
- **Parallel execution**: Handlers run concurrently within stages
- **Resource pooling**: Shared DMG mounts across handlers
- **Early termination**: Context cancellation on critical errors

### Maintainability
- **Modular design**: Easy to add/remove handlers
- **Clear separation**: Each handler is self-contained
- **Testability**: Mock handlers and resources for testing
- **Extensibility**: New DMG types can be added easily

### Reliability
- **Graceful degradation**: Individual handler failures don't crash pipeline
- **Resource cleanup**: Guaranteed unmount with defer statements
- **Progress tracking**: Know which operations completed/failed
- **Validation phase**: Catch issues before execution

## Migration Strategy

1. **Phase 1**: Implement core pipeline infrastructure
2. **Phase 2**: Convert existing functions to handlers
3. **Phase 3**: Add resource management
4. **Phase 4**: Implement concurrent execution
5. **Phase 5**: Add new DMG type support

## Future Enhancements

- **Caching**: Cache extracted/mounted resources between runs
- **Incremental diff**: Only process changed components
- **Distributed execution**: Run handlers on multiple machines
- **Plugin system**: Allow external handlers via plugin API
- **Progress UI**: Real-time progress visualization