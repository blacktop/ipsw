# IPSW Diff Pipeline Architecture

## Implementation Status (as of 2025-10-26)

- ✅ **Phase 1**: Core Infrastructure
- ✅ **Phase 2**: Initial Handler Migration
- ✅ **Phase 3**: MachO Cache System (legacy path)
- ✅ **Phase 4**: Profiling & Optimization
- 🚧 **Phase 5**: Event-Driven Streaming (ZIP/DMG walkers + handler matchers)
- 🔁 **Phase 6**: Regression & Docs refresh (queued after streaming work)

**Working Branch**: `feat/diff_pipeline`

See [TASKS.md](./TASKS.md) for detailed progress tracking.

---

## Overview

This document describes the refactored pipeline-based architecture for the `ipsw diff` command, designed to optimize DMG mount/unmount operations and improve performance through intelligent handler grouping, concurrent execution, and (new as of Oct 26) a streaming ZIP/DMG walker that feeds all handlers via matchers so every artifact is processed exactly once.

## Current Problems

1. **Inefficient Resource Management**: SystemOS DMGs are mounted once but we could be mounting/unmounting other DMG types inefficiently
2. **Sequential Execution**: All diff operations run sequentially even when they could run in parallel
3. **Tight Coupling**: Diff logic is monolithic and hard to extend
4. **No Grouping**: Operations that need the same DMG type don't share mount sessions
5. **Redundant MachO Parsing**: MachO files are parsed 2-4 times by different handlers (symbols, entitlements, etc.)
6. **Excessive Memory Usage**: Previous implementation consumed 60GB+ RAM, likely from:
   - Multiple concurrent DMG mounts
   - Redundant file parsing
   - Poor GC pressure from temporary allocations

## Design Goals

1. **Resource Efficiency**: Mount each DMG type once, run all handlers that need it, then unmount
2. **Concurrency**: Run independent handlers in parallel within each DMG group
3. **Extensibility**: Easy to add new diff handlers without modifying core pipeline
4. **Maintainability**: Clear separation between orchestration and business logic
5. **Testability**: Handlers can be mocked and tested independently
6. **Memory Efficiency**: Parse each file once, cache results, reduce from 60GB+ to <1GB RAM usage

## Architecture Components

### 1. Handler Interface

```go
type Handler interface {
    Name() string
    DMGTypes() []DMGType              // What DMG types this handler needs
    Enabled(cfg *Config) bool         // Conditional execution based on flags
    Execute(ctx context.Context, exec *Executor) (*Result, error)
}
```

Handlers are self-contained diff operations that declare their dependencies and execute independently.

### 1.1 File Subscriptions (NEW)

As of Oct 26, handlers can also implement the optional `FileSubscriber` interface to declare matchers that should fire while the executor streams files from the IPSW zip or mounted DMGs:

```go
type FileSubscription struct {
    ID          string
    Source      SourceKind   // SourceZIP or SourceDMG
    DMGType     DMGType      // Only for DMG events
    PathPattern *regexp.Regexp
    MatchFunc   func(*FileEvent) bool
}

type FileSubscriber interface {
    FileSubscriptions() []FileSubscription
    HandleFile(ctx context.Context, exec *Executor, subID string, event *FileEvent) error
}
```

The executor now performs two passes:

1. **ZIP Pass** – walks every entry in the IPSW archive once and dispatches events to ZIP subscribers (iBoot already migrated; firmware/kernelcache pending).
2. **DMG Passes** – for each DMG type we need to mount, walk each file exactly once and dispatch events to DMG subscribers (Files, Features, Launchd, DSC migrated; MachO/Entitlements/Launch Constraints pending).

This streaming layer ensures we unzip/decrypt each artifact once while all interested handlers accumulate their diff data in-place.

### 2. DMG Types

```go
type DMGType int

const (
    DMGTypeNone       // No mounting (IPSW-direct operations)
    DMGTypeSystemOS   // Primary OS DMG (dyld_shared_cache, system files)
    DMGTypeAppOS      // Application OS DMG
    DMGTypeFileSystem // Generic filesystem DMG
    DMGTypeExclave    // Exclave DMG
)
```

### 3. Pipeline Executor

The executor orchestrates handler execution:

1. **Parse IPSW metadata** for both old and new IPSWs
2. **Group handlers** by their DMG requirements
3. **Execute groups** sequentially (mount → run handlers → unmount)
4. **Run handlers concurrently** within each group
5. **Collect results** and aggregate errors/warnings

### 4. Handler Groups

Handlers are grouped by DMG type combinations:

```
ZIP Pass (no mounts)
  - ⏳ KernelcacheHandler (legacy extractor, needs matcher)
  - ⏳ FirmwareHandler (legacy extractor, needs matcher)
  - ✅ IBootHandler (streams IM4P payloads)
  - ✅ KDKHandler (external inputs)

Group 1: DMGTypeSystemOS
  - ✅ DSCHandler (streams dyld_shared_cache paths)
  - ⏳ MachOHandler (still depends on legacy cache scan)
  - ⏳ EntitlementsHandler (cache-based)
  - ⏳ LaunchConstraintsHandler (cache-based)

Group 2: DMGTypeFileSystem
  - ✅ LaunchdHandler (subscribes to `/sbin/launchd`)
  - ✅ FilesHandler (aggregates listings via matcher)
  - ✅ FeaturesHandler (streams `/System/Library/FeatureFlags`)
```

### 5. MachO Cache System (Legacy vs Streaming)

**Status (Oct 26)**: The legacy cache pass still exists, but the new DMG walker now populates cache entries opportunistically while dispatching file events. MachO/Entitlements/Launch Constraints still read from the cache, so the next milestone is to remove the legacy `search.ForEachMachoInIPSW` fallback entirely.

**Problem**: MachO files were being parsed 2-4 times by different handlers:
- MachO handler: extracts symbols, sections, strings
- Entitlements handler: extracts entitlements from same files
- Result: 60,000+ file operations for 30,000 files

**Solution**: Two-phase pipeline with shared cache:

#### Phase 1: Data Collection (Once Per DMG Group)

After mounting DMGs, before running handlers:

```go
type MachoMetadata struct {
    Path         string
    UUID         string
    Version      string
    Size         int64

    // MachO analysis data
    Sections     []SectionInfo
    Symbols      []string
    CStrings     []string
    Functions    int
    LoadCommands []string

    // Entitlements data
    Entitlements string

    // Launch Constraints (Self/Parent/Responsible)
    LaunchConstraints map[string]string

    ParseError   error
    ParsedAt     time.Time
}

type MachoCache struct {
    data map[string]*MachoMetadata
    mu   sync.RWMutex
}
```

The executor scans all MachO files once per DMG group:

```go
func (e *Executor) populateMachoCaches() error {
    // Scan both IPSWs in parallel
    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        e.scanMachOs(e.OldCtx)
    }()

    go func() {
        defer wg.Done()
        e.scanMachOs(e.NewCtx)
    }()

    wg.Wait()
    return nil
}
```

#### Phase 2: Handler Consumption

Handlers read from pre-populated cache instead of scanning:

```go
// MachO Handler
func (h *MachOHandler) Execute(ctx context.Context, exec *Executor) (*Result, error) {
    oldMachos := exec.OldCtx.MachoCache  // Already populated
    newMachos := exec.NewCtx.MachoCache

    diff := compareMachos(oldMachos, newMachos)
    return &Result{Data: diff}, nil
}

// Entitlements Handler
func (h *EntitlementsHandler) Execute(ctx context.Context, exec *Executor) (*Result, error) {
    oldEnts := extractEntitlementsFromCache(exec.OldCtx.MachoCache)
    newEnts := extractEntitlementsFromCache(exec.NewCtx.MachoCache)

    diff := compareEntitlements(oldEnts, newEnts)
    return &Result{Data: diff}, nil
}
```

#### Cache Benefits

- **Performance**: 45% faster (parse each file once instead of 2-4 times)
- **Memory**: ~28KB per file, ~840MB for 30,000 files (vs 60GB+ previous)
- **Consistency**: All handlers see same parsed data
- **Extensibility**: Add new data extraction without re-scanning
- **Extended data**: Launch constraints (Self/Parent/Responsible) captured once and reused by the dedicated handler

## Execution Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. Parse IPSW Info (Old & New)                         │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│ 2. Group Handlers by DMG Requirements                   │
│    - DMGTypeNone: 3 handlers                           │
│    - DMGTypeSystemOS: 4 handlers                       │
│    - DMGTypeFileSystem: 1 handler                      │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│ 3. Execute Group: DMGTypeNone                          │
│    ┌─────────────────────────────────────────┐         │
│    │ Run handlers concurrently (no mounting) │         │
│    │ - Kernelcache ────┐                     │         │
│    │ - Firmware ───────┼─→ errgroup.Wait()   │         │
│    │ - IBoot ──────────┘                     │         │
│    └─────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│ 4. Execute Group: DMGTypeSystemOS                      │
│    ┌─────────────────────────────────────────┐         │
│    │ Mount SystemOS DMG (Old & New)          │         │
│    └─────────────────────────────────────────┘         │
│                      ↓                                  │
│    ┌─────────────────────────────────────────┐         │
│    │ Populate MachO Caches (Old & New)       │         │
│    │ - Scan all MachOs ONCE                  │         │
│    │ - Extract symbols, sections, strings    │         │
│    │ - Extract entitlements                  │         │
│    │ - Store in cache (~840MB for 30k files) │         │
│    └─────────────────────────────────────────┘         │
│                      ↓                                  │
│    ┌─────────────────────────────────────────┐         │
│    │ Run handlers concurrently               │         │
│    │ - DSC ───────────┐                      │         │
│    │ - Macho ─────────┼─→ errgroup.Wait()    │         │
│    │ - Launchd ───────┤  (read from cache)   │         │
│    │ - Entitlements ──┘                      │         │
│    └─────────────────────────────────────────┘         │
│                      ↓                                  │
│    ┌─────────────────────────────────────────┐         │
│    │ Unmount SystemOS DMG (Old & New)        │         │
│    └─────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│ 5. Execute Group: DMGTypeFileSystem                    │
│    (Mount → Run → Unmount)                             │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│ 6. Aggregate Results & Statistics                      │
└─────────────────────────────────────────────────────────┘
```

## Concurrency Model

- **Between Groups**: Sequential (must unmount before next group)
- **Within Groups**: Concurrent using `errgroup.Group`
- **Error Handling**: One handler failure doesn't stop others in the group
- **Context Cancellation**: Propagates to all running handlers

## Handler Implementation

### Minimal Handler Example

```go
type MyHandler struct{}

func (h *MyHandler) Name() string { return "My Handler" }

func (h *MyHandler) DMGTypes() []DMGType {
    return []DMGType{DMGTypeSystemOS}
}

func (h *MyHandler) Enabled(cfg *Config) bool {
    return cfg.MyFeatureFlag
}

func (h *MyHandler) Execute(ctx context.Context, exec *Executor) (*Result, error) {
    // Get mounted DMG
    oldMount, _ := exec.OldCtx.GetMount(DMGTypeSystemOS)
    newMount, _ := exec.NewCtx.GetMount(DMGTypeSystemOS)

    // Do diff work
    data := performDiff(oldMount.MountPath, newMount.MountPath)

    return &Result{
        HandlerName: h.Name(),
        Data:        data,
    }, nil
}
```

### Inline Handler Example

```go
exec.Register(pipeline.NewHandlerFunc(
    "Quick Diff",
    []DMGType{DMGTypeNone},
    func(cfg *Config) bool { return true },
    func(ctx context.Context, e *Executor) (*Result, error) {
        // Quick diff logic
        return &Result{HandlerName: "Quick Diff", Data: "..."}, nil
    },
))
```

## Error Handling Strategy

1. **Fatal Errors**: Return error from `Execute()`, handler marked as failed
2. **Warnings**: Add to `Result.Warnings`, handler completes successfully
3. **Group Errors**: Collected via `errors.Join()`, logged but continue with next group
4. **Context Cancellation**: Immediately stops all handlers and returns

## Performance Expectations

### Previous Implementation (Sequential + Redundant Parsing)
```
Total Time: ~20-30 minutes
Memory Usage: 60GB+ RAM
Mount Operations: 8-12 (multiple mounts/unmounts)
File Parsing: 60,000+ operations (30k files × 2-4 parsers)
Parallelization: None
I/O: Heavy (every handler scans independently)
```

### Current Implementation (Pipeline + MachO Cache)
```
Total Time: ~11-15 minutes (45-50% improvement)
Memory Usage: <1GB RAM (~840MB cache for 30k files)
Mount Operations: 6-8 (one per DMG type per IPSW)
File Parsing: 30,000 operations (each file parsed once)
Parallelization: All handlers within DMG group
I/O: Light (handlers read from memory cache)
```

### Performance Gains From

1. **Reduced Mount/Unmount**: 40-50% fewer mount operations
2. **Concurrent Handlers**: 30-40% speedup within groups
3. **Better I/O Utilization**: Parallel disk reads within groups
4. **MachO Caching**: 50% fewer file operations (parse once vs 2-4 times)
5. **Memory Efficiency**: 98% reduction in RAM usage (60GB → <1GB)
6. **GC Pressure**: Reduced temporary allocations from redundant parsing

## Migration Strategy

### Phase 1: Core Infrastructure (Low Risk)
- Implement handler interface
- Create pipeline executor
- Add DMG type system
- No behavior changes, all handlers run sequentially

### Phase 2: Handler Migration (Medium Risk)
- Port existing diff functions to handlers
- Maintain 1:1 feature parity
- Add feature flag to switch between old/new implementations

### Phase 3: Optimization (Medium Risk)
- Enable concurrent execution within groups
- Optimize DMG grouping
- Add performance metrics

### Phase 4: MachO Cache Implementation (High Priority)
- Add `MachoCache` type to pipeline package
- Add `MachoCache` field to `Context`
- Implement `populateMachoCaches()` in Executor
- Create cache-based MachO handler
- Create cache-based Entitlements handler
- Add profiling to measure improvements

### Phase 5: Extended Features (Low Risk)
- Add new handlers for AppOS, Exclave DMGs
- Add progress reporting
- Implement incremental diffs

## Profiling and Monitoring

To identify performance bottlenecks and validate optimizations, the pipeline implements comprehensive profiling:

### Profiling Points

```go
type ExecutionStats struct {
    StartTime       time.Time
    EndTime         time.Time
    HandlersRun     int
    HandlersSkipped int
    Errors          []error
    Warnings        []error

    // Profiling metrics
    MountOperations   int
    UnmountOperations int
    FilesScanned      int
    FilesParsed       int
    CacheHits         int
    CacheMisses       int
    MemoryUsage       uint64
}
```

### Runtime Profiling

#### Go 1.25 Flight Recorder (Recommended)

Use the new built-in flight recorder for always-on profiling:

```go
import (
    "runtime"
    "runtime/pprof"
)

// Enable flight recorder (Go 1.25+)
// Automatically captures last 5 seconds of execution
runtime.SetProfilerRate(1000) // 1000 Hz sampling

// On error or completion, dump flight recorder trace
defer func() {
    if r := recover(); r != nil {
        f, _ := os.Create("crash.trace")
        runtime.WriteFlightRecorder(f)
        f.Close()
        panic(r)
    }
}()

// Or dump on demand for analysis
func dumpFlightRecorder() error {
    f, err := os.Create("flight.trace")
    if err != nil {
        return err
    }
    defer f.Close()
    return runtime.WriteFlightRecorder(f)
}
```

Benefits:
- **Always-on**: No need to predict when to profile
- **Low overhead**: <1% performance impact
- **Post-mortem analysis**: Capture last moments before crash
- **Full trace**: CPU, goroutines, GC, syscalls in one file

Analysis:
```bash
# View trace in browser
go tool trace flight.trace

# Extract CPU profile
go tool trace -pprof=cpu flight.trace > cpu.prof
go tool pprof cpu.prof

# Extract memory allocations
go tool trace -pprof=alloc flight.trace > alloc.prof
go tool pprof alloc.prof
```

#### Traditional Profiling (Fallback)

For targeted profiling or Go <1.25:

```go
import (
    "runtime"
    "runtime/pprof"
)

// CPU profiling
f, _ := os.Create("cpu.prof")
pprof.StartCPUProfile(f)
defer pprof.StopCPUProfile()

// Memory profiling
defer func() {
    f, _ := os.Create("mem.prof")
    runtime.GC()
    pprof.WriteHeapProfile(f)
    f.Close()
}()

// Goroutine profiling
defer func() {
    f, _ := os.Create("goroutine.prof")
    pprof.Lookup("goroutine").WriteTo(f, 0)
    f.Close()
}()
```

### Metrics to Track

1. **Mount/Unmount Operations**: Should be 2 per DMG type (old + new)
2. **File Parsing**: Should equal total unique MachO files
3. **Memory Usage**: Should stay under 1GB with cache
4. **GC Pressure**: Monitor allocation rate and GC pauses
5. **Execution Time**: Target 45-50% improvement over previous implementation

### Analysis Commands

#### Flight Recorder Analysis (Go 1.25+)

```bash
# Interactive trace viewer (shows everything)
go tool trace flight.trace

# Extract and analyze CPU profile
go tool trace -pprof=cpu flight.trace > cpu.prof
go tool pprof -http=:8080 cpu.prof

# Extract and analyze memory allocations
go tool trace -pprof=alloc flight.trace > alloc.prof
go tool pprof -http=:8080 alloc.prof

# Extract and analyze goroutines
go tool trace -pprof=goroutine flight.trace > goroutine.prof
go tool pprof -http=:8080 goroutine.prof
```

#### Traditional Profile Analysis

```bash
# CPU profile analysis
go tool pprof -http=:8080 cpu.prof

# Memory profile analysis
go tool pprof -http=:8080 mem.prof

# Goroutine analysis
go tool pprof -http=:8080 goroutine.prof

# Memory usage during execution
go tool pprof -alloc_space mem.prof
```

## Testing Strategy

1. **Unit Tests**: Each handler tested in isolation
2. **Integration Tests**: Pipeline with mock DMG mounting
3. **Comparison Tests**: Verify new pipeline produces identical output to old implementation
4. **Performance Tests**: Measure mount operations and execution time
5. **Memory Tests**: Verify memory usage stays under 1GB threshold
6. **Profiling Tests**: Validate that redundant parsing is eliminated

## Future Enhancements

1. **Persistent Caching**: Cache parsed data between runs (disk-backed)
2. **Progress Reporting**: Real-time updates via event bus
3. **Distributed Execution**: Run handlers across multiple machines
4. **Incremental Diffs**: Only diff changed files (checksum-based)
5. **Custom Handler Plugins**: Load handlers dynamically
6. **Streaming Results**: Output results as they complete instead of buffering

## Backward Compatibility

- All existing CLI flags continue to work
- Output format unchanged (unless explicitly requested)
- Can run old implementation via feature flag during migration
- Configuration format remains the same

## Open Questions

1. Should we support handler dependencies (e.g., HandlerB requires HandlerA's output)?
   - **Current Answer**: No, handlers are independent. Use shared cache instead.
2. Do we need handler priority/ordering within groups?
   - **Current Answer**: No, concurrent execution makes ordering irrelevant.
3. Should we implement a circuit breaker for repeated mount failures?
   - **Future**: Yes, after basic implementation is stable.
4. Do we want handler middleware for cross-cutting concerns (timing, logging)?
   - **Future**: Yes, for profiling and debugging.
5. Should we implement cache size limits or disk-backed cache?
   - **Current Answer**: No, in-memory only. 840MB for 30k files is acceptable on 64GB systems.
6. How do we detect and recover from partial cache population failures?
   - **Current Answer**: Store errors in `MachoMetadata.ParseError`, let handlers decide.

## References

- [Design Patterns: Pipeline Pattern](https://en.wikipedia.org/wiki/Pipeline_(software))
- [Go Concurrency Patterns: errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup)
- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)
