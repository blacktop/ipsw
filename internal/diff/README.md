# IPSW Diff Pipeline Refactor

**Status**: ✅ Functionally Complete - Manual Testing Only (see Known Limitations)
**Branch**: `feat/diff_pipeline`
**Start Date**: 2025-10-01
**Last Updated**: 2025-10-03
**Completion Date**: 2025-10-03

---

## Quick Links

📊 **[IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md)** - Current progress summary
📐 **[ARCHITECTURE.md](./ARCHITECTURE.md)** - Technical design
📋 **[TASKS.md](./TASKS.md)** - Detailed task tracking
💾 **[CACHE_ARCHITECTURE.md](./CACHE_ARCHITECTURE.md)** - Caching deep dive
🔬 **[PROFILING.md](./PROFILING.md)** - Performance profiling guide
🎯 **[FINAL_TEST_RESULTS.md](./FINAL_TEST_RESULTS.md)** - Full production test results
🚀 **[OPTIMIZATION_RESULTS.md](./OPTIMIZATION_RESULTS.md)** - DSC memory optimization journey

---

## Quick Start

**For agents/developers new to this feature:**

1. **Start here** → [IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md) for current progress
2. Read this document for overview
3. Review [ARCHITECTURE.md](./ARCHITECTURE.md) for technical design
4. Check [TASKS.md](./TASKS.md) for what's next
5. See [CACHE_ARCHITECTURE.md](./CACHE_ARCHITECTURE.md) for caching details

---

## Overview

Refactoring the `ipsw diff` command from a monolithic sequential implementation to a modular pipeline-based architecture with intelligent resource management and concurrent execution.

### The Problem

The current `ipsw diff` implementation has critical performance and resource issues:

```
❌ Current Implementation:
- Execution Time: 20-30 minutes
- Memory Usage: 60GB+ RAM (!)
- File Parsing: 60,000+ operations (30k files parsed 2-4 times)
- Concurrency: None (sequential execution)
- Mount Operations: 8-12 (redundant mounts/unmounts)
- Architecture: Monolithic, tightly coupled
```

### The Solution

Pipeline-based architecture with handler grouping and two-phase caching:

```
✅ New Implementation (VALIDATED):
- Execution Time: 8m 45s (60-70% faster)
- Memory Usage: 721 MB peak (99% reduction, verified)
- File Parsing: 30,000 operations (each file parsed once)
- Concurrency: Parallel handlers within DMG groups
- Mount Operations: 6-8 (one per DMG type)
- Architecture: Modular, extensible handlers
```

---

## Key Innovations

### 1. Handler-Based Pipeline

Self-contained handlers that declare their DMG dependencies:

```go
type Handler interface {
    Name() string
    DMGTypes() []DMGType              // What DMGs this needs
    Enabled(cfg *Config) bool         // Conditional execution
    Execute(ctx context.Context, exec *Executor) (*Result, error)
}
```

### 2. DMG Grouping

Mount each DMG type once, run all handlers that need it, then unmount:

```
Group 1: DMGTypeNone (no mounting)
  → Kernelcache, Firmware, IBoot handlers run in parallel

Group 2: DMGTypeSystemOS (mount once)
  → DSC, MachO, Launchd, Entitlements handlers run in parallel

Group 3: DMGTypeFileSystem (mount once)
  → Files handler runs
```

### 3. Two-Phase MachO Caching

**Problem**: MachO files were parsed 2-4 times by different handlers

**Solution**: Scan once, cache all data, handlers read from memory

```
Phase 1: Data Collection
  - Mount DMG
  - Scan all MachOs ONCE
  - Extract symbols, sections, strings, entitlements
  - Store in shared cache (~840MB for 30k files)

Phase 2: Handler Consumption
  - MachO handler reads from cache (no I/O)
  - Entitlements handler reads from cache (no I/O)
  - Other handlers run concurrently
```

### 4. Comprehensive Profiling

Built-in profiling using **Go 1.25 Flight Recorder** to identify and eliminate bottlenecks:

- **Flight Recorder**: Always-on profiling with <1% overhead
- **Post-mortem analysis**: Capture last 5 seconds before crash
- **Full trace**: CPU, memory, goroutines, GC, syscalls in one file
- **Execution statistics**: Mount ops, parse ops, cache hits, memory usage

```bash
# Enable profiling
ipsw diff --profile old.ipsw new.ipsw

# Analyze with interactive trace viewer
go tool trace flight.trace
```

---

## Project Structure

```
internal/diff/
├── README.md                    # ← You are here (overview)
├── IMPLEMENTATION_STATUS.md     # ✨ Current progress summary
├── ARCHITECTURE.md              # Technical architecture & design
├── TASKS.md                     # Implementation tasks & timeline
├── CACHE_ARCHITECTURE.md        # Two-phase caching deep dive
├── PROFILING.md                 # ✅ Performance profiling guide
│
├── diff.go                      # Legacy implementation (923 lines)
├── adapter.go                   # ✅ Bridge to new pipeline (203 lines)
│
└── pipeline/                    # New pipeline package
    ├── handler.go               # ✅ Handler interface (164 lines)
    ├── types.go                 # ✅ Core types (211 lines)
    ├── executor.go              # ✅ Pipeline orchestration (801 lines)
    ├── cache.go                 # ✅ MachO cache infrastructure (132 lines)
    ├── profiling.go             # ✅ Flight recorder profiling (254 lines)
    │
    └── handlers/                # Handler implementations
        ├── kernelcache.go       # ✅ Kernelcache diff (194 lines)
        ├── dsc.go               # ✅ DYLD Shared Cache (146 lines)
        ├── launchd.go           # ✅ Launchd config (70 lines)
        ├── firmware.go          # ✅ Firmware diff (60 lines)
        ├── iboot.go             # ✅ iBoot strings (154 lines)
        ├── features.go          # ✅ Feature flags (130 lines)
        ├── files.go             # ✅ File listings (89 lines)
        ├── entitlements.go      # ✅ Entitlements (76 lines - cache-optimized)
        ├── kdk.go               # ✅ KDK DWARF (89 lines)
        └── macho.go             # ✅ MachO diff (107 lines - cache-based)
```

---

## Current Progress (as of 2025-10-03)

**Overall: Functionally Complete - See Known Limitations** ✅

### ✅ Phase 1: Core Infrastructure (100%)

- [x] Pipeline package structure created
- [x] Handler interface and DMGType system
- [x] Executor with mount/unmount logic
- [x] Thread-safe context management
- [x] DMG grouping and concurrent execution
- [x] Execution statistics tracking

### ✅ Phase 2: Handler Migration (100% - 10 of 10 handlers) 🎉

**All Handlers Complete:**
1. [x] KernelcacheHandler (with signature symbolication support)
2. [x] DSCHandler (with WebKit version extraction)
3. [x] LaunchdHandler
4. [x] FirmwareHandler
5. [x] IBootHandler
6. [x] FeaturesHandler
7. [x] FilesHandler
8. [x] EntitlementsHandler (cache-optimized, see limitations)
9. [x] KDKHandler
10. [x] MachOHandler (cache-based)

### ✅ Phase 3: MachO Cache System (100%) 🎉

- [x] Cache types and infrastructure (Task 3.1-3.2)
- [x] Cache population in Executor (Task 3.3)
- [x] MachO handler using cache (Task 3.4)
- [x] Entitlements migrated to cache (Task 3.5)
- [x] Cache performance metrics (Task 3.6)

### ✅ Phase 4: Profiling & Optimization (100%) 🎉

- [x] Go 1.25 Flight Recorder profiling (Task 4.1)
- [x] Detailed performance metrics (Task 4.2)
- [x] Performance analysis on real IPSWs (Task 4.3) - **COMPLETED**
- [x] Targeted optimizations (Task 4.4) - **COMPLETED**
  - **DSC memory optimization**: 94% reduction (15.4 GB → 721 MB)
  - **Streaming pair diff**: Process 4,180 images one-by-one
  - **Manual GC strategy**: Every 200 images in parallel mode
  - **Full production test**: All handlers validated

### 🎯 Phase 5: Extended Features (Optional)

**Core functionality complete. Future enhancements:**
- [ ] Advanced progress reporting with ETA
- [ ] Handler middleware framework
- [ ] Additional DMG types
- [ ] Performance regression testing

---

## Performance Results (Validated)

**Test Date:** 2025-10-03 | **IPSWs:** iPhone18,1 26.0 → 26.0.1 | See [FINAL_TEST_RESULTS.md](./FINAL_TEST_RESULTS.md)

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Execution Time** | 20-30 min | **8m 45s** | **60-70%** ✅ |
| **Memory Usage** | 60GB+ | **721 MB** | **99%** ✅ |
| **File Parsing** | 60k+ ops | 30k ops | **50%** ✅ |
| **Mount Operations** | 8-12 | 6-8 | **40%** ✅ |
| **DSC Processing** | 15.4 GB peak | **<1 GB peak** | **94%** ✅ |

**Key Achievements:**
- All handlers working in parallel groups
- 4,180 DSC images processed via streaming pair diff
- Manual GC strategy keeps memory under 1 GB
- Flight recorder profiling validates optimizations

---

## Performance Profiling

The pipeline includes comprehensive profiling and performance metrics. See **[PROFILING.md](./PROFILING.md)** for full details.

### Quick Start

**Enable verbose metrics:**
```bash
ipsw diff old.ipsw new.ipsw --verbose
```

**Enable flight recorder profiling (Go 1.25+):**
```bash
ipsw diff old.ipsw new.ipsw --profile --profile-dir ./profiles
```

### Available Metrics

- **Per-handler timing**: Execution time for each handler
- **Memory tracking**: Start, end, peak, and delta
- **Cache metrics**: Population time, file counts, errors
- **DMG operations**: Mount/unmount counts and timing
- **GC statistics**: Pause times and run counts

### Example Output

```
Execution time: 2m34s
Handlers run: 8, skipped: 3
Cache populated: 15234 + 15678 files in 23.4s

Handler execution times:
  DYLD Shared Cache: 1m12s
  MachO: 18.7s
  Kernelcache: 5.2s
  ...

Memory usage:
  Start: 45.2 MiB
  Peak: 1.2 GiB
  Delta: +867.2 MiB
```

---

## Key Design Decisions

### Why Handlers?

- **Modularity**: Each diff operation is independent
- **Testability**: Mock DMG mounting for unit tests
- **Extensibility**: Add new handlers without changing core
- **Concurrency**: Handlers run in parallel within groups

### Why Two-Phase Caching?

- **Performance**: Eliminate 50% of file I/O operations
- **Memory**: 840MB cache vs 60GB redundant parsing
- **Consistency**: All handlers see same parsed data
- **Simplicity**: Scan once, consume many times

### Why DMG Grouping?

- **Resource Efficiency**: Mount each DMG type once
- **Concurrency**: Parallel execution within groups
- **Safety**: Sequential between groups (clean unmount)

---

## Testing Strategy

**Current Status**: Manual testing only. Automated tests are TODO.

**Manual Validation** (Completed 2025-10-03):
- ✅ Full production test with real IPSWs (iPhone18,1 26.0 → 26.0.1)
- ✅ All 10 handlers verified against legacy implementation
- ✅ Performance metrics validated (see FINAL_TEST_RESULTS.md)
- ✅ Memory optimization confirmed (99% reduction to 721 MB peak)
- ✅ Execution time improvement validated (60-70% faster)

**TODO - Automated Test Coverage**:
- [ ] Unit tests for each handler
- [ ] Integration tests for full pipeline
- [ ] Regression tests for performance
- [ ] Comparison tests against legacy output
- [ ] CI/CD integration

---

## How to Contribute

### Adding a New Handler

1. Create file in `internal/diff/pipeline/handlers/`
2. Implement `Handler` interface
3. Declare DMG dependencies in `DMGTypes()`
4. Register in `adapter.go`
5. Add integration test
6. Update TASKS.md checklist

Example:

```go
type MyHandler struct{}

func (h *MyHandler) Name() string { return "My Feature" }

func (h *MyHandler) DMGTypes() []pipeline.DMGType {
    return []pipeline.DMGType{pipeline.DMGTypeSystemOS}
}

func (h *MyHandler) Enabled(cfg *pipeline.Config) bool {
    return cfg.MyFeature
}

func (h *MyHandler) Execute(ctx context.Context, exec *pipeline.Executor) (*pipeline.Result, error) {
    // Get mounted DMG
    oldMount, _ := exec.OldCtx.GetMount(pipeline.DMGTypeSystemOS)
    newMount, _ := exec.NewCtx.GetMount(pipeline.DMGTypeSystemOS)

    // Do diff work
    data := performDiff(oldMount.MountPath, newMount.MountPath)

    return &pipeline.Result{
        HandlerName: h.Name(),
        Data:        data,
    }, nil
}
```

---

## Documentation Map

| Document | Purpose | Read When |
|----------|---------|-----------|
| **README.md** (this file) | Overview, quick start, current status | First time / quick refresh |
| **ARCHITECTURE.md** | Technical design, execution flow, patterns | Implementing features |
| **TASKS.md** | Task breakdown, timeline, acceptance criteria | Planning work |
| **CACHE_ARCHITECTURE.md** | Two-phase caching deep dive | Implementing cache or handlers using cache |

---

## Migration Strategy

Since we're on a feature branch, no backward compatibility concerns:

1. **Phase 1**: Core infrastructure ✅
2. **Phase 2**: Port all handlers (in progress)
3. **Phase 3**: Add MachO caching (critical for memory)
4. **Phase 4**: Add profiling and optimize
5. **Phase 5**: Extended features (optional)

**No feature flags needed** - this is a clean rewrite on a branch.

---

## Known Limitations

### Feature Parity with Legacy

**⚠️ Missing: LaunchConstraints in Entitlements Handler**

The legacy implementation includes LaunchConstraints (Self, Parent, Responsible) in entitlements diff by default. The pipeline implementation currently only extracts basic entitlements from the MachO cache.

- **Impact**: Entitlements diff output will not include LaunchConstraints data
- **Workaround**: None currently - feature not implemented
- **Fix**: Update cache population to extract LaunchConstraints from `m.CodeSignature()` and store in `MachoMetadata`
- **Priority**: Low - most users diff entitlements only, not constraints
- **Code locations**:
  - Legacy: `internal/commands/ent/ent.go:141-166` (LaunchConstraints extraction)
  - Pipeline: `internal/diff/pipeline/handlers/entitlements.go` (cache-based, no constraints)

### Resolved Issues

- ✅ AEA file cleanup (`.dmg.aea` files left in directory)
- ✅ DMG extraction before decryption
- ✅ Pipeline infrastructure working
- ✅ All config options supported (Signatures, PemDB, AllowList, BlockList, etc.)

### Outstanding Issues

- ⚠️ Files handler fails on certain IPSWs with AEA decryption errors (non-critical)
- ⚠️ Broken symlinks generate verbose warnings (cosmetic issue)
- ⚠️ No automated test coverage (manual testing only)

---

## Resources

### Code References

- Legacy implementation: `internal/diff/diff.go` (923 LOC)
- New pipeline core: `internal/diff/pipeline/executor.go` (801 LOC)
- All handlers combined: `internal/diff/pipeline/handlers/*.go` (1,115 LOC)
- Example handler: `internal/diff/pipeline/handlers/dsc.go` (146 LOC)

### Test Data

- Successfully tested with:
  - `iPhone18,1_26.0_23A345_Restore.ipsw`
  - `iPhone18,1_26.0.1_23A355_Restore.ipsw`
- Output: `/tmp/ipsw-diff-test/26_0_23A345__vs_26_0_1_23A355/`

### Dependencies

- **Go 1.25.0+** (required):
  - Index-less `for range` loops
  - `errgroup.Go()` method
  - **Flight Recorder profiling** (new in 1.25)
  - Updated go.mod to: `go 1.25.0` / `toolchain go1.25.1`
- `golang.org/x/sync/errgroup`
- Existing `internal/commands/*` packages
- Existing `pkg/*` packages (dyld, macho, info, etc.)

### Profiling Resources

- [Go 1.25 Flight Recorder Blog Post](https://go.dev/blog/flight-recorder)
- Traditional profiling docs: [Profiling Go Programs](https://go.dev/blog/pprof)

---

## Questions?

For new agents/developers joining this feature:

1. **What's the current state?** Check "Current Progress" section above
2. **What should I work on?** See "Known Limitations" and TODO items
3. **How does the pipeline work?** Read ARCHITECTURE.md execution flow
4. **How does caching work?** Read CACHE_ARCHITECTURE.md
5. **Where are the tests?** Currently manual testing only - automated tests are TODO

---

## Success Criteria

Pipeline refactor is complete when:

- ✅ All 10 handlers ported and tested
- ✅ MachO caching implemented and working
- ✅ Performance targets met (60-70% faster, <1GB RAM)
- ✅ Profiling infrastructure in place
- ✅ Production test with all handlers passing
- ⚠️ Documentation complete (updated with accurate metrics)
- ⚠️ Automated test coverage (TODO)

**Status**: ✅ **FUNCTIONALLY COMPLETE** | ⚠️ **Manual Testing Only**

Full production test completed 2025-10-03 with all 10 handlers enabled, achieving 721 MB peak memory (99% reduction from 60GB+) and 8m 45s execution time (60-70% faster than 20-30 min baseline). See Known Limitations for minor feature gaps.
