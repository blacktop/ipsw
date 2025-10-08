# IPSW Diff Pipeline Implementation Plan

## Overview

This document outlines the implementation phases for migrating the `ipsw diff` command to a pipeline-based architecture. Each phase builds on the previous one, allowing for incremental testing and validation.

## Phase 1: Core Infrastructure (Small)

### 1.1 Define Core Types
**Priority**: Critical
**Complexity**: Small
**Files**: `internal/diff/pipeline/types.go`

```go
- DMGType enum
- DiffHandler interface
- Result interface
- Pipeline configuration
```

### 1.2 Create Handler Registry
**Priority**: Critical
**Complexity**: Small
**Files**: `internal/diff/pipeline/registry.go`

```go
- Handler registration system
- Handler lookup by name
- Handler grouping by DMG type
```

### 1.3 Implement Result Collector
**Priority**: Critical
**Complexity**: Small
**Files**: `internal/diff/pipeline/results.go`

```go
- Thread-safe result storage
- Result aggregation
- Error collection
```

**Dependencies**: None
**Testing**: Unit tests for each component
**Risk**: Low - foundational code with clear interfaces

---

## Phase 2: Resource Management (Medium)

### 2.1 DMG Resource Manager
**Priority**: Critical
**Complexity**: Medium
**Files**: `internal/diff/pipeline/resources.go`

```go
- Resource acquisition/release
- Mount reference counting
- Cleanup guarantees
```

### 2.2 Mount Operations Wrapper
**Priority**: High
**Complexity**: Small
**Files**: `internal/diff/pipeline/mount.go`

```go
- Unified mount/unmount interface
- Error recovery
- Retry logic
```

### 2.3 Resource Pool
**Priority**: Medium
**Complexity**: Medium
**Files**: `internal/diff/pipeline/pool.go`

```go
- Shared resource tracking
- Concurrent access control
- Lifecycle management
```

**Dependencies**: Phase 1
**Testing**: Integration tests with mock DMGs
**Risk**: Medium - OS-specific mount operations may have edge cases

---

## Phase 3: Handler Implementation (Large)

### 3.1 Base Handler Implementation
**Priority**: Critical
**Complexity**: Small
**Files**: `internal/diff/pipeline/handlers/base.go`

```go
- Common handler functionality
- Validation helpers
- Configuration access
```

### 3.2 IPSW-Direct Handlers
**Priority**: High
**Complexity**: Medium
**Files**: `internal/diff/pipeline/handlers/ipsw/`

```go
- KernelcacheHandler
- KDKHandler
- FirmwareHandler
- IBootHandler
- EntitlementHandler
```

### 3.3 SystemOS Handlers
**Priority**: High
**Complexity**: Medium
**Files**: `internal/diff/pipeline/handlers/systemos/`

```go
- DSCHandler
- MachoHandler
- LaunchdHandler
```

### 3.4 FileSystem Handlers
**Priority**: Medium
**Complexity**: Small
**Files**: `internal/diff/pipeline/handlers/filesystem/`

```go
- FileHandler
```

### 3.5 Multi-DMG Handlers
**Priority**: Low
**Complexity**: Large
**Files**: `internal/diff/pipeline/handlers/multi/`

```go
- FeatureFlagHandler
```

**Dependencies**: Phase 1, Phase 2
**Testing**: Individual handler unit tests
**Risk**: High - Need to ensure backward compatibility with existing output

---

## Phase 4: Pipeline Executor (Medium)

### 4.1 Pipeline Core
**Priority**: Critical
**Complexity**: Medium
**Files**: `internal/diff/pipeline/executor.go`

```go
- Pipeline initialization
- Stage orchestration
- Error aggregation
```

### 4.2 Scheduler
**Priority**: High
**Complexity**: Medium
**Files**: `internal/diff/pipeline/scheduler.go`

```go
- Handler prioritization
- Dependency resolution
- Stage grouping
```

### 4.3 Concurrent Execution
**Priority**: High
**Complexity**: Medium
**Files**: `internal/diff/pipeline/concurrent.go`

```go
- errgroup integration
- Concurrency limiting
- Context propagation
```

### 4.4 Progress Tracking
**Priority**: Low
**Complexity**: Small
**Files**: `internal/diff/pipeline/progress.go`

```go
- Handler progress reporting
- Overall pipeline progress
- ETA calculation
```

**Dependencies**: Phase 1, 2, 3
**Testing**: End-to-end pipeline tests
**Risk**: Medium - Complex orchestration logic

---

## Phase 5: Integration & Migration (Medium)

### 5.1 Adapter Layer
**Priority**: Critical
**Complexity**: Medium
**Files**: `internal/diff/adapter.go`

```go
- Legacy to pipeline adapter
- Configuration mapping
- Result transformation
```

### 5.2 Update Main Diff Logic
**Priority**: Critical
**Complexity**: Small
**Files**: `internal/diff/diff.go`

```go
- Replace sequential calls with pipeline
- Maintain backward compatibility
- Feature flag for pipeline mode
```

### 5.3 CLI Integration
**Priority**: High
**Complexity**: Small
**Files**: `cmd/ipsw/cmd/diff.go`

```go
- Add pipeline-specific flags
- Progress output option
- Debug mode
```

### 5.4 Migration Documentation
**Priority**: Medium
**Complexity**: Small
**Files**: `docs/diff-pipeline.md`

```go
- Architecture overview
- Migration guide
- Performance comparisons
```

**Dependencies**: All previous phases
**Testing**: Full regression test suite
**Risk**: High - Must ensure no behavior changes for users

---

## Phase 6: Optimization & Enhancement (Small)

### 6.1 Performance Profiling
**Priority**: Low
**Complexity**: Small

- Benchmark pipeline vs sequential
- Identify bottlenecks
- Optimize hot paths

### 6.2 Caching Layer
**Priority**: Low
**Complexity**: Medium
**Files**: `internal/diff/pipeline/cache.go`

```go
- DMG extraction cache
- Mount point cache
- Result cache
```

### 6.3 Additional DMG Types
**Priority**: Low
**Complexity**: Medium

- Add AppOS support
- Add Exclave support
- Dynamic DMG discovery

**Dependencies**: Phase 5 complete
**Testing**: Performance benchmarks
**Risk**: Low - Optional enhancements

---

## Risk Mitigation

### Technical Risks

1. **Mount Operation Failures**
   - Mitigation: Robust retry logic with exponential backoff
   - Fallback: Sequential execution mode

2. **Memory Usage**
   - Mitigation: Stream processing where possible
   - Monitoring: Memory profiling during development

3. **Backward Compatibility**
   - Mitigation: Comprehensive test suite
   - Feature flag for gradual rollout

### Schedule Risks

1. **Underestimated Complexity**
   - Buffer: 20% time buffer per phase
   - Option: Defer Phase 6 optimizations

2. **OS-Specific Issues**
   - Testing: Multi-platform CI/CD
   - Fallback: Platform-specific implementations

## Success Metrics

- **Performance**: 30-50% reduction in execution time
- **Reliability**: <1% failure rate increase
- **Maintainability**: 50% reduction in cyclomatic complexity
- **Test Coverage**: >80% coverage for new code

## Timeline Estimate

| Phase | Duration | Dependencies | Risk |
|-------|----------|--------------|------|
| Phase 1 | 2 days | None | Low |
| Phase 2 | 3 days | Phase 1 | Medium |
| Phase 3 | 5 days | Phase 1, 2 | High |
| Phase 4 | 3 days | Phase 1-3 | Medium |
| Phase 5 | 2 days | Phase 1-4 | High |
| Phase 6 | 2 days | Phase 1-5 | Low |

**Total**: ~17 days with buffer

## Next Steps

1. Review and approve architecture design
2. Set up feature branch for development
3. Begin Phase 1 implementation
4. Create test fixtures for DMG operations
5. Set up performance benchmarking