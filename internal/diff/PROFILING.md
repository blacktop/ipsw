# Performance Profiling and Metrics

This document describes the profiling and performance monitoring capabilities built into the `ipsw diff` pipeline.

## Overview

The pipeline includes comprehensive performance instrumentation:
- **Go 1.25+ Flight Recorder**: Low-overhead continuous profiling
- **Detailed Metrics**: Per-handler timing, memory tracking, GC stats
- **DMG Operations**: Mount/unmount counts and timing
- **Cache Metrics**: Population time, file counts, parse errors

## Quick Start

### Basic Usage with Metrics

Run diff with verbose mode to see execution statistics:

```bash
ipsw diff old.ipsw new.ipsw --verbose
```

This displays a summary at the end:

```
Execution time: 2m34s
Handlers run: 8, skipped: 3
Cache populated: 15234 + 15678 files in 23.4s

Handler execution times:
  Kernelcache: 5.2s
  DYLD Shared Cache: 1m12s
  Entitlements: 3.1s
  MachO: 18.7s
  ...

DMG operations:
  Mounts: 4 (total time: 12.3s)
  Unmounts: 4 (total time: 8.1s)

Memory usage:
  Start: 45.2 MiB
  End: 912.4 MiB
  Peak: 1.2 GiB
  Delta: +867.2 MiB

Garbage collection:
  Runs: 23
  Total pause: 145ms
  Avg pause: 6.3ms
```

### Flight Recorder Profiling (Go 1.25+)

Enable continuous execution tracing with minimal overhead (<1%):

```bash
ipsw diff old.ipsw new.ipsw --profile --profile-dir ./profiles
```

This creates a trace file: `./profiles/trace-20251001-143022.out`

### Memory Profiling

Enable heap memory profiling to identify allocation hotspots:

```bash
ipsw diff old.ipsw new.ipsw --memprofile --profile-dir ./profiles
```

This creates a memory profile: `./profiles/mem-20251001-143022.pprof`

**Note**: Memory profiling writes a heap snapshot at the END of execution. This is different from execution traces and provides exact allocation locations with line numbers.

## Analyzing Traces

### View Interactive Trace

```bash
go tool trace ./profiles/trace-20251001-143022.out
```

This opens a web browser with:
- **View trace**: Timeline of all goroutines and events
- **Goroutine analysis**: Blocking, network, sync operations
- **Network blocking profile**: Network I/O bottlenecks
- **Synchronization blocking profile**: Lock contention
- **Syscall blocking profile**: System call overhead
- **Scheduler latency profile**: Goroutine scheduling delays

### Extract CPU Profile

```bash
go tool trace -pprof=cpu ./profiles/trace-20251001-143022.out > cpu.pprof
go tool pprof cpu.pprof
```

Interactive commands:
- `top`: Top CPU consumers
- `list <function>`: Source code with CPU time
- `web`: Generate graph (requires Graphviz)

### Analyze Memory Profile

If you used `--memprofile` flag:

```bash
go tool pprof ./profiles/mem-20251001-143022.pprof
```

Interactive commands:
- `top`: Top memory allocators
- `top -cum`: Top cumulative allocations
- `list <function>`: Source code with allocation amounts
- `web`: Generate allocation graph
- `peek <regex>`: Show callers/callees

**Note**: Execution traces (`--profile`) do NOT contain heap allocation data. Use `--memprofile` for memory analysis.

### Extract Blocking Profile

```bash
go tool trace -pprof=block ./profiles/trace-20251001-143022.out > block.pprof
go tool pprof block.pprof
```

## Performance Metrics Details

### Handler Timing

Each handler's execution time is tracked individually:
- Includes handler initialization, execution, and cleanup
- Tracked in `ExecutionStats.HandlerTimes` map
- Logged when `--verbose` is enabled

### DMG Operations

Tracks mount/unmount operations:
- `MountCount`: Number of successful mounts
- `UnmountCount`: Number of successful unmounts
- `MountTime`: Total time spent mounting DMGs
- `UnmountTime`: Total time spent unmounting DMGs

### Memory Tracking

Captures memory usage at key points:
- `StartMemory`: Memory allocated at start
- `EndMemory`: Memory allocated at completion
- `PeakMemory`: Maximum memory used during execution
- Delta calculated automatically

Memory is measured using `runtime.MemStats.Alloc` (bytes currently allocated).

### Garbage Collection

Tracks GC impact on performance:
- `NumGC`: Number of GC runs during execution
- `TotalGCPause`: Total time spent in GC pauses
- Average pause calculated in summary

### Cache Metrics

Tracks MachO cache population:
- `CachePopulated`: Whether cache was used
- `CachePopulateTime`: Time to scan and cache all MachOs
- `OldCacheSize`: Number of files cached from old IPSW
- `NewCacheSize`: Number of files cached from new IPSW
- `OldCacheErrors`: Parse errors in old IPSW
- `NewCacheErrors`: Parse errors in new IPSW

## Accessing Metrics Programmatically

```go
// Create and execute pipeline
exec := pipeline.NewExecutor(oldIPSW, newIPSW, cfg)
exec.RegisterAll(handlers...)
exec.Execute(ctx)

// Get statistics
stats := exec.Stats()

// Access individual metrics
fmt.Printf("Total time: %s\n", stats.Duration())
fmt.Printf("Cache population: %s\n", stats.CachePopulateTime)
fmt.Printf("Peak memory: %d bytes\n", stats.PeakMemory)

// Print full summary
fmt.Print(stats.Summary())
```

## Performance Optimization Guide

### Expected Baseline Metrics

Based on typical iPhone 15 Pro IPSW diffs:
- **Total execution time**: 2-5 minutes (depending on flags)
- **Cache population**: 20-30s for ~30,000 MachO files
- **Memory usage**: 800MB-1.2GB (cache-based approach)
- **Handler times**:
  - DSC (Shared Cache): 1-2 minutes (largest)
  - MachO: 15-30s
  - Entitlements: 2-5s
  - Others: <5s each

### Optimization Strategies

#### 1. Reduce Memory Usage

If peak memory exceeds 2GB:
- Enable allow/block lists to filter sections
- Disable expensive features (`--strs`, `--starts`)
- Process IPSWs one at a time instead of parallel

#### 2. Speed Up Cache Population

If cache population >30s:
- Check for slow I/O (use SSD, not network drive)
- Verify AEA decryption is fast (use PemDB)
- Profile with `--profile` to identify bottlenecks

#### 3. Optimize Handler Execution

If specific handler is slow:
- Profile handler with flight recorder
- Check for redundant parsing (should use cache)
- Verify concurrent execution (handlers in same DMG group)

#### 4. Reduce DMG Mount Time

If mount time >20s:
- Check disk encryption overhead
- Verify sufficient disk space for extraction
- Consider pre-extracting DMGs for repeated runs

## Troubleshooting

### High Memory Usage

**Symptom**: Peak memory >2GB

**Solutions**:
1. Use allow-list to filter sections: `--allow-list __TEXT.__text`
2. Disable string extraction: Remove `--strs` flag
3. Reduce parallel handlers (edit handler grouping)

### Slow Cache Population

**Symptom**: Cache population >60s

**Solutions**:
1. Check I/O with `iostat` during run
2. Verify SSD is being used (not HDD)
3. Profile with `--profile` and check `populateMachoCaches`

### Frequent GC Pauses

**Symptom**: GC pause time >1s total

**Solutions**:
1. Increase GOGC: `GOGC=200 ipsw diff ...`
2. Pre-allocate cache capacity (edit `NewMachoCache`)
3. Reduce cache retention (currently keeps all data)

### Handler Taking Too Long

**Symptom**: Single handler >5 minutes

**Solutions**:
1. Profile with `--profile`
2. Check if handler uses cache correctly
3. Verify no redundant file I/O
4. Check for CPU-intensive operations

## Flight Recorder Best Practices

### When to Enable Profiling

- **Performance regression investigation**: Compare traces before/after changes
- **Production debugging**: Enable for failed runs (trace persists on panic)
- **Optimization targets**: Identify CPU/memory/lock bottlenecks
- **CI/CD validation**: Detect performance regressions in tests

### Trace File Management

Traces can be large (50-500MB depending on duration):
- Automatically timestamped for versioning
- Store in dedicated directory (`--profile-dir`)
- Clean up old traces regularly
- Archive important traces for regression testing

### Overhead Considerations

Flight recorder has <1% overhead but:
- Trace files grow with execution time
- Longer runs = larger traces
- Disk I/O for writing trace
- Memory for trace buffer

For production use, enable only when needed.

## Performance Testing Checklist

Before and after optimization:

- [ ] Run with `--verbose` and capture metrics
- [ ] Enable `--profile` and save trace
- [ ] Extract CPU profile and identify top 5 functions
- [ ] Extract memory profile and check allocations
- [ ] Check GC pause times
- [ ] Verify cache hit rates
- [ ] Compare handler execution times
- [ ] Measure total execution time improvement

## Integration with CI/CD

### Automated Performance Testing

```bash
#!/bin/bash
# Run diff with profiling
ipsw diff old.ipsw new.ipsw \
  --verbose \
  --profile \
  --profile-dir ./metrics \
  --output ./results > metrics.log 2>&1

# Extract key metrics
grep "Execution time:" metrics.log
grep "Cache populated:" metrics.log
grep "Peak:" metrics.log

# Fail if execution time exceeds threshold
EXEC_TIME=$(grep "Execution time:" metrics.log | awk '{print $3}')
if [[ "$EXEC_TIME" > "5m" ]]; then
  echo "Performance regression detected!"
  exit 1
fi
```

### Baseline Comparison

Keep baseline traces and compare:

```bash
# Generate CPU profile diff
go tool pprof -base=baseline-cpu.pprof current-cpu.pprof -web
```

## Future Enhancements

Potential additions to profiling infrastructure:
- [ ] Prometheus metrics export
- [ ] JSON metrics output for tooling
- [ ] Per-file timing breakdown
- [ ] Network I/O tracking (for remote IPSWs)
- [ ] Real-time progress dashboard
- [ ] Automatic anomaly detection
