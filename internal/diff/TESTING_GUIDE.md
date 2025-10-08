# Testing Guide for Pipeline Refactor

This document provides a comprehensive testing plan for validating the new pipeline-based `ipsw diff` implementation.

## Overview

The pipeline refactor is **95% complete** with all core functionality implemented. Tasks 4.3 and 4.4 (performance analysis and optimization) require real IPSW testing to complete.

## Testing Phases

### Phase 1: Smoke Tests (Quick Validation)

Quick tests to verify basic functionality without full IPSW processing.

#### 1.1 Build Verification

```bash
# Build the project
go build -v ./cmd/ipsw

# Verify the binary exists
./ipsw version

# Check diff command is available
./ipsw diff --help
```

**Expected**: Clean build, help text shows new flags (`--profile`, `--profile-dir`)

#### 1.2 Flag Validation

```bash
# Test that new flags are recognized
./ipsw diff --profile --help
./ipsw diff --profile-dir ./test-profiles --help
```

**Expected**: No errors, flags accepted

#### 1.3 Error Handling

```bash
# Test with missing arguments
./ipsw diff

# Test with non-existent files
./ipsw diff nonexistent1.ipsw nonexistent2.ipsw --verbose
```

**Expected**: Clear error messages, no panics

### Phase 2: Unit Tests (Handler Isolation)

Tests for individual handlers and cache components.

#### 2.1 Cache Infrastructure

```bash
# Run cache-specific tests
go test -v ./internal/diff/pipeline -run TestMachoCache
```

**Expected Tests**:
- Cache creation and initialization
- Thread-safe concurrent access
- Set/Get/All operations
- Error counting
- Memory efficiency

#### 2.2 Handler Tests

```bash
# Run all handler tests
go test -v ./internal/diff/pipeline/handlers/...
```

**Expected Tests** (per handler):
- DMGTypes() returns correct types
- Enabled() respects configuration
- Execute() with mocked executor
- Result format validation

#### 2.3 Executor Tests

```bash
# Run executor tests
go test -v ./internal/diff/pipeline -run TestExecutor
```

**Expected Tests**:
- Handler registration
- DMG grouping logic
- Mount/unmount operations (mocked)
- Statistics collection
- Error handling

### Phase 3: Integration Tests (Real IPSWs)

**Prerequisites**: Two iPhone IPSWs (old and new versions)

#### 3.1 Basic Diff (No Options)

```bash
# Run basic diff
./ipsw diff old.ipsw new.ipsw --verbose
```

**Validation Checklist**:
- [ ] No panics or crashes
- [ ] Completes successfully
- [ ] Verbose output shows execution stats
- [ ] Memory usage logged
- [ ] Handler times displayed
- [ ] DMG mount/unmount counts shown

#### 3.2 Full Feature Diff

```bash
# Run with all features enabled
./ipsw diff old.ipsw new.ipsw \
  --fw \
  --launchd \
  --feat \
  --files \
  --ent \
  --strs \
  --starts \
  --verbose \
  --output ./diff-output \
  --markdown
```

**Validation Checklist**:
- [ ] All handlers execute
- [ ] Markdown file created in output dir
- [ ] No handlers skipped unexpectedly
- [ ] Cache metrics show population
- [ ] All diff sections present in output

#### 3.3 Profiling Test

```bash
# Run with profiling enabled
./ipsw diff old.ipsw new.ipsw \
  --fw \
  --ent \
  --profile \
  --profile-dir ./profiles \
  --verbose
```

**Validation Checklist**:
- [ ] Trace file created in `./profiles/`
- [ ] Trace file is non-zero size
- [ ] Can open with `go tool trace`
- [ ] Profiling overhead <5% (compare times with/without)
- [ ] Memory metrics captured

#### 3.4 Cache Performance Test

```bash
# Run entitlements and MachO (both use cache)
./ipsw diff old.ipsw new.ipsw \
  --ent \
  --verbose 2>&1 | tee cache-test.log
```

**Validation Checklist**:
- [ ] Cache populated exactly once
- [ ] Cache population time logged
- [ ] File counts shown (old + new)
- [ ] Parse errors (if any) reported
- [ ] Entitlements handler uses cache (no ent.GetDatabase calls)
- [ ] MachO handler uses cache

### Phase 4: Comparison Tests (Legacy vs Pipeline)

Compare output between old and new implementations.

#### 4.1 Output Comparison

```bash
# Run legacy implementation (if available)
git stash
go build -v ./cmd/ipsw
./ipsw diff old.ipsw new.ipsw --fw --ent --output ./legacy

# Run new implementation
git stash pop
go build -v ./cmd/ipsw
./ipsw diff old.ipsw new.ipsw --fw --ent --output ./pipeline

# Compare outputs
diff -r ./legacy ./pipeline
```

**Expected**: Identical or very similar output (minor formatting differences OK)

#### 4.2 Consistency Test

Run same diff multiple times to verify deterministic output:

```bash
# Run 3 times
for i in {1..3}; do
  ./ipsw diff old.ipsw new.ipsw --ent --output ./run$i --markdown
done

# Compare outputs
diff ./run1 ./run2
diff ./run2 ./run3
```

**Expected**: Identical output across all runs

### Phase 5: Performance Tests

Measure performance improvements vs legacy implementation.

#### 5.1 Execution Time

```bash
# Legacy
time ./ipsw-legacy diff old.ipsw new.ipsw --fw --ent --launchd

# New pipeline
time ./ipsw diff old.ipsw new.ipsw --fw --ent --launchd --verbose
```

**Target**: 45-50% time reduction

#### 5.2 Memory Usage

```bash
# Monitor with time (macOS)
/usr/bin/time -l ./ipsw diff old.ipsw new.ipsw --fw --ent --verbose 2>&1 | grep "maximum resident"

# Or use profiling
./ipsw diff old.ipsw new.ipsw --fw --ent --profile --verbose
go tool trace -pprof=mem ./profiles/trace-*.out > mem.pprof
go tool pprof -top mem.pprof
```

**Target**: <1GB peak memory (98% reduction from 60GB)

#### 5.3 Cache Effectiveness

```bash
# Count file operations with strace/dtruss
sudo dtruss -c ./ipsw diff old.ipsw new.ipsw --ent --verbose 2>&1 | grep open
```

**Target**: ~30k file operations (50% reduction from 60k)

### Phase 6: Stress Tests

Test edge cases and failure scenarios.

#### 6.1 Large IPSWs

```bash
# Test with largest available IPSW (e.g., iPad Pro)
./ipsw diff large-old.ipsw large-new.ipsw --verbose --profile
```

**Validation**:
- [ ] Completes without OOM
- [ ] Cache size reasonable (<2GB)
- [ ] Performance acceptable (<10min)

#### 6.2 Minimal Memory

```bash
# Limit memory and test
GOMEMLIMIT=1GiB ./ipsw diff old.ipsw new.ipsw --ent --verbose
```

**Validation**:
- [ ] Completes successfully
- [ ] GC runs but doesn't thrash
- [ ] No OOM kills

#### 6.3 Interrupted Execution

```bash
# Start diff and kill it
./ipsw diff old.ipsw new.ipsw --fw --ent &
PID=$!
sleep 30
kill -TERM $PID
```

**Validation**:
- [ ] DMGs unmounted cleanly
- [ ] Temp files cleaned up
- [ ] No orphaned mounts (`mount | grep ipsw`)

#### 6.4 Missing/Corrupt DMGs

```bash
# Test with IPSW missing expected DMGs
./ipsw diff minimal.ipsw full.ipsw --verbose
```

**Validation**:
- [ ] Clear error messages
- [ ] Graceful failure
- [ ] No panics

### Phase 7: Profiling Analysis (Task 4.3)

**Prerequisite**: Complete Phase 3.3 and collect trace files

#### 7.1 Analyze Trace

```bash
# Open interactive trace viewer
go tool trace ./profiles/trace-<timestamp>.out
```

**Analysis Tasks**:
1. Identify top 5 CPU consumers
2. Check for goroutine blocking
3. Verify concurrent handler execution
4. Look for GC pressure
5. Identify I/O bottlenecks

#### 7.2 Extract CPU Profile

```bash
go tool trace -pprof=cpu ./profiles/trace-<timestamp>.out > cpu.pprof
go tool pprof cpu.pprof
```

**Analysis**:
```
(pprof) top10
(pprof) list populateMachoCaches
(pprof) list extractMachoMetadata
(pprof) web
```

**Document**: Top CPU consumers and optimization opportunities

#### 7.3 Extract Memory Profile

```bash
go tool trace -pprof=mem ./profiles/trace-<timestamp>.out > mem.pprof
go tool pprof mem.pprof
```

**Analysis**:
```
(pprof) top10
(pprof) list NewMachoCache
(pprof) list extractMachoMetadata
```

**Document**: Large allocations and potential for pooling

#### 7.4 Create Performance Report

Document findings in `internal/diff/PERFORMANCE_ANALYSIS.md`:

```markdown
# Performance Analysis Results

## Test Configuration
- Old IPSW: [version/build]
- New IPSW: [version/build]
- Hardware: [Mac specs]
- Go Version: [version]

## Metrics
- Total execution time: [time]
- Cache population: [time]
- Peak memory: [size]
- Handler breakdown: [table]

## Top CPU Consumers
1. [function]: [%]
2. [function]: [%]
...

## Optimization Opportunities
1. [opportunity]: [expected impact]
2. [opportunity]: [expected impact]
...

## Recommendations
- [recommendation 1]
- [recommendation 2]
...
```

### Phase 8: Optimization Implementation (Task 4.4)

Based on Phase 7 findings, implement targeted optimizations.

#### Common Optimization Patterns

**1. Pool Allocations**
```go
var metadataPool = sync.Pool{
    New: func() any { return &MachoMetadata{} },
}
```

**2. Reduce String Allocations**
```go
// Use strings.Builder for concatenation
var sb strings.Builder
sb.WriteString(seg)
sb.WriteRune('.')
sb.WriteString(name)
```

**3. Optimize Hot Paths**
```go
// Cache frequently accessed values
// Avoid redundant map lookups
// Use type assertions efficiently
```

**4. Parallelize Sequential Operations**
```go
// If cache population is sequential, parallelize per-IPSW
// Use worker pools for file processing
```

#### Validation After Optimization

For each optimization:
1. Run benchmarks before/after
2. Verify no behavior changes (comparison test)
3. Check profiling shows improvement
4. Document in git commit

## Testing Checklist Summary

### Pre-Testing
- [ ] Code builds cleanly
- [ ] All flags recognized
- [ ] Unit tests pass
- [ ] No linter errors

### Basic Testing
- [ ] Smoke tests pass
- [ ] Integration tests pass (all features)
- [ ] Profiling works
- [ ] Cache functions correctly

### Performance Testing
- [ ] Execution time meets target (45-50% reduction)
- [ ] Memory usage meets target (<1GB)
- [ ] File operations meet target (50% reduction)
- [ ] No performance regressions

### Comparison Testing
- [ ] Output matches legacy implementation
- [ ] Results are deterministic
- [ ] Edge cases handled

### Profiling Analysis
- [ ] Trace collected and analyzed
- [ ] CPU hotspots identified
- [ ] Memory allocations profiled
- [ ] Performance report written

### Optimization
- [ ] Targeted optimizations implemented
- [ ] Improvements validated
- [ ] No regressions introduced

## Automated Testing Script

Save as `test-pipeline.sh`:

```bash
#!/bin/bash
set -e

echo "=== IPSW Diff Pipeline Testing ==="
echo

# Configuration
OLD_IPSW="${1:-old.ipsw}"
NEW_IPSW="${2:-new.ipsw}"
OUTPUT_DIR="./test-results-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTPUT_DIR"

# Test 1: Basic build
echo "Test 1: Build verification..."
go build -v -o ./ipsw-test ./cmd/ipsw
echo "✓ Build successful"
echo

# Test 2: Help text
echo "Test 2: Flag validation..."
./ipsw-test diff --help | grep -q "profile"
echo "✓ Profiling flags present"
echo

# Test 3: Basic diff with verbose
echo "Test 3: Basic diff with verbose metrics..."
./ipsw-test diff "$OLD_IPSW" "$NEW_IPSW" \
  --verbose \
  --output "$OUTPUT_DIR/basic" \
  2>&1 | tee "$OUTPUT_DIR/basic.log"
echo "✓ Basic diff completed"
echo

# Test 4: Full features
echo "Test 4: Full feature diff..."
./ipsw-test diff "$OLD_IPSW" "$NEW_IPSW" \
  --fw --launchd --feat --files --ent \
  --verbose \
  --output "$OUTPUT_DIR/full" \
  --markdown \
  2>&1 | tee "$OUTPUT_DIR/full.log"
echo "✓ Full diff completed"
echo

# Test 5: Profiling
echo "Test 5: Profiling enabled..."
./ipsw-test diff "$OLD_IPSW" "$NEW_IPSW" \
  --ent \
  --profile \
  --profile-dir "$OUTPUT_DIR/profiles" \
  --verbose \
  2>&1 | tee "$OUTPUT_DIR/profile.log"
echo "✓ Profiling completed"
echo

# Extract metrics
echo "=== Test Results ==="
echo
echo "Execution time:"
grep "Execution time:" "$OUTPUT_DIR"/*.log
echo
echo "Cache metrics:"
grep "Cache populated:" "$OUTPUT_DIR"/*.log
echo
echo "Memory usage:"
grep "Peak:" "$OUTPUT_DIR"/*.log
echo
echo "Profile traces:"
ls -lh "$OUTPUT_DIR/profiles/"
echo

echo "All tests completed! Results in: $OUTPUT_DIR"
```

## Troubleshooting

### Common Issues

**Issue**: Panic during cache population
**Solution**: Check MachO file permissions, verify PemDB path

**Issue**: High memory usage (>2GB)
**Solution**: Use allow-list to filter sections, disable `--strs`

**Issue**: DMG mount failures
**Solution**: Check disk space, verify sudo access, unmount manually

**Issue**: Slow cache population (>60s)
**Solution**: Check I/O with iostat, verify SSD usage, profile with `--profile`

**Issue**: Profiling overhead >5%
**Solution**: This is expected with large traces; reduce IPSW size for testing

## Next Steps After Testing

1. **Document results** in PERFORMANCE_ANALYSIS.md
2. **Implement optimizations** based on profiling (Task 4.4)
3. **Update benchmarks** with real numbers
4. **Create regression tests** with baseline metrics
5. **Prepare PR** with test results and comparisons
