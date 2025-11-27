# Integration Tests for IPSW

This directory contains integration tests for the `ipsw` command-line tool. These tests verify that the various commands work correctly with actual IPSW, OTA, and macOS firmware files.

## Overview

Integration tests are designed to test the full workflow of extracting, parsing, and analyzing iOS and macOS firmware files. Due to the large size of these files (often several GB), the tests are designed to:

1. **Skip gracefully** when test data is not available
2. **Use cached artifacts** to avoid repeated downloads
3. **Run independently** so you can run specific test suites
4. **Be configurable** via environment variables

## Test Coverage

The integration tests cover the following commands:

- **info**: Display IPSW/OTA metadata
- **extract**: Extract kernelcache, dyld_shared_cache, and DeviceTree
- **kernel**: Kernel analysis (info, version, kexts, syscalls)
- **dyld**: dyld_shared_cache analysis (info, images, ObjC classes)
- **img4**: IMG4 file parsing and extraction
- **macho**: Mach-O binary analysis (info, search, code signing)

## Prerequisites

To run the integration tests, you need:

1. **Go 1.25.3 or later**
2. **Test IPSW files** (iOS, macOS, or OTA files)
3. **Sufficient disk space** (at least 20GB recommended for caching)
4. **Time** - some tests can take several minutes due to large file processing

## Configuration

Integration tests are configured using environment variables:

### Required Variables

At least one of these must be set to run the tests:

- `IPSW_TEST_IPSW`: Path to an iOS IPSW file
- `IPSW_TEST_OTA`: Path to an OTA update file
- `IPSW_TEST_MACOS`: Path to a macOS IPSW file

### Optional Variables

- `IPSW_TEST_CACHE`: Directory for caching extracted artifacts (default: `~/.cache/ipsw-test`)

### Example Configuration

```bash
# Set test data paths
export IPSW_TEST_IPSW="/path/to/iPhone16,1_18.2_22C150_Restore.ipsw"
export IPSW_TEST_OTA="/path/to/iPhone16,1_18.2_OTA.zip"
export IPSW_TEST_MACOS="/path/to/UniversalMac_14.0_23A344_Restore.ipsw"

# Optional: Set custom cache directory
export IPSW_TEST_CACHE="/tmp/ipsw-test-cache"
```

## Running the Tests

### Run All Integration Tests

```bash
cd test/integration
go test -v -timeout 60m
```

### Run Specific Test Suites

```bash
# Run only info tests
go test -v -run TestInfo

# Run only kernel tests
go test -v -run TestKernel

# Run only dyld tests
go test -v -run TestDyld
```

### Run Tests in Parallel

```bash
# Run tests in parallel (use with caution - can be resource intensive)
go test -v -parallel 4 -timeout 60m
```

## Getting Test Data

### Option 1: Download IPSWs Manually

You can download IPSW files from:

- [ipsw.me](https://ipsw.me) - iOS firmware files
- [Apple Developer](https://developer.apple.com/download/) - Beta versions
- [Archive.org](https://archive.org) - Historical versions

### Option 2: Use ipsw to Download

```bash
# Download latest iOS IPSW for a specific device
./ipsw download ipsw --device iPhone16,1 --latest

# Download latest OTA
./ipsw download ota --device iPhone16,1 --latest

# Download macOS IPSW
./ipsw download macos --latest
```

### Option 3: Use Small Test Files

For quick testing, you can use older, smaller IPSW files:

```bash
# Example: iPhone 5s iOS 12.5.7 (~2.5GB)
wget https://updates.cdn-apple.com/2022FCSWinter/fullrestores/002-64241/F1E03485-0D7F-4AC3-A9C1-E59AA0D6BD37/iPhone_4.0_64bit_12.5.7_16H81_Restore.ipsw

export IPSW_TEST_IPSW="iPhone_4.0_64bit_12.5.7_16H81_Restore.ipsw"
```

## Test Structure

Each test file follows this pattern:

1. **Setup**: Get test data configuration and skip if not available
2. **Build**: Build the `ipsw` binary for testing
3. **Extract**: Extract required components (kernelcache, dyld_shared_cache, etc.)
4. **Test**: Run the command and verify output
5. **Cleanup**: Automatic cleanup via `t.TempDir()`

## Caching Strategy

To minimize test execution time:

1. **Cache directory** is used to store extracted artifacts
2. **Extracted files** are reused across test runs when possible
3. **Temporary directories** are used for test-specific output
4. **Cleanup** happens automatically for temp dirs, but cache persists

## CI/CD Integration

The tests are designed to work in CI/CD environments:

```yaml
# Example GitHub Actions workflow
- name: Run Integration Tests
  env:
    IPSW_TEST_IPSW: ${{ github.workspace }}/test-data/test.ipsw
    IPSW_TEST_CACHE: ${{ github.workspace }}/test-cache
  run: |
    cd test/integration
    go test -v -timeout 60m
```

For CI, consider:

1. **Caching IPSW files** between runs to save bandwidth
2. **Using smaller test files** to reduce test time
3. **Running tests in parallel** on different OS versions
4. **Setting appropriate timeouts** (60+ minutes recommended)

## Troubleshooting

### Tests Are Skipped

If all tests are skipped, it means no test data is configured:

```bash
# Verify environment variables are set
echo $IPSW_TEST_IPSW
echo $IPSW_TEST_OTA
echo $IPSW_TEST_MACOS
```

### Tests Timeout

Some tests process large files and may timeout. Increase the timeout:

```bash
go test -v -timeout 120m
```

### Out of Disk Space

Integration tests can use significant disk space:

- IPSW files: 2-10 GB each
- Extracted caches: 5-20 GB each
- Temporary files: 1-5 GB

Ensure you have at least 20 GB free space before running tests.

### Tests Fail

If tests fail, check:

1. **IPSW file is valid**: Try opening it with `ipsw info <file>`
2. **Permissions**: Ensure you have read access to IPSW files
3. **Dependencies**: Build the project first with `make build`
4. **Logs**: Run with `-v` flag to see detailed output

## Writing New Tests

To add new integration tests:

1. Create a new test file in `test/integration/`
2. Use the helper functions from `helpers.go`
3. Use the test data management from `testdata.go`
4. Follow the existing test patterns
5. Ensure tests skip gracefully when data is unavailable

Example:

```go
func TestNewCommand(t *testing.T) {
    td := GetTestData(t)
    td.SkipIfNoIPSW(t)

    binPath := BuildIPSW(t)
    
    t.Run("test case", func(t *testing.T) {
        stdout := RunIPSWExpectSuccess(t, binPath, "command", "args", td.IPSWPath)
        // Add assertions
    })
}
```

## Performance Tips

1. **Use the cache directory** - Set `IPSW_TEST_CACHE` to a persistent location
2. **Run tests selectively** - Use `-run` to test specific functionality
3. **Use smaller IPSWs** - Older iOS versions are smaller
4. **Parallel execution** - Use `-parallel` but watch resource usage

## Contributing

When contributing integration tests:

1. Ensure tests skip gracefully without test data
2. Use the provided helper functions
3. Add appropriate logging with `t.Logf()`
4. Test with multiple IPSW versions if possible
5. Update this README if adding new test categories

## Support

For issues or questions:

- Open an issue on [GitHub](https://github.com/blacktop/ipsw/issues)
- Join the [Discord community](https://discord.gg/BEamsHAWAh)
- Check the [documentation](https://blacktop.github.io/ipsw)
