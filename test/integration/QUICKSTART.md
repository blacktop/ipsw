# Integration Tests Quick Start Guide

This is a quick reference for running the IPSW integration tests.

## TL;DR

```bash
# 1. Set environment variable to point to an IPSW file
export IPSW_TEST_IPSW="/path/to/iPhone16,1_18.2_22C150_Restore.ipsw"

# 2. Run the tests
cd test/integration
go test -v -timeout 60m

# Or use Make
make test-integration
```

## One-Line Setup Examples

### Using an existing IPSW file
```bash
export IPSW_TEST_IPSW="/path/to/your/existing.ipsw" && cd test/integration && go test -v
```

### Download and test (using ipsw tool)
```bash
# Download a recent IPSW first
./ipsw download ipsw --device iPhone16,1 --latest --output /tmp
export IPSW_TEST_IPSW="/tmp/iPhone*.ipsw"
make test-integration-quick
```

## Running Specific Tests

```bash
# Only run info tests (fastest)
go test -v -run TestInfo

# Only run extract kernelcache test
go test -v -run TestExtractKernelcache

# Run all extract tests
go test -v -run TestExtract
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `IPSW_TEST_IPSW` | Path to iOS IPSW file | `/tmp/iPhone.ipsw` |
| `IPSW_TEST_OTA` | Path to OTA file | `/tmp/iPhone.zip` |
| `IPSW_TEST_MACOS` | Path to macOS IPSW | `/tmp/Mac.ipsw` |
| `IPSW_TEST_CACHE` | Cache directory | `~/.cache/ipsw-test` |

## Make Targets

```bash
make test                    # Run unit tests
make test-integration        # Run all integration tests (60m timeout)
make test-integration-quick  # Run quick tests only (30m timeout)
```

## Getting Test Data

### Option 1: Use ipsw to download
```bash
# Build ipsw first
make build

# Download a test IPSW
./ipsw download ipsw --device iPhone16,1 --latest --output ~/ipsw-test-data
export IPSW_TEST_IPSW="$(ls ~/ipsw-test-data/*.ipsw | head -n1)"
```

### Option 2: Manual download
Visit [ipsw.me](https://ipsw.me) and download any iOS IPSW file.

### Option 3: Use a small/old IPSW
Smaller, older IPSWs are faster for testing:
```bash
# iPhone 5s iOS 12.5.7 is ~2.5GB
wget -P ~/ipsw-test-data "https://updates.cdn-apple.com/2022FCSWinter/fullrestores/002-64241/F1E03485-0D7F-4AC3-A9C1-E59AA0D6BD37/iPhone_4.0_64bit_12.5.7_16H81_Restore.ipsw"
export IPSW_TEST_IPSW="~/ipsw-test-data/iPhone_4.0_64bit_12.5.7_16H81_Restore.ipsw"
```

## What Gets Tested?

✅ **info** - Display firmware metadata  
✅ **extract** - Extract kernelcache, dyld, DeviceTree  
✅ **kernel** - Kernel analysis (version, kexts, syscalls)  
✅ **dyld** - Shared cache analysis  
✅ **img4** - IMG4 file parsing  
✅ **macho** - Mach-O binary analysis  
✅ **diff** - Compare firmware files  

## Common Issues

### "Tests are skipped"
You need to set environment variables:
```bash
export IPSW_TEST_IPSW="/path/to/ipsw/file"
```

### "Test timeout"
Increase timeout:
```bash
go test -v -timeout 120m
```

### "Out of disk space"
- IPSW files are large (2-10 GB)
- Extracted caches can be 5-20 GB
- Ensure you have at least 20 GB free space

### Tests are slow
Run quick tests only:
```bash
make test-integration-quick
```

## CI/CD Usage

```yaml
- name: Run Integration Tests
  env:
    IPSW_TEST_IPSW: ${{ github.workspace }}/test-data/test.ipsw
    IPSW_TEST_CACHE: ${{ github.workspace }}/test-cache
  run: make test-integration-quick
```

## Need Help?

- Read the full [README.md](./README.md)
- Open an issue on [GitHub](https://github.com/blacktop/ipsw/issues)
- Join [Discord](https://discord.gg/BEamsHAWAh)
