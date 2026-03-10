package cpp

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

const (
	benchmarkKDKKernelEnv = "IPSW_BENCH_KDK_KERNEL"
	benchmarkIOSKernelEnv = "IPSW_BENCH_IOS_KERNEL"
	testKDKPathEnv        = "IPSW_TEST_KDK_PATH"
)

var (
	benchmarkClassSink    []Class
	benchmarkFunctionSink types.Function
)

type benchmarkKernelFixture struct {
	path string
	root *macho.File
}

func BenchmarkScannerScanKDK(b *testing.B) {
	fixture := openBenchmarkKernelFixture(b)

	b.ReportAllocs()
	for b.Loop() {
		scanner := NewScanner(fixture.root, Config{})
		classes, err := scanner.Scan()
		if err != nil {
			b.Fatalf("scan %s: %v", fixture.path, err)
		}
		if len(classes) == 0 {
			b.Fatalf("scan %s returned no classes", fixture.path)
		}
		benchmarkClassSink = classes
	}
}

func BenchmarkScannerScanNearbyIOSKernelEntry(b *testing.B) {
	path := os.Getenv(benchmarkIOSKernelEnv)
	if path == "" {
		b.Skipf("set %s to an iOS kernelcache path", benchmarkIOSKernelEnv)
	}
	fixture := openBenchmarkKernelFixtureAtPath(b, path)
	if fixture.root.FileHeader.Type != types.MH_FILESET {
		b.Skip("kernel-entry scan is identical to full scan on non-fileset fixtures")
	}

	b.ReportAllocs()
	for b.Loop() {
		scanner := NewScanner(fixture.root, Config{Entries: []string{kernelBundleName}})
		classes, err := scanner.Scan()
		if err != nil {
			b.Fatalf("scan %s kernel entry: %v", fixture.path, err)
		}
		if len(classes) == 0 {
			b.Fatalf("scan %s kernel entry returned no classes", fixture.path)
		}
		benchmarkClassSink = classes
	}
}

func BenchmarkScannerScanKernelEntryKDK(b *testing.B) {
	fixture := openBenchmarkKernelFixture(b)
	if fixture.root.FileHeader.Type != types.MH_FILESET {
		b.Skip("kernel-entry scan is identical to full scan on non-fileset fixtures")
	}

	b.ReportAllocs()
	for b.Loop() {
		scanner := NewScanner(fixture.root, Config{Entries: []string{kernelBundleName}})
		classes, err := scanner.Scan()
		if err != nil {
			b.Fatalf("scan %s kernel entry: %v", fixture.path, err)
		}
		if len(classes) == 0 {
			b.Fatalf("scan %s kernel entry returned no classes", fixture.path)
		}
		benchmarkClassSink = classes
	}
}

func BenchmarkScannerScanClassFilteredKDK(b *testing.B) {
	fixture := openBenchmarkKernelFixture(b)
	_, classes := seedBenchmarkScan(b, fixture)
	className := selectBenchmarkClassName(classes)
	if className == "" {
		b.Skipf("no benchmark class name found in %s", fixture.path)
	}

	b.ReportAllocs()
	for b.Loop() {
		scanner := NewScanner(fixture.root, Config{ClassName: className})
		classes, err := scanner.Scan()
		if err != nil {
			b.Fatalf("scan %s filtered to %q: %v", fixture.path, className, err)
		}
		if len(classes) == 0 {
			b.Fatalf("scan %s filtered to %q returned no classes", fixture.path, className)
		}
		benchmarkClassSink = classes
	}
}

func BenchmarkScannerFunctionLookupKDK(b *testing.B) {
	fixture := openBenchmarkKernelFixture(b)
	scanner, classes := seedBenchmarkScan(b, fixture)

	owner, addr, err := selectLookupTarget(scanner, classes)
	if err != nil {
		b.Skipf("no benchmark lookup target found in %s: %v", fixture.path, err)
	}

	b.ReportAllocs()
	for b.Loop() {
		fn, err := scanner.functionForAddr(owner, addr)
		if err != nil {
			b.Fatalf("lookup %#x in %s: %v", addr, fixture.path, err)
		}
		benchmarkFunctionSink = fn
	}
}

func openBenchmarkKernelFixture(tb testing.TB) benchmarkKernelFixture {
	tb.Helper()

	path := resolveBenchmarkKernelPath(tb)
	return openBenchmarkKernelFixtureAtPath(tb, path)
}

func openBenchmarkKernelFixtureAtPath(tb testing.TB, path string) benchmarkKernelFixture {
	tb.Helper()

	root, err := macho.Open(path)
	if err != nil {
		tb.Fatalf("open benchmark kernel %s: %v", path, err)
	}
	tb.Cleanup(func() {
		if err := root.Close(); err != nil {
			tb.Errorf("close benchmark kernel %s: %v", path, err)
		}
	})

	return benchmarkKernelFixture{
		path: path,
		root: root,
	}
}

func seedBenchmarkScan(tb testing.TB, fixture benchmarkKernelFixture) (*Scanner, []Class) {
	tb.Helper()

	scanner := NewScanner(fixture.root, Config{})
	classes, err := scanner.Scan()
	if err != nil {
		tb.Fatalf("seed scan %s: %v", fixture.path, err)
	}
	if len(classes) == 0 {
		tb.Skipf("seed scan %s returned no classes", fixture.path)
	}

	return scanner, classes
}

func selectBenchmarkClassName(classes []Class) string {
	for _, class := range classes {
		if strings.TrimSpace(class.Name) != "" {
			return class.Name
		}
	}
	return ""
}

func selectLookupTarget(scanner *Scanner, classes []Class) (*macho.File, uint64, error) {
	for _, class := range classes {
		if class.Ctor == 0 {
			continue
		}
		owner := scanner.fileForVMAddr(class.Ctor)
		if owner == nil {
			continue
		}
		if _, err := scanner.functionForAddr(owner, class.Ctor); err != nil {
			continue
		}
		return owner, class.Ctor, nil
	}

	return nil, 0, fmt.Errorf("no constructor address resolved to a function")
}

func resolveBenchmarkKernelPath(tb testing.TB) string {
	tb.Helper()

	for _, hint := range []string{os.Getenv(benchmarkKDKKernelEnv), os.Getenv(testKDKPathEnv)} {
		if path := resolveBenchmarkKernelHint(hint); path != "" {
			return path
		}
	}

	for _, root := range benchmarkKDKRoots() {
		for _, pattern := range benchmarkKernelPatterns(filepath.Join(root, "*.kdk")) {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				tb.Fatalf("glob benchmark kernels %s: %v", pattern, err)
			}
			if path := firstRegularFile(matches); path != "" {
				return path
			}
		}
	}

	tb.Skipf("benchmark fixture not found; set %s or %s to a KDK kernel path or KDK root", benchmarkKDKKernelEnv, testKDKPathEnv)
	return ""
}

func resolveBenchmarkKernelHint(hint string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return ""
	}

	info, err := os.Stat(hint)
	if err != nil {
		return ""
	}

	if info.Mode().IsRegular() {
		return hint
	}
	if !info.IsDir() {
		return ""
	}

	for _, base := range []string{hint, filepath.Join(hint, "System", "Library", "Kernels")} {
		for _, pattern := range benchmarkKernelPatterns(base) {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			if path := firstRegularFile(matches); path != "" {
				return path
			}
		}
	}

	return ""
}

func benchmarkKDKRoots() []string {
	roots := []string{
		"/Library/Developer/KDKs",
		filepath.Join(os.Getenv("HOME"), "Library", "Developer", "KDKs"),
		"/Applications/KDKs",
		"/AppleInternal/KDKs",
	}

	filtered := roots[:0]
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			filtered = append(filtered, root)
		}
	}
	return filtered
}

func benchmarkKernelPatterns(base string) []string {
	return []string{
		filepath.Join(base, "System", "Library", "Kernels", "kernel.release*"),
		filepath.Join(base, "System", "Library", "Kernels", "kernel.development*"),
		filepath.Join(base, "System", "Library", "Kernels", "kernel*"),
		filepath.Join(base, "kernel.release*"),
		filepath.Join(base, "kernel.development*"),
		filepath.Join(base, "kernel*"),
	}
}

func firstRegularFile(paths []string) string {
	sort.Strings(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}
