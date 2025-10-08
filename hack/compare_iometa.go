package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/blacktop/go-macho"
)

// IometaClass represents a class parsed from iometa output
type IometaClass struct {
	Name          string `json:"name"`
	Bundle        string `json:"bundle"`
	Ctor          uint64 `json:"ctor"`
	MetaPtr       uint64 `json:"meta_ptr"`
	ParentMeta    uint64 `json:"parent_meta"`
	Size          uint64 `json:"size"`
	VtableAddr    uint64 `json:"vtable_addr"`
	MetaVtableAddr uint64 `json:"metavtable_addr"`
}

// ClassDiff represents a difference between our implementation and iometa
type ClassDiff struct {
	ClassName    string                 `json:"class_name"`
	InIometa     bool                   `json:"in_iometa"`
	InOurs       bool                   `json:"in_ours"`
	IometaData   *IometaClass           `json:"iometa_data,omitempty"`
	OurData      *cpp.Class             `json:"our_data,omitempty"`
	FieldDiffs   map[string]interface{} `json:"field_diffs,omitempty"`
}

// BundleComparison represents comparison results for a single bundle
type BundleComparison struct {
	BundleName    string      `json:"bundle_name"`
	IometaCount   int         `json:"iometa_count"`
	OurCount      int         `json:"our_count"`
	MissingInOurs []string    `json:"missing_in_ours,omitempty"`
	ExtraInOurs   []string    `json:"extra_in_ours,omitempty"`
	Differences   []ClassDiff `json:"differences,omitempty"`
	Perfect       bool        `json:"perfect"`
}

// ComparisonResult represents the complete comparison output
type ComparisonResult struct {
	Bundles      []BundleComparison `json:"bundles"`
	TotalIometa  int                `json:"total_iometa"`
	TotalOurs    int                `json:"total_ours"`
	PerfectMatch bool               `json:"perfect_match"`
}

var (
	entryFilter   string
	iometaBinary  string
	outputFile    string
	verbose       bool

	// Regex to parse iometa output:
	// vtab=0xfffffe0007cf0c30 size=0x00000028 init=0xfffffe00089340c8 meta=0xfffffe000b476018 parent=0x0000000000000000 metavtab=0xfffffe0007cf0ba8 OSMetaClass (__kernel__)
	// Also handles unknown vtables: vtab=??????????????????
	iometaLineRe = regexp.MustCompile(`vtab=(0x[0-9a-fA-F]+|\?+)\s+size=(0x[0-9a-fA-F]+)\s+init=(0x[0-9a-fA-F]+)\s+meta=(0x[0-9a-fA-F]+)\s+parent=(0x[0-9a-fA-F]+)\s+metavtab=(0x[0-9a-fA-F]+)\s+([^\s]+)\s+\(([^)]+)\)`)
)

func init() {
	flag.StringVar(&entryFilter, "entry", "", "Only compare specified bundle/entry (e.g., __kernel__)")
	flag.StringVar(&iometaBinary, "iometa", "OPC/iometa/iometa", "Path to iometa binary")
	flag.StringVar(&outputFile, "output", "", "Write JSON diff to file (empty = no file output)")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <kernelcache>\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Compares Go-based C++ class discovery against canonical iometa output.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExit codes:\n")
		fmt.Fprintf(os.Stderr, "  0 = perfect match\n")
		fmt.Fprintf(os.Stderr, "  1 = differences found\n")
		fmt.Fprintf(os.Stderr, "  2 = error occurred\n")
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	kernelPath := flag.Arg(0)

	// Run comparison
	result, err := compareImplementations(kernelPath)
	if err != nil {
		log.Errorf("Comparison failed: %v", err)
		os.Exit(2)
	}

	// Print summary
	printSummary(result)

	// Write JSON output if requested
	if outputFile != "" {
		if err := writeJSON(result, outputFile); err != nil {
			log.Errorf("Failed to write JSON output: %v", err)
			os.Exit(2)
		}
		log.Infof("Detailed diff written to %s", outputFile)
	}

	// Exit with appropriate code
	if result.PerfectMatch {
		os.Exit(0)
	}
	os.Exit(1)
}

// normalizeBundle converts bundle names to a canonical form
// iometa uses "__kernel__" for the kernel proper, while our implementation uses "com.apple.kernel"
func normalizeBundle(bundle string) string {
	if bundle == "__kernel__" {
		return "com.apple.kernel"
	}
	return bundle
}

// parseIometaOutput parses iometa output and returns classes grouped by bundle
func parseIometaOutput(output []byte) (map[string][]IometaClass, error) {
	bundles := make(map[string][]IometaClass)

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip warning/error lines
		if strings.Contains(line, "[WRN]") || strings.Contains(line, "[ERR]") {
			continue
		}

		matches := iometaLineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		class := IometaClass{
			Name:   strings.TrimSpace(matches[7]),
			Bundle: normalizeBundle(matches[8]), // Normalize bundle name
		}

		// Parse hex values
		// VtableAddr may be "??????????????????" (unknown) - leave as 0 in that case
		if strings.HasPrefix(matches[1], "0x") {
			fmt.Sscanf(matches[1], "0x%x", &class.VtableAddr)
		}
		fmt.Sscanf(matches[2], "0x%x", &class.Size)
		fmt.Sscanf(matches[3], "0x%x", &class.Ctor)
		fmt.Sscanf(matches[4], "0x%x", &class.MetaPtr)
		fmt.Sscanf(matches[5], "0x%x", &class.ParentMeta)
		fmt.Sscanf(matches[6], "0x%x", &class.MetaVtableAddr)

		bundles[class.Bundle] = append(bundles[class.Bundle], class)
	}

	return bundles, scanner.Err()
}

// runIometa executes iometa and returns its output
func runIometa(kernelPath string, bundleFilter string) ([]byte, error) {
	args := []string{"-a", "-n"} // all metadata, no color

	if bundleFilter != "" {
		// Convert our bundle naming to iometa's naming
		iometaBundle := bundleFilter
		if bundleFilter == "com.apple.kernel" {
			iometaBundle = "__kernel__"
		}
		args = append(args, "-B", iometaBundle)
	}

	args = append(args, kernelPath)

	cmd := exec.Command(iometaBinary, args...)
	log.Debugf("Running: %s %s", iometaBinary, strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		// iometa may return non-zero on warnings, check if we got any output
		if len(output) == 0 {
			return nil, fmt.Errorf("iometa failed: %w\n%s", err, output)
		}
		log.Warnf("iometa returned error but produced output: %v", err)
	}

	return output, nil
}

// getOurClasses runs our Go implementation and returns classes grouped by bundle
func getOurClasses(kernelPath string, entryFilter []string) (map[string][]cpp.Class, error) {
	m, err := macho.Open(kernelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open kernelcache: %w", err)
	}
	defer m.Close()

	cppEngine := cpp.Create(m, &cpp.Config{
		WithMethods:           false,
		Entries:               entryFilter,
		MaxCtorInstructions:   1000,
		DisableStubResolution: true,
		UseXrefAnchorDiscovery: false,
	})

	classes, err := cppEngine.GetClasses()
	if err != nil {
		return nil, fmt.Errorf("failed to get classes: %w", err)
	}

	// Group by bundle
	bundles := make(map[string][]cpp.Class)
	for _, class := range classes {
		bundles[class.Bundle] = append(bundles[class.Bundle], class)
	}

	return bundles, nil
}

// compareBundle compares classes in a single bundle
func compareBundle(bundleName string, iometaClasses []IometaClass, ourClasses []cpp.Class) BundleComparison {
	result := BundleComparison{
		BundleName:  bundleName,
		IometaCount: len(iometaClasses),
		OurCount:    len(ourClasses),
		Perfect:     true,
	}

	// Build lookup maps
	iometaMap := make(map[string]*IometaClass)
	for i := range iometaClasses {
		iometaMap[iometaClasses[i].Name] = &iometaClasses[i]
	}

	ourMap := make(map[string]*cpp.Class)
	for i := range ourClasses {
		ourMap[ourClasses[i].Name] = &ourClasses[i]
	}

	// Find missing in ours
	for name := range iometaMap {
		if _, exists := ourMap[name]; !exists {
			result.MissingInOurs = append(result.MissingInOurs, name)
			result.Perfect = false
		}
	}

	// Find extra in ours
	for name := range ourMap {
		if _, exists := iometaMap[name]; !exists {
			result.ExtraInOurs = append(result.ExtraInOurs, name)
			result.Perfect = false
		}
	}

	// Compare metadata for classes in both
	for name, iometaClass := range iometaMap {
		ourClass, exists := ourMap[name]
		if !exists {
			continue
		}

		diff := ClassDiff{
			ClassName:  name,
			InIometa:   true,
			InOurs:     true,
			FieldDiffs: make(map[string]interface{}),
		}

		// Compare fields
		if iometaClass.Ctor != ourClass.Ctor {
			diff.FieldDiffs["ctor"] = map[string]uint64{
				"iometa": iometaClass.Ctor,
				"ours":   ourClass.Ctor,
			}
		}

		if iometaClass.MetaPtr != ourClass.MetaPtr {
			diff.FieldDiffs["meta_ptr"] = map[string]uint64{
				"iometa": iometaClass.MetaPtr,
				"ours":   ourClass.MetaPtr,
			}
		}

		if iometaClass.Size != uint64(ourClass.Size) {
			diff.FieldDiffs["size"] = map[string]uint64{
				"iometa": iometaClass.Size,
				"ours":   uint64(ourClass.Size),
			}
		}

		if iometaClass.VtableAddr != ourClass.VtableAddr {
			diff.FieldDiffs["vtable_addr"] = map[string]uint64{
				"iometa": iometaClass.VtableAddr,
				"ours":   ourClass.VtableAddr,
			}
		}

		if iometaClass.MetaVtableAddr != ourClass.MetaVtableAddr {
			diff.FieldDiffs["metavtable_addr"] = map[string]uint64{
				"iometa": iometaClass.MetaVtableAddr,
				"ours":   ourClass.MetaVtableAddr,
			}
		}

		// If there are differences, record them
		if len(diff.FieldDiffs) > 0 {
			diff.IometaData = iometaClass
			diff.OurData = ourClass
			result.Differences = append(result.Differences, diff)
			result.Perfect = false
		}
	}

	// Sort lists for consistent output
	sort.Strings(result.MissingInOurs)
	sort.Strings(result.ExtraInOurs)

	return result
}

// compareImplementations compares iometa vs our implementation
func compareImplementations(kernelPath string) (*ComparisonResult, error) {
	log.Info("Running iometa...")

	var bundleFilter string
	if entryFilter != "" {
		bundleFilter = entryFilter
	}

	iometaOutput, err := runIometa(kernelPath, bundleFilter)
	if err != nil {
		return nil, fmt.Errorf("iometa execution failed: %w", err)
	}

	log.Debug("Parsing iometa output...")
	iometaBundles, err := parseIometaOutput(iometaOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse iometa output: %w", err)
	}

	log.Infof("iometa found %d bundles", len(iometaBundles))

	log.Info("Running our Go implementation...")
	var entries []string
	if entryFilter != "" {
		entries = []string{entryFilter}
	}

	ourBundles, err := getOurClasses(kernelPath, entries)
	if err != nil {
		return nil, fmt.Errorf("our implementation failed: %w", err)
	}

	log.Infof("Our implementation found %d bundles", len(ourBundles))

	// Build complete bundle list
	bundleSet := make(map[string]bool)
	for bundle := range iometaBundles {
		bundleSet[bundle] = true
	}
	for bundle := range ourBundles {
		bundleSet[bundle] = true
	}

	bundles := make([]string, 0, len(bundleSet))
	for bundle := range bundleSet {
		bundles = append(bundles, bundle)
	}
	sort.Strings(bundles)

	// Compare each bundle
	result := &ComparisonResult{
		PerfectMatch: true,
	}

	for _, bundle := range bundles {
		iometaClasses := iometaBundles[bundle]
		ourClasses := ourBundles[bundle]

		bundleResult := compareBundle(bundle, iometaClasses, ourClasses)

		result.Bundles = append(result.Bundles, bundleResult)
		result.TotalIometa += bundleResult.IometaCount
		result.TotalOurs += bundleResult.OurCount

		if !bundleResult.Perfect {
			result.PerfectMatch = false
		}
	}

	return result, nil
}

// printSummary prints a human-readable summary
func printSummary(result *ComparisonResult) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("C++ CLASS DISCOVERY COMPARISON: iometa vs Go Implementation")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("\nOverall Totals:\n")
	fmt.Printf("  iometa:  %d classes\n", result.TotalIometa)
	fmt.Printf("  ours:    %d classes\n", result.TotalOurs)
	fmt.Printf("  delta:   %+d\n", result.TotalOurs-result.TotalIometa)

	if result.PerfectMatch {
		fmt.Println("\n✅ PERFECT MATCH - All bundles match exactly!")
		return
	}

	fmt.Println("\n❌ DIFFERENCES FOUND\n")

	// Print per-bundle summary
	for _, bundle := range result.Bundles {
		if bundle.Perfect {
			fmt.Printf("✅ %-40s  iometa: %4d  ours: %4d\n",
				bundle.BundleName, bundle.IometaCount, bundle.OurCount)
			continue
		}

		fmt.Printf("❌ %-40s  iometa: %4d  ours: %4d  delta: %+d\n",
			bundle.BundleName, bundle.IometaCount, bundle.OurCount,
			bundle.OurCount-bundle.IometaCount)

		if len(bundle.MissingInOurs) > 0 {
			fmt.Printf("   Missing in ours (%d):\n", len(bundle.MissingInOurs))
			for _, name := range bundle.MissingInOurs {
				fmt.Printf("     - %s\n", name)
			}
		}

		if len(bundle.ExtraInOurs) > 0 {
			fmt.Printf("   Extra in ours (%d):\n", len(bundle.ExtraInOurs))
			for _, name := range bundle.ExtraInOurs {
				fmt.Printf("     + %s\n", name)
			}
		}

		if len(bundle.Differences) > 0 {
			fmt.Printf("   Metadata differences (%d):\n", len(bundle.Differences))
			for _, diff := range bundle.Differences {
				fmt.Printf("     ~ %s\n", diff.ClassName)
				for field, values := range diff.FieldDiffs {
					fmt.Printf("       %s: %v\n", field, values)
				}
			}
		}

		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 80))
}

// writeJSON writes the comparison result as JSON
func writeJSON(result *ComparisonResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
