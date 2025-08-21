package vtable

import (
	"os"
	"testing"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
)

// Test configuration for KDK analysis
const (
	// Target class counts for validation
	ExpectedKDKClasses = 159  // Target class count for KDK
	ExpectediOSClasses = 3188 // Target class count for iOS kernelcache

	// Test data paths (should be set via environment variables)
	EnvKDKPath = "IPSW_TEST_KDK_PATH"
	EnviOSPath = "IPSW_TEST_IOS_PATH"
)

// TestVtableSymbolicationKDK tests vtable symbolication on KDK targeting 159 classes
func TestVtableSymbolicationKDK(t *testing.T) {
	kdkPath := os.Getenv(EnvKDKPath)
	if kdkPath == "" {
		t.Skip("KDK test path not set in", EnvKDKPath)
	}

	if !fileExists(kdkPath) {
		t.Skipf("KDK file not found at %s", kdkPath)
	}

	log.SetLevel(log.DebugLevel)

	t.Logf("Testing KDK vtable symbolication with target of %d classes", ExpectedKDKClasses)

	// Load the KDK kernelcache
	file, err := macho.Open(kdkPath)
	if err != nil {
		t.Fatalf("Failed to open KDK file: %v", err)
	}
	defer file.Close()

	// Create symbolicator
	vs := NewVtableSymbolicator(file)

	// Run symbolication
	err = vs.SymbolicateVtables()
	if err != nil {
		t.Fatalf("Failed to symbolicate vtables: %v", err)
	}

	// Get discovered classes
	classes := vs.GetClasses()
	classCount := len(classes)

	t.Logf("Discovered %d classes in KDK", classCount)

	// Validate class count is reasonable
	if classCount < 50 {
		t.Errorf("Class count too low: %d (expected at least 50)", classCount)
	}

	// Check if we're approaching the target
	if classCount < ExpectedKDKClasses/2 {
		t.Errorf("Class count significantly below target: %d (expected around %d)", classCount, ExpectedKDKClasses)
	}

	// Log progress toward target
	progress := float64(classCount) / float64(ExpectedKDKClasses) * 100
	t.Logf("Progress toward KDK target: %.1f%% (%d/%d classes)", progress, classCount, ExpectedKDKClasses)

	// Validate class structure
	validateDiscoveredClasses(t, classes)

	// Test class lookup functionality
	testClassLookup(t, vs, classes)

	// Log some example classes for debugging
	logExampleClasses(t, classes, 10)
}

// TestVtableSymbolicationiOS tests vtable symbolication on iOS kernelcache
func TestVtableSymbolicationiOS(t *testing.T) {
	iosPath := os.Getenv(EnviOSPath)
	if iosPath == "" {
		t.Skip("iOS test path not set in", EnviOSPath)
	}

	if !fileExists(iosPath) {
		t.Skipf("iOS file not found at %s", iosPath)
	}

	log.SetLevel(log.DebugLevel)

	t.Logf("Testing iOS vtable symbolication with target of %d classes", ExpectediOSClasses)

	// Load the iOS kernelcache
	file, err := macho.Open(iosPath)
	if err != nil {
		t.Fatalf("Failed to open iOS file: %v", err)
	}
	defer file.Close()

	// Create symbolicator
	vs := NewVtableSymbolicator(file)

	// Run symbolication
	err = vs.SymbolicateVtables()
	if err != nil {
		t.Fatalf("Failed to symbolicate vtables: %v", err)
	}

	// Get discovered classes
	classes := vs.GetClasses()
	classCount := len(classes)

	t.Logf("Discovered %d classes in iOS kernelcache", classCount)

	// Validate class count is reasonable
	if classCount < 100 {
		t.Errorf("Class count too low: %d (expected at least 100)", classCount)
	}

	// Check if we're approaching the target
	if classCount < ExpectediOSClasses/10 {
		t.Errorf("Class count significantly below target: %d (expected around %d)", classCount, ExpectediOSClasses)
	}

	// Log progress toward target
	progress := float64(classCount) / float64(ExpectediOSClasses) * 100
	t.Logf("Progress toward iOS target: %.1f%% (%d/%d classes)", progress, classCount, ExpectediOSClasses)

	// Validate class structure
	validateDiscoveredClasses(t, classes)

	// Test class lookup functionality
	testClassLookup(t, vs, classes)

	// Log some example classes for debugging
	logExampleClasses(t, classes, 20)
}

// TestConstructorDiscovery tests OSMetaClass constructor discovery
func TestConstructorDiscovery(t *testing.T) {
	kdkPath := os.Getenv(EnvKDKPath)
	if kdkPath == "" {
		t.Skip("KDK test path not set in", EnvKDKPath)
	}

	if !fileExists(kdkPath) {
		t.Skipf("KDK file not found at %s", kdkPath)
	}

	// Load the KDK kernelcache
	file, err := macho.Open(kdkPath)
	if err != nil {
		t.Fatalf("Failed to open KDK file: %v", err)
	}
	defer file.Close()

	// Create symbolicator
	vs := NewVtableSymbolicator(file)

	// Test constructor discovery
	err = vs.findOSMetaClassConstructor()
	if err != nil {
		t.Fatalf("Failed to find OSMetaClass constructor: %v", err)
	}

	if vs.constructorAddr == 0 {
		t.Error("Constructor address not found")
	}

	t.Logf("Found OSMetaClass constructor at 0x%x", vs.constructorAddr)
	t.Logf("Constructor target set has %d entries", len(vs.constructorTargetSet))

	// Validate target set is reasonable
	if len(vs.constructorTargetSet) == 0 {
		t.Error("Constructor target set is empty")
	}

	if len(vs.constructorTargetSet) > 100 {
		t.Errorf("Constructor target set suspiciously large: %d entries", len(vs.constructorTargetSet))
	}
}

// TestEmulatorAdapter tests the emulator adapter functionality
func TestEmulatorAdapter(t *testing.T) {
	// Create emulator adapter
	adapter := NewEmulatorAdapter()

	// Test basic functionality
	if adapter.GetPC() != 0 {
		t.Error("Initial PC should be 0")
	}

	// Test register operations
	adapter.SetRegister(0, 0x1234567890abcdef)
	if adapter.GetRegister(0) != 0x1234567890abcdef {
		t.Error("Register set/get failed")
	}

	// Test setup functions
	adapter.SetupForAllocFunction(64)
	if adapter.GetRegister(1) != 64 {
		t.Error("SetupForAllocFunction failed to set class size")
	}

	// Test memory operations
	testData := []byte{0x01, 0x02, 0x03, 0x04}
	err := adapter.SetMemory(0x1000, testData)
	if err != nil {
		t.Errorf("Failed to set memory: %v", err)
	}

	readData, err := adapter.GetMemory(0x1000, len(testData))
	if err != nil {
		t.Errorf("Failed to read memory: %v", err)
	}

	for i, b := range testData {
		if readData[i] != b {
			t.Errorf("Memory read/write mismatch at index %d: got %#x, want %#x", i, readData[i], b)
		}
	}

	t.Log("Emulator adapter tests passed")
}

// BenchmarkVtableSymbolication benchmarks the vtable symbolication process
func BenchmarkVtableSymbolication(b *testing.B) {
	kdkPath := os.Getenv(EnvKDKPath)
	if kdkPath == "" {
		b.Skip("KDK test path not set in", EnvKDKPath)
	}

	if !fileExists(kdkPath) {
		b.Skipf("KDK file not found at %s", kdkPath)
	}

	// Load the KDK kernelcache
	file, err := macho.Open(kdkPath)
	if err != nil {
		b.Fatalf("Failed to open KDK file: %v", err)
	}
	defer file.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create symbolicator
		vs := NewVtableSymbolicator(file)

		// Run symbolication
		err = vs.SymbolicateVtables()
		if err != nil {
			b.Fatalf("Failed to symbolicate vtables: %v", err)
		}

		// Get class count for validation
		classes := vs.GetClasses()
		if len(classes) < 10 {
			b.Errorf("Insufficient classes discovered: %d", len(classes))
		}
	}
}

// Helper functions

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func validateDiscoveredClasses(t *testing.T, classes []*ClassMeta) {
	t.Helper()

	if len(classes) == 0 {
		t.Error("No classes discovered")
		return
	}

	// Validate class structure
	validClasses := 0
	for _, class := range classes {
		if class.Name == "" {
			t.Errorf("Class with empty name at MetaPtr 0x%x", class.MetaPtr)
			continue
		}

		if class.MetaPtr == 0 {
			t.Errorf("Class %s has zero MetaPtr", class.Name)
			continue
		}

		validClasses++
	}

	t.Logf("Validated %d/%d classes", validClasses, len(classes))

	// Check for known important classes
	knownClasses := []string{"OSObject", "IOService", "IORegistryEntry", "IOUserClient"}
	foundKnown := 0

	for _, class := range classes {
		for _, known := range knownClasses {
			if class.Name == known {
				foundKnown++
				t.Logf("Found important class: %s (MetaPtr: 0x%x)", class.Name, class.MetaPtr)
				break
			}
		}
	}

	t.Logf("Found %d/%d known important classes", foundKnown, len(knownClasses))
}

func testClassLookup(t *testing.T, vs *VtableSymbolicator, classes []*ClassMeta) {
	t.Helper()

	if len(classes) == 0 {
		return
	}

	// Test GetClassByName
	testClass := classes[0]
	foundClass, exists := vs.GetClassByName(testClass.Name)
	if !exists {
		t.Errorf("Failed to lookup class by name: %s", testClass.Name)
	} else if foundClass != testClass {
		t.Errorf("Lookup returned wrong class for name: %s", testClass.Name)
	}

	// Test GetSymbolMap
	symbolMap := vs.GetSymbolMap()
	t.Logf("Symbol map contains %d entries", len(symbolMap))
}

func logExampleClasses(t *testing.T, classes []*ClassMeta, limit int) {
	t.Helper()

	if len(classes) == 0 {
		return
	}

	t.Log("Example discovered classes:")
	count := 0
	for _, class := range classes {
		if count >= limit {
			break
		}

		t.Logf("  %s (MetaPtr: 0x%x, Size: %d, Methods: %d)",
			class.Name, class.MetaPtr, class.Size, len(class.Methods))
		count++
	}

	if len(classes) > limit {
		t.Logf("  ... and %d more classes", len(classes)-limit)
	}
}

// TestSetupInstructions demonstrates how to set up test data
func TestSetupInstructions(t *testing.T) {
	t.Log("To run comprehensive vtable tests:")
	t.Log("")
	t.Log("1. Set KDK path environment variable:")
	t.Logf("   export %s=/path/to/kdk/kernelcache", EnvKDKPath)
	t.Log("")
	t.Log("2. Set iOS kernelcache path environment variable:")
	t.Logf("   export %s=/path/to/ios/kernelcache", EnviOSPath)
	t.Log("")
	t.Log("3. Run tests:")
	t.Log("   go test -v ./pkg/kernelcache/vtable")
	t.Log("")
	t.Log("4. Run benchmarks:")
	t.Log("   go test -bench=. ./pkg/kernelcache/vtable")
}
