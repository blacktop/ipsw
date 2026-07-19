package dyld

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestGetDscPathsInMountMatchesRosettaAOTCaches(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		"System/Library/dyld/aot_shared_cache.0",
		"System/Library/dyld/aot_shared_cache.6",
		"System/Library/dyld/dyld_shared_cache_x86_64",
		"System/Library/dyld/dyld_shared_cache_x86_64.01",
		"System/DriverKit/System/Library/dyld/dyld_shared_cache_x86_64",
		"System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64",
		"System/Library/dyld/aot_shared_cache",
		"System/Library/dyld/aot_shared_cache.foo",
		"System/Library/dyld/aot_shared_cache.0.map",
		"System/Library/Caches/com.apple.dyld/aot_shared_cache.0",
		"usr/lib/aot_shared_cache.0",
	}
	for _, path := range paths {
		writeDscFixture(t, root, path, "")
	}

	tests := []struct {
		name string
		all  bool
		want []string
	}{
		{
			name: "default cache paths",
			want: []string{
				"System/Library/dyld/aot_shared_cache.0",
				"System/Library/dyld/aot_shared_cache.6",
				"System/Library/dyld/dyld_shared_cache_x86_64",
				"System/Library/dyld/dyld_shared_cache_x86_64.01",
			},
		},
		{
			name: "all cache paths",
			all:  true,
			want: []string{
				"System/DriverKit/System/Library/dyld/dyld_shared_cache_x86_64",
				"System/Library/dyld/aot_shared_cache.0",
				"System/Library/dyld/aot_shared_cache.6",
				"System/Library/dyld/dyld_shared_cache_x86_64",
				"System/Library/dyld/dyld_shared_cache_x86_64.01",
				"System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := GetDscPathsInMount(root, false, test.all)
			if err != nil {
				t.Fatalf("GetDscPathsInMount() failed: %v", err)
			}
			got := make([]string, 0, len(matches))
			for _, match := range matches {
				rel, err := filepath.Rel(root, match)
				if err != nil {
					t.Fatalf("failed to make %q relative: %v", match, err)
				}
				got = append(got, filepath.ToSlash(rel))
			}
			slices.Sort(got)
			slices.Sort(test.want)
			if !slices.Equal(got, test.want) {
				t.Fatalf("GetDscPathsInMount(all=%t) = %v, want %v", test.all, got, test.want)
			}
		})
	}
}

func TestDscArchRegexMatchesAOTCacheFamily(t *testing.T) {
	re := dscArchRegex([]string{"aot"}, false, false)
	tests := []struct {
		path string
		want bool
	}{
		{path: "System/Library/dyld/aot_shared_cache.0", want: true},
		{path: "System/Library/dyld/aot_shared_cache.6", want: true},
		{path: "System/Library/dyld/dyld_shared_cache_x86_64", want: true},
		{path: "System/Library/dyld/dyld_shared_cache_x86_64.01", want: true},
		{path: "System/Library/dyld/dyld_shared_cache_x86_64.atlas", want: true},
		{path: "System/Library/dyld/dyld_shared_cache_x86_64.map", want: true},
		{path: "System/Library/dyld/dyld_shared_cache_arm64e", want: false},
		{path: "System/Library/dyld/aot_shared_cache", want: false},
		{path: "System/Library/dyld/aot_shared_cache.foo", want: false},
		{path: "System/Library/dyld/aot_shared_cache.0.map", want: false},
		{path: "System/Library/Caches/com.apple.dyld/aot_shared_cache.0", want: false},
		{path: "usr/lib/aot_shared_cache.0", want: false},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := re.MatchString(test.path); got != test.want {
				t.Fatalf("dscArchRegex(aot).MatchString(%q) = %t, want %t", test.path, got, test.want)
			}
		})
	}
}

func TestExtractFromMountedDscDMGsCombinesSystemAndRosettaPicker(t *testing.T) {
	systemRoot := t.TempDir()
	rosettaRoot := t.TempDir()
	arm64e := writeDscFixture(t, systemRoot, "System/Library/dyld/dyld_shared_cache_arm64e", "arm64e")
	aot := writeDscFixture(t, rosettaRoot, "System/Library/dyld/aot_shared_cache.0", "aot")
	x86 := writeDscFixture(t, rosettaRoot, "System/Library/dyld/dyld_shared_cache_x86_64", "x86")

	dmgs := []mountedDscDMG{
		testMountedDscDMG(SystemOSDscDMG, systemRoot, nil),
		testMountedDscDMG(RosettaOSDscDMG, rosettaRoot, nil),
	}
	var pickerCalls int
	var pickerOptions []string
	selectAOT := func(candidates []dscCandidate) ([]dscCandidate, error) {
		pickerCalls++
		for _, candidate := range candidates {
			pickerOptions = append(pickerOptions, candidate.path)
		}
		return slices.DeleteFunc(candidates, func(candidate dscCandidate) bool {
			return candidate.path != aot
		}), nil
	}

	dest := t.TempDir()
	artifacts, err := extractFromMountedDscDMGs(testMacOSDscInfo(), dmgs, dest, nil, false, false, selectAOT)
	if err != nil {
		t.Fatalf("extractFromMountedDscDMGs() failed: %v", err)
	}
	if pickerCalls != 1 {
		t.Fatalf("combined picker called %d times, want 1", pickerCalls)
	}
	wantOptions := []string{arm64e, aot, x86}
	slices.Sort(pickerOptions)
	slices.Sort(wantOptions)
	if !slices.Equal(pickerOptions, wantOptions) {
		t.Fatalf("combined picker options = %v, want %v", pickerOptions, wantOptions)
	}
	if len(artifacts) != 1 || filepath.Base(artifacts[0]) != "aot_shared_cache.0" {
		t.Fatalf("artifacts = %v, want selected AOT cache", artifacts)
	}
	data, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatalf("failed to read extracted AOT cache: %v", err)
	}
	if string(data) != "aot" {
		t.Fatalf("extracted AOT cache contents = %q, want %q", data, "aot")
	}
}

func TestExtractFromMountedDscDMGsExplicitArchesSkipPicker(t *testing.T) {
	systemRoot := t.TempDir()
	rosettaRoot := t.TempDir()
	writeDscFixture(t, systemRoot, "System/Library/dyld/dyld_shared_cache_arm64e", "arm64e")
	writeDscFixture(t, systemRoot, "System/Library/dyld/dyld_shared_cache_x86_64", "wrong-volume")
	writeDscFixture(t, rosettaRoot, "System/Library/dyld/aot_shared_cache.0", "aot")
	writeDscFixture(t, rosettaRoot, "System/Library/dyld/dyld_shared_cache_x86_64", "x86")
	writeDscFixture(t, rosettaRoot, "System/Library/dyld/dyld_shared_cache_arm64e", "wrong-volume")

	dmgs := []mountedDscDMG{
		testMountedDscDMG(SystemOSDscDMG, systemRoot, []string{"arm64e"}),
		testMountedDscDMG(RosettaOSDscDMG, rosettaRoot, []string{"aot"}),
	}
	unexpectedPicker := func([]dscCandidate) ([]dscCandidate, error) {
		t.Fatal("explicit architecture extraction must not prompt")
		return nil, nil
	}

	artifacts, err := extractFromMountedDscDMGs(
		testMacOSDscInfo(),
		dmgs,
		t.TempDir(),
		[]string{"arm64e", "aot"},
		false,
		false,
		unexpectedPicker,
	)
	if err != nil {
		t.Fatalf("extractFromMountedDscDMGs() failed: %v", err)
	}
	got := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		got = append(got, filepath.Base(artifact))
	}
	slices.Sort(got)
	want := []string{"aot_shared_cache.0", "dyld_shared_cache_arm64e", "dyld_shared_cache_x86_64"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("explicit architecture artifacts = %v, want %v", got, want)
	}
}

func writeDscFixture(t *testing.T, root, path, contents string) string {
	t.Helper()
	path = filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("failed to create DSC fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to create DSC fixture: %v", err)
	}
	return path
}

func testMountedDscDMG(kind DscDMGKind, root string, arches []string) mountedDscDMG {
	return mountedDscDMG{
		DscExtractionDMG: DscExtractionDMG{Kind: kind, Arches: arches},
		mountPoint:       root,
		mountedRoot:      root,
		alreadyMounted:   true,
	}
}

func testMacOSDscInfo() *info.Info {
	return &info.Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				SupportedProductTypes: []string{"Mac17,1"},
			},
		},
	}
}

func TestRemoteCryptexFilesArchFiltering(t *testing.T) {
	files := []*zip.File{
		{FileHeader: zip.FileHeader{Name: "cryptex-system-arm64"}},
		{FileHeader: zip.FileHeader{Name: "cryptex-system-arm64e"}},
		{FileHeader: zip.FileHeader{Name: "cryptex-system-x86_64"}},
		{FileHeader: zip.FileHeader{Name: "cryptex-system-x86_64h"}},
		{FileHeader: zip.FileHeader{Name: "cryptex-system-arm64_32"}},
	}

	tests := []struct {
		name   string
		arches []string
		want   []string
	}{
		{
			name:   "empty matches supported cryptex families",
			arches: nil,
			want: []string{
				"cryptex-system-arm64",
				"cryptex-system-arm64e",
				"cryptex-system-x86_64",
				"cryptex-system-x86_64h",
			},
		},
		{
			name:   "arm64 stays exact",
			arches: []string{"arm64"},
			want:   []string{"cryptex-system-arm64"},
		},
		{
			name:   "x86_64 stays exact",
			arches: []string{"x86_64"},
			want:   []string{"cryptex-system-x86_64"},
		},
		{
			name:   "aot uses x86 cryptex family",
			arches: []string{"aot"},
			want:   []string{"cryptex-system-x86_64", "cryptex-system-x86_64h"},
		},
		{
			name:   "unknown arches do not fall back to x86",
			arches: []string{"arm64_32"},
			want:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := RemoteCryptexFiles(files, test.arches)
			if got := zipFileNames(matches); !slices.Equal(got, test.want) {
				t.Fatalf("RemoteCryptexFiles(..., %v) = %v, want %v", test.arches, got, test.want)
			}
		})
	}
}

func TestDscExtractionPlanRoutesRosettaArches(t *testing.T) {
	tests := []struct {
		name            string
		arches          []string
		hasRosettaOS    bool
		requiresRosetta bool
		driverKit       bool
		want            []DscExtractionStep
		wantErr         bool
	}{
		{
			name:            "legacy x86 stays in system os when rosetta os is absent",
			arches:          []string{"x86_64"},
			hasRosettaOS:    false,
			requiresRosetta: false,
			want:            []DscExtractionStep{{Kind: SystemOSDscDMG, Arches: []string{"x86_64"}}},
		},
		{
			name:            "empty arches cover both system and rosetta os",
			arches:          nil,
			hasRosettaOS:    true,
			requiresRosetta: true,
			want: []DscExtractionStep{
				{Kind: SystemOSDscDMG},
				{Kind: RosettaOSDscDMG},
			},
		},
		{
			name:            "driverkit empty arches allow either dmg to be empty",
			arches:          nil,
			hasRosettaOS:    true,
			requiresRosetta: true,
			driverKit:       true,
			want: []DscExtractionStep{
				{Kind: SystemOSDscDMG, AllowEmpty: true},
				{Kind: RosettaOSDscDMG, AllowEmpty: true},
			},
		},
		{
			name:            "empty arches fall back to system os when rosetta os is absent",
			arches:          nil,
			hasRosettaOS:    false,
			requiresRosetta: true,
			want:            []DscExtractionStep{{Kind: SystemOSDscDMG}},
		},
		{
			name:            "rosetta os before it is required keeps legacy system os extraction",
			arches:          []string{"x86_64"},
			hasRosettaOS:    true,
			requiresRosetta: false,
			want:            []DscExtractionStep{{Kind: SystemOSDscDMG, Arches: []string{"x86_64"}}},
		},
		{
			name:            "x86_64 uses rosetta os when available",
			arches:          []string{"x86_64"},
			hasRosettaOS:    true,
			requiresRosetta: true,
			want:            []DscExtractionStep{{Kind: RosettaOSDscDMG, Arches: []string{"x86_64"}}},
		},
		{
			name:            "mixed arches split system and rosetta os",
			arches:          []string{"arm64e", "x86_64"},
			hasRosettaOS:    true,
			requiresRosetta: true,
			want: []DscExtractionStep{
				{Kind: SystemOSDscDMG, Arches: []string{"arm64e"}},
				{Kind: RosettaOSDscDMG, Arches: []string{"x86_64"}},
			},
		},
		{
			name:            "aot follows the rosetta os x86 cache family",
			arches:          []string{"aot"},
			hasRosettaOS:    true,
			requiresRosetta: true,
			want:            []DscExtractionStep{{Kind: RosettaOSDscDMG, Arches: []string{"aot"}}},
		},
		{
			name:            "required rosetta os fails instead of falling back to system os",
			arches:          []string{"x86_64"},
			hasRosettaOS:    false,
			requiresRosetta: true,
			wantErr:         true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dscExtractionPlan(test.arches, test.hasRosettaOS, test.requiresRosetta, test.driverKit)
			if test.wantErr {
				if err == nil {
					t.Fatalf("dscExtractionPlan(%v, %v, %v, %v) error = nil, want error", test.arches, test.hasRosettaOS, test.requiresRosetta, test.driverKit)
				}
				return
			}
			if err != nil {
				t.Fatalf("dscExtractionPlan(%v, %v, %v, %v) error = %v", test.arches, test.hasRosettaOS, test.requiresRosetta, test.driverKit, err)
			}
			if !equalDscExtractionSteps(got, test.want) {
				t.Fatalf("dscExtractionPlan(%v, %v, %v, %v) = %#v, want %#v", test.arches, test.hasRosettaOS, test.requiresRosetta, test.driverKit, got, test.want)
			}
		})
	}
}

func TestIsDscNotFoundRecognizesWrappedMisses(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "missing dsc",
			err:  fmt.Errorf("%w in DMG: rosetta.dmg", ErrNoDscFound),
			want: true,
		},
		{
			name: "missing arch",
			err:  fmt.Errorf("%w: [x86_64]", ErrNoDscForArch),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("mount failed"),
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsDscNotFound(test.err); got != test.want {
				t.Fatalf("IsDscNotFound(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func zipFileNames(files []*zip.File) []string {
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	return names
}

func equalDscExtractionSteps(a, b []DscExtractionStep) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx].Kind != b[idx].Kind || a[idx].AllowEmpty != b[idx].AllowEmpty || !slices.Equal(a[idx].Arches, b[idx].Arches) {
			return false
		}
	}
	return true
}
