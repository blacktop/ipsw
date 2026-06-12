package dyld

import (
	"archive/zip"
	"errors"
	"fmt"
	"slices"
	"testing"
)

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
