package dyld

import (
	"archive/zip"
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
		want            []dscExtractionStep
		wantErr         bool
	}{
		{
			name:            "legacy x86 stays in system os when rosetta os is absent",
			arches:          []string{"x86_64"},
			hasRosettaOS:    false,
			requiresRosetta: false,
			want:            []dscExtractionStep{{kind: systemOSDscDMG, arches: []string{"x86_64"}}},
		},
		{
			name:            "empty arches preserve existing system os behavior",
			arches:          nil,
			hasRosettaOS:    true,
			requiresRosetta: true,
			want:            []dscExtractionStep{{kind: systemOSDscDMG, arches: nil}},
		},
		{
			name:            "rosetta os before it is required keeps legacy system os extraction",
			arches:          []string{"x86_64"},
			hasRosettaOS:    true,
			requiresRosetta: false,
			want:            []dscExtractionStep{{kind: systemOSDscDMG, arches: []string{"x86_64"}}},
		},
		{
			name:            "x86_64 uses rosetta os when available",
			arches:          []string{"x86_64"},
			hasRosettaOS:    true,
			requiresRosetta: true,
			want:            []dscExtractionStep{{kind: rosettaOSDscDMG, arches: []string{"x86_64"}}},
		},
		{
			name:            "mixed arches split system and rosetta os",
			arches:          []string{"arm64e", "x86_64"},
			hasRosettaOS:    true,
			requiresRosetta: true,
			want: []dscExtractionStep{
				{kind: systemOSDscDMG, arches: []string{"arm64e"}},
				{kind: rosettaOSDscDMG, arches: []string{"x86_64"}},
			},
		},
		{
			name:            "aot follows the rosetta os x86 cache family",
			arches:          []string{"aot"},
			hasRosettaOS:    true,
			requiresRosetta: true,
			want:            []dscExtractionStep{{kind: rosettaOSDscDMG, arches: []string{"aot"}}},
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
			got, err := dscExtractionPlan(test.arches, test.hasRosettaOS, test.requiresRosetta)
			if test.wantErr {
				if err == nil {
					t.Fatalf("dscExtractionPlan(%v, %v, %v) error = nil, want error", test.arches, test.hasRosettaOS, test.requiresRosetta)
				}
				return
			}
			if err != nil {
				t.Fatalf("dscExtractionPlan(%v, %v, %v) error = %v", test.arches, test.hasRosettaOS, test.requiresRosetta, err)
			}
			if !equalDscExtractionSteps(got, test.want) {
				t.Fatalf("dscExtractionPlan(%v, %v, %v) = %#v, want %#v", test.arches, test.hasRosettaOS, test.requiresRosetta, got, test.want)
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

func equalDscExtractionSteps(a, b []dscExtractionStep) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx].kind != b[idx].kind || !slices.Equal(a[idx].arches, b[idx].arches) {
			return false
		}
	}
	return true
}
