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

func zipFileNames(files []*zip.File) []string {
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	return names
}
