package plist

import (
	"bytes"
	"fmt"
	"io/fs"
	"testing"
	"time"
)

type testPlistFile struct {
	*bytes.Reader
	name string
}

func newTestPlistFile(name string, data []byte) fs.File {
	return &testPlistFile{
		Reader: bytes.NewReader(data),
		name:   name,
	}
}

func (f *testPlistFile) Close() error               { return nil }
func (f *testPlistFile) Stat() (fs.FileInfo, error) { return f, nil }
func (f *testPlistFile) Name() string               { return f.name }
func (f *testPlistFile) Size() int64                { return f.Reader.Size() }
func (f *testPlistFile) Mode() fs.FileMode          { return 0 }
func (f *testPlistFile) ModTime() time.Time         { return time.Time{} }
func (f *testPlistFile) IsDir() bool                { return false }
func (f *testPlistFile) Sys() any                   { return nil }

func syntheticBuildManifest(build string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BuildIdentities</key>
	<array/>
	<key>ProductBuildVersion</key>
	<string>%s</string>
	<key>ProductVersion</key>
	<string>1.0</string>
	<key>SupportedProductTypes</key>
	<array>
		<string>iSim1,1</string>
	</array>
</dict>
</plist>`, build))
}

func TestParsePlistFilesUsesRestoreBuildManifestFallback(t *testing.T) {
	got, err := ParsePlistFiles([]fs.File{
		newTestPlistFile("AssetData/Restore/BuildManifest.plist", syntheticBuildManifest("RESTORE_BUILD")),
	})
	if err != nil {
		t.Fatalf("ParsePlistFiles() unexpected error: %v", err)
	}
	if got.BuildManifest == nil {
		t.Fatal("ParsePlistFiles() did not retain the restore BuildManifest fallback")
	}
	if got.BuildManifest.ProductBuildVersion != "RESTORE_BUILD" {
		t.Fatalf("ParsePlistFiles() build = %q, want %q", got.BuildManifest.ProductBuildVersion, "RESTORE_BUILD")
	}
}

func TestParsePlistFilesPrefersPrimaryBuildManifest(t *testing.T) {
	for _, restoreFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("restore_first=%t", restoreFirst), func(t *testing.T) {
			primary := newTestPlistFile("BuildManifest.plist", syntheticBuildManifest("PRIMARY_BUILD"))
			restore := newTestPlistFile("AssetData/Restore/BuildManifest.plist", syntheticBuildManifest("RESTORE_BUILD"))
			files := []fs.File{primary, restore}
			if restoreFirst {
				files[0], files[1] = files[1], files[0]
			}

			got, err := ParsePlistFiles(files)
			if err != nil {
				t.Fatalf("ParsePlistFiles() unexpected error: %v", err)
			}
			if got.BuildManifest == nil {
				t.Fatal("ParsePlistFiles() returned no BuildManifest")
			}
			if got.BuildManifest.ProductBuildVersion != "PRIMARY_BUILD" {
				t.Fatalf("ParsePlistFiles() build = %q, want %q", got.BuildManifest.ProductBuildVersion, "PRIMARY_BUILD")
			}
		})
	}
}

func TestParsePlistFilesDoesNotParseRestoreManifestWhenPrimaryExists(t *testing.T) {
	got, err := ParsePlistFiles([]fs.File{
		newTestPlistFile("AssetData/Restore/BuildManifest.plist", []byte("not a plist")),
		newTestPlistFile("BuildManifest.plist", syntheticBuildManifest("PRIMARY_BUILD")),
	})
	if err != nil {
		t.Fatalf("ParsePlistFiles() unexpected error: %v", err)
	}
	if got.BuildManifest == nil {
		t.Fatal("ParsePlistFiles() returned no BuildManifest")
	}
	if got.BuildManifest.ProductBuildVersion != "PRIMARY_BUILD" {
		t.Fatalf("ParsePlistFiles() build = %q, want %q", got.BuildManifest.ProductBuildVersion, "PRIMARY_BUILD")
	}
}
