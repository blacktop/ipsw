package ota

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestExtractFromDscCryptexFilesIncludesRosettaAndContinuesAfterFailure(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64e"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-x86_64h"},
		{name: "AssetData/payloadv2/image_patches/cryptex-app"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta.dmg"},
		{name: "AssetData/payloadv2/image_patches/prefix-cryptex-system-rosetta"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta-extra"},
	}

	var called []string
	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		called = append(called, file.Base())
		switch file.Base() {
		case "cryptex-system-arm64e":
			return nil, errors.New("hdiutil attach: Device not configured")
		case "cryptex-system-rosetta":
			return []string{
				"System/Library/dyld/aot_shared_cache.0",
				"System/Library/dyld/dyld_shared_cache_x86_64",
			}, nil
		case "cryptex-system-x86_64h":
			return []string{"System/Library/dyld/dyld_shared_cache_x86_64h"}, nil
		default:
			t.Fatalf("unexpected cryptex extraction attempt for %q", file.Name())
			return nil, nil
		}
	})

	wantCalled := []string{
		"cryptex-system-arm64e",
		"cryptex-system-rosetta",
		"cryptex-system-x86_64h",
	}
	if !slices.Equal(called, wantCalled) {
		t.Fatalf("extract calls = %v, want %v", called, wantCalled)
	}
	wantOut := []string{
		"System/Library/dyld/aot_shared_cache.0",
		"System/Library/dyld/dyld_shared_cache_x86_64",
		"System/Library/dyld/dyld_shared_cache_x86_64h",
	}
	if !slices.Equal(out, wantOut) {
		t.Fatalf("extracted files = %v, want %v", out, wantOut)
	}
	if err == nil {
		t.Fatal("extractFromDscCryptexFiles() error = nil, want arm64e extraction error")
	}
	for _, want := range []string{"cryptex-system-arm64e", "Device not configured"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("extractFromDscCryptexFiles() error = %q, want substring %q", err, want)
		}
	}
}

func TestExtractFromDscCryptexFilesReturnsNilErrorWhenAllCryptexesSucceed(t *testing.T) {
	files := []*File{
		{name: "AssetData/payloadv2/image_patches/cryptex-system-arm64"},
		{name: "AssetData/payloadv2/image_patches/cryptex-system-rosetta"},
	}

	out, err := extractFromDscCryptexFiles(files, func(file *File) ([]string, error) {
		return []string{file.Base()}, nil
	})
	if err != nil {
		t.Fatalf("extractFromDscCryptexFiles() unexpected error: %v", err)
	}
	want := []string{"cryptex-system-arm64", "cryptex-system-rosetta"}
	if !slices.Equal(out, want) {
		t.Fatalf("extracted files = %v, want %v", out, want)
	}
}
