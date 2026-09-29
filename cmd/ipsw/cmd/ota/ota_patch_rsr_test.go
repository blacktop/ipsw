//go:build darwin && cgo

package ota

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	otapkg "github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/lzraven"
)

// TestRsrSystemCryptexREDefaultCoversArm64_32 pins the unfiltered RSR selector.
// `arm64e?` cannot match arm64_32, so an unfiltered patch would skip a watchOS
// system cryptex it was asked to handle.
func TestRsrSystemCryptexREDefaultCoversArm64_32(t *testing.T) {
	re := rsrSystemCryptexRE(nil)
	for _, name := range []string{
		"cryptex-system-arm64",
		"cryptex-system-arm64e",
		"cryptex-system-arm64_32",
		"cryptex-system-x86_64",
		"cryptex-system-x86_64h",
	} {
		if !re.MatchString(name) {
			t.Errorf("rsrSystemCryptexRE(nil) does not match %q", name)
		}
	}
	if re.MatchString("cryptex-app") {
		t.Error("rsrSystemCryptexRE(nil) unexpectedly matches cryptex-app")
	}
	if !rsrSystemCryptexRE([]string{"arm64_32"}).MatchString("cryptex-system-arm64_32") {
		t.Error("rsrSystemCryptexRE([arm64_32]) does not match its own arch")
	}
}

func TestRsrCryptexTypeNumberedArm64e(t *testing.T) {
	for _, variant := range []string{"arm64e_x1", "arm64e_x2", "arm64e_x12"} {
		for _, arches := range [][]string{nil, {variant}} {
			name := "AssetData/payloadv2/image_patches/" + otapkg.SystemCryptexBasename(variant)
			typ, arch := rsrCryptexType(name, rsrSystemCryptexRE(arches))
			if typ != "system" || arch != variant {
				t.Errorf("arches %v: type = %q, arch = %q", arches, typ, arch)
			}
		}
		base := otapkg.SystemCryptexBasename(variant)
		if typ, _ := rsrCryptexType(base, rsrSystemCryptexRE([]string{"arm64e"})); typ != "" {
			t.Error("arm64e selector also selected " + variant)
		}
	}
}

func rsrTestOTA(t *testing.T, members map[string]string) *otapkg.AA {
	t.Helper()
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	for name, content := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := otapkg.NewOTA(bytes.NewReader(data.Bytes()), int64(data.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// TestRsrDeltaBase pins how `ota patch rsr --dyld-arch arm64e_x1` finds the
// image the .x1 delta applies to when its base was not selected.
func TestRsrDeltaBase(t *testing.T) {
	const dir = "AssetData/payloadv2/image_patches/"
	delta := dir + "cryptex-system-arm64e.x1"

	t.Run("reuses base patched this run", func(t *testing.T) {
		o := rsrTestOTA(t, map[string]string{delta: "delta"})
		patched := map[string]string{"cryptex-system-arm64e": "/out/SystemOS/arm64e/x.dmg"}
		base, cleanup, err := rsrDeltaBase(o, delta, "", patched, 0)
		if err != nil || base != "/out/SystemOS/arm64e/x.dmg" {
			t.Fatalf("rsrDeltaBase() = %q, %v", base, err)
		}
		cleanup()
	})

	t.Run("missing base member", func(t *testing.T) {
		o := rsrTestOTA(t, map[string]string{delta: "delta"})
		_, _, err := rsrDeltaBase(o, delta, "", map[string]string{}, 0)
		if err == nil || !strings.Contains(err.Error(), "which the OTA does not contain") {
			t.Fatalf("rsrDeltaBase() error = %v", err)
		}
	})

	lzravenBase := "RIDIFF10" + strings.Repeat("\x00", 0x36) + "pbzm"
	failingAA := func(t *testing.T) {
		t.Helper()
		bin := t.TempDir()
		if err := os.WriteFile(filepath.Join(bin, "aa"), []byte("#!/bin/sh\ncat >/dev/null\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin)
	}

	t.Run("input folder patches base from its own input", func(t *testing.T) {
		failingAA(t)
		in := t.TempDir()
		if err := os.MkdirAll(filepath.Join(in, "SystemOS", "arm64e"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(in, "SystemOS", "arm64e", "base.dmg"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		o := rsrTestOTA(t, map[string]string{delta: "delta", dir + "cryptex-system-arm64e": lzravenBase})
		// No SystemOS/arm64e_x1 input exists: the delta must not look for one.
		_, _, err := rsrDeltaBase(o, delta, in, map[string]string{}, 0)
		if !errors.Is(err, lzraven.ErrUnsupported) || !strings.Contains(err.Error(), "failed to patch base") {
			t.Fatalf("rsrDeltaBase() error = %v", err)
		}
	})

	t.Run("input folder without base input", func(t *testing.T) {
		o := rsrTestOTA(t, map[string]string{delta: "delta", dir + "cryptex-system-arm64e": lzravenBase})
		_, _, err := rsrDeltaBase(o, delta, t.TempDir(), map[string]string{}, 0)
		if err == nil || !strings.Contains(err.Error(), "failed to find input for base cryptex-system-arm64e") {
			t.Fatalf("rsrDeltaBase() error = %v", err)
		}
	})

	t.Run("patches unselected base", func(t *testing.T) {
		// An LZRaven base on a host whose aa rejects it fails before reaching
		// libParallelCompression, which proves the base member was staged.
		failingAA(t)
		o := rsrTestOTA(t, map[string]string{delta: "delta", dir + "cryptex-system-arm64e": lzravenBase})
		_, _, err := rsrDeltaBase(o, delta, "", map[string]string{}, 0)
		if !errors.Is(err, lzraven.ErrUnsupported) || !strings.Contains(err.Error(), "failed to patch base") {
			t.Fatalf("rsrDeltaBase() error = %v", err)
		}
	})
}
