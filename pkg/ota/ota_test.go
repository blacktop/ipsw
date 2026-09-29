package ota

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota/lzraven"
)

// TestRemoteExtractReportsUnsupportedLZRaven pins that a host which cannot
// decode LZRaven gets the compatibility error from the first payload, not a
// generic "not found" after probing every payload.
func TestRemoteExtractReportsUnsupportedLZRaven(t *testing.T) {
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	script := "#!/bin/sh\necho x >> " + calls + "\ncat >/dev/null\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "aa"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	for _, name := range []string{"AssetData/payloadv2/payload.000", "AssetData/payloadv2/payload.001"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(lzraven.Magic + "synthetic")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data.Bytes()), int64(data.Len()))
	if err != nil {
		t.Fatal(err)
	}

	_, err = RemoteExtract(zr, "dyld_shared_cache", t.TempDir(), func(string) bool { return false })
	if !errors.Is(err, lzraven.ErrUnsupported) {
		t.Fatalf("RemoteExtract() error = %v, want ErrUnsupported", err)
	}
	probes, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(probes, []byte("x")); n != 1 {
		t.Fatalf("aa ran %d times, want 1 (stop at the first payload)", n)
	}
}
