package lzraven

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeAA puts an aa script that exits with status on PATH.
func fakeAA(t *testing.T, status string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake aa requires a POSIX shell")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat >/dev/null\necho 'invalid/non-supported archive stream' >&2\nexit " + status + "\n"
	if err := os.WriteFile(filepath.Join(dir, "aa"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func writeRIDIFF(t *testing.T, codec string) string {
	t.Helper()
	header := make([]byte, 0x46)
	copy(header, "RIDIFF10")
	patch := append(header, codec...)
	patch = append(patch, make([]byte, 64)...)
	path := filepath.Join(t.TempDir(), "cryptex-system-arm64e")
	if err := os.WriteFile(path, patch, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckHostWithoutAA(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := CheckHost(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CheckHost() = %v, want ErrUnsupported", err)
	}
}

func TestCheckHostWithOldAA(t *testing.T) {
	fakeAA(t, "1")
	if err := CheckHost(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CheckHost() = %v, want ErrUnsupported", err)
	}
}

func TestCheckHostWithCapableAA(t *testing.T) {
	fakeAA(t, "0")
	if err := CheckHost(); err != nil {
		t.Fatalf("CheckHost() = %v, want nil", err)
	}
}

func TestCheckStreamIgnoresOtherCodecs(t *testing.T) {
	fakeAA(t, "1")
	for _, header := range [][]byte{[]byte("pbzx"), []byte("AA01"), []byte("pb"), nil} {
		if err := CheckStream(header); err != nil {
			t.Fatalf("CheckStream(%q) = %v, want nil", header, err)
		}
	}
	if err := CheckStream([]byte(Magic)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CheckStream(pbzm) = %v, want ErrUnsupported", err)
	}
}

func TestCheckRIDIFF(t *testing.T) {
	fakeAA(t, "1")
	if err := CheckRIDIFF(writeRIDIFF(t, "pbzx")); err != nil {
		t.Fatalf("CheckRIDIFF(pbzx) = %v, want nil", err)
	}
	if err := CheckRIDIFF(writeRIDIFF(t, Magic)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CheckRIDIFF(pbzm) = %v, want ErrUnsupported", err)
	}
	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, []byte("RIDIFF10"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckRIDIFF(short); err != nil {
		t.Fatalf("CheckRIDIFF(short) = %v, want nil", err)
	}
	if err := CheckRIDIFF(filepath.Join(t.TempDir(), "missing")); err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatalf("CheckRIDIFF(missing) = %v, want an open error", err)
	}
}

// TestProbeDecodesOnCapableHost guards the embedded sample: a host aa that can
// write LZRaven must accept it, or CheckHost would reject capable hosts.
func TestProbeDecodesOnCapableHost(t *testing.T) {
	aaPath, err := exec.LookPath("aa")
	if err != nil {
		t.Skip("aa is only available on macOS")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "probe.aar")
	cmd := exec.Command(aaPath, "archive", "-d", dir, "-o", archive, "-a", "lzraven")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("host aa cannot write LZRaven: %v: %s", err, out)
	}
	if err := CheckHost(); err != nil {
		t.Fatalf("CheckHost() = %v on a host whose aa writes LZRaven", err)
	}
}
