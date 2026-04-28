package kernel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenKernelCollectionPrefersMachOPath(t *testing.T) {
	// Mach-O 64-bit magic (little-endian): 0xfeedfacf.
	// The file is intentionally truncated so parse fails after detection.
	path := filepath.Join(t.TempDir(), "BootKernelExtensions.kc")
	if err := os.WriteFile(path, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := openKernelCollection(path)
	if err == nil {
		t.Fatal("expected parse error for truncated Mach-O file")
	}
	if !strings.Contains(err.Error(), "failed to parse kernelcache MachO") {
		t.Fatalf("expected Mach-O parse path error, got: %v", err)
	}
}

func TestOpenKernelCollectionUsesImg4PathByExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kernelcache.img4")
	if err := os.WriteFile(path, []byte("not a valid img4 payload"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := openKernelCollection(path)
	if err == nil {
		t.Fatal("expected decompression error for invalid img4 payload")
	}
	if !strings.Contains(err.Error(), "failed to decompress kernelcache (kernel management data)") {
		t.Fatalf("expected IMG4 decompression path error, got: %v", err)
	}
}

func TestOpenKernelCollectionRejectsUnknownFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kernelcache.bin")
	if err := os.WriteFile(path, []byte("random data"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := openKernelCollection(path)
	if err == nil {
		t.Fatal("expected format detection error")
	}
	if !strings.Contains(err.Error(), "failed to detect kernelcache IMG4 format") {
		t.Fatalf("expected IMG4 detection error for unknown format, got: %v", err)
	}
}
