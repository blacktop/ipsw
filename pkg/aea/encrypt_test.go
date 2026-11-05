package aea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func fileDigest(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return h.Sum(nil)
}

func nativeDecrypt(t *testing.T, archive, output string, key []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	data, err := exec.CommandContext(ctx, aeaBinPath, "decrypt", "-i", archive, "-o", output,
		"-key-value", "base64:"+base64.StdEncoding.EncodeToString(key)).CombinedOutput()
	if err != nil {
		t.Fatalf("native AEA decryption: %v: %s", err, data)
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	for _, tc := range []struct {
		name string
		size int64
	}{
		{"empty", 0},
		{"partial_segment", segmentSize + 17},
		{"full_cluster", int64(segmentSize) * segmentsPerCluster},
		{"two_clusters", int64(segmentSize)*segmentsPerCluster + 1},
		{"three_clusters", 2*int64(segmentSize)*segmentsPerCluster + 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "synthetic.bin")
			f, err := os.Create(in)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(tc.size); err != nil {
				t.Fatal(err)
			}
			if tc.size > 0 {
				// The first segment is incompressible; the remaining sparse data
				// covers compressed segments and distinct cluster boundaries.
				data := make([]byte, min(tc.size, segmentSize))
				if _, err := rand.New(rand.NewSource(1)).Read(data); err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteAt(data, 0); err != nil {
					t.Fatal(err)
				}
				if _, err := f.WriteAt([]byte{0xa5}, tc.size-1); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			want := fileDigest(t, in)
			if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key}); err != nil {
				t.Fatal(err)
			}
			// Keep only one large plaintext copy in the test's temporary tree.
			if err := os.Remove(in); err != nil {
				t.Fatal(err)
			}
			archive := in + ".aea"
			out := filepath.Join(dir, "decoded.bin")
			if _, err := decrypt(archive, out, key); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fileDigest(t, out), want) {
				t.Fatal("Go decoder plaintext differs")
			}
			if err := os.Remove(out); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS == "darwin" {
				nativeDecrypt(t, archive, out, key)
				if !bytes.Equal(fileDigest(t, out), want) {
					t.Fatal("native decoder plaintext differs")
				}
			}
		})
	}
}

func TestEncryptFailurePreservesOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "synthetic.bin")
	if err := os.WriteFile(in, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := in + ".aea"
	if err := os.WriteFile(archive, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, make([]byte, 16), make([]byte, 24)} {
		if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key}); err == nil {
			t.Fatalf("accepted a %d-byte key", len(key))
		}
	}
	got, err := os.ReadFile(archive)
	if err != nil || string(got) != "existing" {
		t.Fatalf("existing archive was changed: %q, %v", got, err)
	}
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: make([]byte, 32)}); err == nil {
		t.Fatal("published over a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("temporary output leaked: %v", entries)
	}
}

func TestEncryptPreservesOutputPermissions(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "synthetic.bin")
	if err := os.WriteFile(in, []byte("payload"), 0o666); err != nil {
		t.Fatal(err)
	}
	mode := func(name string) os.FileMode {
		t.Helper()
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm()
	}
	archive := in + ".aea"
	conf := &EncryptConfig{Output: dir, SymmetricKey: make([]byte, 32)}
	want := mode(in)
	if err := Encrypt(in, conf); err != nil {
		t.Fatal(err)
	}
	if got := mode(archive); got != want {
		t.Fatalf("new archive mode = %04o; want %04o", got, want)
	}
	if err := os.Chmod(archive, 0o640); err != nil {
		t.Fatal(err)
	}
	want = mode(archive)
	if err := Encrypt(in, conf); err != nil {
		t.Fatal(err)
	}
	if got := mode(archive); got != want {
		t.Fatalf("replacement archive mode = %04o; want %04o", got, want)
	}
}
