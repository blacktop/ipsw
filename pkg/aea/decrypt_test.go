package aea

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDecryptAuthData(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	payload := []byte("synthetic payload\n")
	for _, tc := range []struct {
		name     string
		auth     []byte
		implicit bool
	}{
		{"raw", []byte{1}, false},
		{"large_raw", bytes.Repeat([]byte{0xa5}, 16<<20+1), false},
		{"explicit_key_wins", metadataEntry("encryption_key", strings.Repeat("00", 32)), false},
		{"embedded_key", metadataEntry("encryption_key", hex.EncodeToString(key)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "synthetic.bin")
			if err := os.WriteFile(in, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key, AuthData: tc.auth}); err != nil {
				t.Fatal(err)
			}
			archive := in + ".aea"
			out := filepath.Join(dir, "decoded.bin")
			if _, err := decrypt(archive, out, key); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("Go decoder plaintext differs: %v", err)
			}
			conf := &DecryptConfig{Input: archive, Output: dir}
			if !tc.implicit {
				conf.B64SymKey = base64.StdEncoding.EncodeToString(key)
			}
			decoded, err := Decrypt(conf)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(decoded); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("public decoder plaintext differs: %v", err)
			}
		})
	}
}

func TestDecryptRejectsModifiedAuthData(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x5a}, 32)
	in := filepath.Join(dir, "synthetic.bin")
	if err := os.WriteFile(in, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(in, &EncryptConfig{Output: dir, SymmetricKey: key, AuthData: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	archive := in + ".aea"
	f, err := os.OpenFile(archive, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{2}, int64(binary.Size(Header{}))); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "decoded.bin")
	if _, err := decrypt(archive, out, key); err == nil || !strings.Contains(err.Error(), "root header HMAC") {
		t.Fatalf("modified auth data was not rejected: %v", err)
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := exec.CommandContext(ctx, aeaBinPath, "decrypt", "-i", archive, "-o", out,
			"-key-value", "base64:"+base64.StdEncoding.EncodeToString(key)).Run(); err == nil {
			t.Fatal("native decoder accepted modified auth data")
		}
	}
}

func TestDecryptTruncatedPrologue(t *testing.T) {
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, Header{
		Magic: [4]byte{'A', 'E', 'A', '1'}, ProfileAndScryptStrength: uint32(SymmetricEncryption), AuthDataLength: math.MaxUint32,
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "synthetic.aea")
	if err := os.WriteFile(in, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decrypt(in, filepath.Join(dir, "decoded.bin"), make([]byte, 32)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("unexpected error: %v", err)
	}
}
