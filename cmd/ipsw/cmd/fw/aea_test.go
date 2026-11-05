package fw

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/aea"
)

func TestAEAAuthData(t *testing.T) {
	setFlag := func(name, value string) {
		t.Helper()
		flag := aeaCmd.Flags().Lookup(name)
		old, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() {
			if err := flag.Value.Set(old); err != nil {
				t.Error(err)
			}
			flag.Changed = changed
		})
		if err := aeaCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "synthetic.bin")
	authFile := filepath.Join(dir, "auth.bin")
	payload := []byte("synthetic CLI payload")
	if err := os.WriteFile(in, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authFile, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	setFlag("auth-data", authFile)
	if err := aeaCmd.RunE(aeaCmd, []string{in}); err == nil || !strings.Contains(err.Error(), "requires --encrypt") {
		t.Fatalf("unexpected mode validation: %v", err)
	}
	setFlag("encrypt", "true")
	setFlag("info", "true")
	if err := aeaCmd.RunE(aeaCmd, []string{in}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("unexpected mode conflict: %v", err)
	}
	setFlag("info", "false")
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	setFlag("key-val", key)
	setFlag("output", dir)
	setFlag("auth-data", filepath.Join(dir, "missing"))
	if err := aeaCmd.RunE(aeaCmd, []string{in}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error was not preserved: %v", err)
	}
	setFlag("auth-data", authFile)
	if err := aeaCmd.RunE(aeaCmd, []string{in}); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(in + ".aea")
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) < 13 || binary.LittleEndian.Uint32(blob[8:12]) != 1 || blob[12] != 1 {
		t.Fatal("CLI did not preserve auth data")
	}
	decoded, err := aea.Decrypt(&aea.DecryptConfig{Input: in + ".aea", Output: dir, B64SymKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(decoded); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round trip differs: %v", err)
	}
}
