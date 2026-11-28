package ota

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

// payloadFixture builds a minimal YAA entry named file.txt for listing tests.
func payloadFixture() []byte {
	header := append([]byte("TYP1FPATP"), 8, 0)
	header = append(header, []byte("file.txtMOD1")...)
	header = append(header, 0o100)
	var out bytes.Buffer
	out.WriteString("YAA1")
	binary.Write(&out, binary.LittleEndian, uint16(6+len(header)))
	out.Write(header)
	return out.Bytes()
}

// zipPayloadFixture places named payloads in a temporary OTA-like ZIP.
func zipPayloadFixture(t *testing.T, members map[string][]byte) string {
	t.Helper()
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	for name, contents := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "synthetic.zip")
	if err := os.WriteFile(name, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// captureOTAOutput captures a command's stdout while preserving its error
// and restoring stdout before returning.
func captureOTAOutput(t *testing.T, run func() error) (string, error) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = out
	defer func() { os.Stdout = old; out.Close() }()
	runErr := run()
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data), runErr
}

// TestOTAPayloadInputs checks raw YAA, PBZX and PBZM listings from standalone
// files and ZIP members, including PBZM operation without a system aa tool.
func TestOTAPayloadInputs(t *testing.T) {
	previousContext := otaPayloadCmd.Context()
	otaPayloadCmd.SetContext(t.Context())
	t.Cleanup(func() { otaPayloadCmd.SetContext(previousContext) })
	raw := payloadFixture()
	var compressed bytes.Buffer
	compressed.WriteString("pbzx")
	for range 3 {
		binary.Write(&compressed, binary.BigEndian, uint64(len(raw)))
	}
	compressed.Write(raw)
	pbzm, err := os.ReadFile("../../../../pkg/ota/lzraven/probe.aar")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"raw", raw, "file.txt"},
		{"pbzx", compressed.Bytes(), "file.txt"},
		{"pbzm", pbzm, " a\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "pbzm" {
				t.Setenv("PATH", t.TempDir())
			}
			standalone := filepath.Join(t.TempDir(), "payload.000")
			if err := os.WriteFile(standalone, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			archive := zipPayloadFixture(t, map[string][]byte{"AssetData/payloadv2/payload.000": tc.data})
			for _, args := range [][]string{{standalone}, {archive, "AssetData/payloadv2/payload.000"}} {
				out, err := captureOTAOutput(t, func() error {
					return otaPayloadCmd.RunE(otaPayloadCmd, args)
				})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out, tc.want) {
					t.Fatalf("listing missing %q: %q", tc.want, out)
				}
			}
		})
	}
}

// TestOTAPayloadUnknownHeaderNamesMember checks that an invalid payload header
// reports the affected member and offset while preserving the parsing error.
func TestOTAPayloadUnknownHeaderNamesMember(t *testing.T) {
	_, err := parseOTAPayload(context.Background(), strings.NewReader("nope"), "AssetData/payloadv2/payload.001")
	if !errors.Is(err, yaa.ErrInvalidMagic) || !strings.Contains(err.Error(), "AssetData/payloadv2/payload.001") || !strings.Contains(err.Error(), "offset 0x0") {
		t.Fatalf("parse error = %v", err)
	}
}
