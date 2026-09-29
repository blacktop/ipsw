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

	"github.com/blacktop/ipsw/pkg/ota/lzraven"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

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

func TestOTAPayloadRawAndPBZXInputs(t *testing.T) {
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
	for _, tc := range []struct {
		name string
		data []byte
	}{{"raw", raw}, {"pbzx", compressed.Bytes()}} {
		t.Run(tc.name, func(t *testing.T) {
			standalone := filepath.Join(t.TempDir(), "payload.000")
			if err := os.WriteFile(standalone, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			archive := zipPayloadFixture(t, map[string][]byte{"AssetData/payloadv2/payload.000": tc.data})
			for _, args := range [][]string{{standalone}, {archive, "AssetData/payloadv2/payload.000"}} {
				out, err := captureOTAOutput(t, func() error { return otaPayloadCmd.RunE(otaPayloadCmd, args) })
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out, "file.txt") {
					t.Fatalf("listing missing synthetic file: %q", out)
				}
			}
		})
	}
}

func TestOTAPayloadPBZMConversion(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	input := append([]byte("pbzm"), payloadFixture()...)
	_, err := parseOTAPayload(context.Background(), bytes.NewReader(input), "payload.000")
	if !errors.Is(err, lzraven.ErrUnsupported) {
		t.Fatalf("missing converter error = %v", err)
	}
	tool := filepath.Join(bin, "aa")
	// `aa list` is the LZRaven capability probe; `aa convert` decodes.
	script := "#!/bin/sh\n[ \"$1\" = list ] && { /bin/cat >/dev/null; exit 0; }\n" +
		"[ \"$*\" = 'convert -a raw' ] || exit 42\n/bin/dd bs=1 skip=4 2>/dev/null\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	aa, err := parseOTAPayload(context.Background(), bytes.NewReader(input), "payload.000")
	if err != nil {
		t.Fatal(err)
	}
	if len(aa.Entries) != 1 || aa.Entries[0].Path != "file.txt" {
		t.Fatalf("entries = %+v", aa.Entries)
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho unsupported-codec >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = parseOTAPayload(context.Background(), bytes.NewReader(input), "payload.000")
	if err == nil || !strings.Contains(err.Error(), "payload.000") || !strings.Contains(err.Error(), "unsupported-codec") {
		t.Fatalf("conversion error = %v", err)
	}
}

func TestOTAPayloadUnknownHeaderNamesMember(t *testing.T) {
	_, err := parseOTAPayload(context.Background(), strings.NewReader("nope"), "AssetData/payloadv2/payload.001")
	if !errors.Is(err, yaa.ErrInvalidMagic) || !strings.Contains(err.Error(), "AssetData/payloadv2/payload.001") || !strings.Contains(err.Error(), "offset 0x0") {
		t.Fatalf("parse error = %v", err)
	}
}
