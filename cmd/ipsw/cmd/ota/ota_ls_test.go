package ota

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestOTALsPayloadJSONStream(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "aa"), []byte("#!/bin/sh\necho diagnostic >&2\n/bin/cat\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for key, value := range map[string]any{"ota.ls.payload": true, "ota.ls.json": true, "ota.ls.pattern": ""} {
		previous := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
	for _, tc := range []struct {
		name    string
		members map[string][]byte
		count   int
	}{
		{"no payloads", map[string][]byte{"Info.plist": []byte("synthetic")}, 0},
		{"empty result", map[string][]byte{"AssetData/payloadv2/payload.000": []byte("[]")}, 0},
		{"one payload", map[string][]byte{"AssetData/payloadv2/payload.000": []byte(`[{"path":"one"}]`)}, 1},
		{"multiple payloads", map[string][]byte{"AssetData/payloadv2/payload.000": []byte(`[{"path":"one"}]`), "AssetData/payloadv2/payload.001": []byte(`[{"path":"two"}]`)}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := zipPayloadFixture(t, tc.members)
			out, err := captureOTAOutput(t, func() error { return otaLsCmd.RunE(otaLsCmd, []string{archive}) })
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(strings.NewReader(out))
			count := 0
			for {
				var records []map[string]string
				err := decoder.Decode(&records)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("invalid JSON output %q: %v", out, err)
				}
				count++
			}
			if count != tc.count {
				t.Fatalf("JSON values = %d, want %d", count, tc.count)
			}
		})
	}
}
