package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/viper"
)

func TestExtractJSONComponents(t *testing.T) {
	keybag, err := asn1.Marshal([]img4.Keybag{{Type: img4.PRODUCTION, IV: bytes.Repeat([]byte{0x11}, 16), Key: bytes.Repeat([]byte{0x22}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := asn1.Marshal(img4.IM4P{Tag: "IM4P", Type: "test", Version: "synthetic", Data: []byte("synthetic data"), Keybag: keybag})
	if err != nil {
		t.Fatal(err)
	}
	buildIPSW := func(t *testing.T, extra map[string]string) string {
		t.Helper()
		members := map[string]string{
			"BuildManifest.plist":           `<plist version="1.0"><dict><key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string><key>SupportedProductTypes</key><array><string>iPhone99,1</string></array></dict></plist>`,
			"Restore.plist":                 `<plist version="1.0"><dict><key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string><key>SupportedProductTypes</key><array><string>iPhone99,1</string></array></dict></plist>`,
			"Firmware/DeviceTree.test.im4p": string(payload),
			"Firmware/iBoot.test.im4p":      string(payload),
			"README.txt":                    "synthetic text",
		}
		maps.Copy(members, extra)
		var archive bytes.Buffer
		zw := zip.NewWriter(&archive)
		for name, data := range members {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(w, data); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(t.TempDir(), "synthetic.ipsw")
		if err := os.WriteFile(input, archive.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return input
	}
	input := buildIPSW(t, nil)
	// A valid SPTM payload followed by a corrupt TXM payload: the SPTM file is
	// written before the TXM parse fails and must still be reported.
	sptmPartialInput := buildIPSW(t, map[string]string{
		"Firmware/sptm.test.im4p": string(payload),
		"Firmware/txm.test.im4p":  "not an im4p",
	})
	for _, mode := range []string{"legacy", "artifacts", "partial", "keybags", "sptm-partial"} {
		t.Run(mode, func(t *testing.T) {
			format := mode
			partial := mode == "partial" || mode == "sptm-partial"
			if partial || mode == "keybags" {
				format = "artifacts"
			}
			pattern := `README\.txt$`
			if mode == "keybags" || mode == "sptm-partial" {
				pattern = ""
			}
			components := mode != "sptm-partial"
			for key, value := range map[string]any{
				"kernel": false, "dyld": false, "dmg": "", "dtree": components,
				"iboot": components, "sep": mode == "partial", "sptm": mode == "sptm-partial", "kbag": mode == "keybags",
				"sys-ver": false, "exclave": false, "pattern": pattern, "fcs-key": false,
				"dyld-arch": []string{}, "files": false, "driverkit": false,
				"device": "", "remote": false, "lookup": false,
				"json": true, "json-format": format, "output": t.TempDir(),
			} {
				key := "extract." + key
				previous := viper.Get(key)
				viper.Set(key, value)
				t.Cleanup(func() { viper.Set(key, previous) })
			}
			var out bytes.Buffer
			extractCmd.SetOut(&out)
			t.Cleanup(func() { extractCmd.SetOut(nil) })
			target := input
			if mode == "sptm-partial" {
				target = sptmPartialInput
			}
			err := extractCmd.RunE(extractCmd, []string{target})
			if (err != nil) != partial {
				t.Fatalf("error = %v", err)
			}
			dec := json.NewDecoder(&out)
			if mode == "legacy" {
				for i := range 3 {
					var paths []string
					if err := dec.Decode(&paths); err != nil || len(paths) != 1 {
						t.Fatalf("component %d paths = %v, error = %v", i, paths, err)
					}
					if i == 2 && filepath.Base(paths[0]) != "README.txt" {
						t.Fatalf("pattern overwritten by previous component: %v", paths)
					}
				}
			} else {
				var report extractionReport
				if err := dec.Decode(&report); err != nil {
					t.Fatal(err)
				}
				count := 3
				switch mode {
				case "partial", "keybags":
					count = 2
				case "sptm-partial":
					count = 1
				}
				if report.SchemaVersion != 1 || report.Complete != !partial || len(report.Artifacts) != count {
					t.Fatalf("unexpected report: %+v", report)
				}
				if (report.Error != "") != partial {
					t.Fatalf("unexpected report error: %q", report.Error)
				}
				if mode == "sptm-partial" && (report.Artifacts[0].Kind != "sptm" || filepath.Base(report.Artifacts[0].Path) != "sptm.test") {
					t.Fatalf("partial SPTM artifact not retained: %+v", report.Artifacts)
				}
				if mode == "keybags" {
					var keybags struct {
						Files []json.RawMessage `json:"files"`
					}
					if err := json.Unmarshal(report.Keybags, &keybags); err != nil {
						t.Fatal(err)
					}
					if len(keybags.Files) != 2 {
						t.Fatalf("keybags restricted by prior component: %d files", len(keybags.Files))
					}
				}
				for _, artifact := range report.Artifacts {
					if _, err := os.Stat(artifact.Path); err != nil {
						t.Fatalf("reported missing artifact: %v", err)
					}
				}
			}
			var extra any
			if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
				t.Fatalf("unexpected trailing output: %v, %v", extra, err)
			}
		})
	}
}

func TestWriteExtractionReportMetadataAndKernelDevices(t *testing.T) {
	report := extractionReport{
		SchemaVersion: 1,
		Artifacts:     []extractionArtifact{{Kind: "kernel", Path: "kernel.test", Devices: []string{"iPhone99,2", "iPhone99,1"}}},
		Keybags:       json.RawMessage(`{"files":[]}`),
		SystemVersion: map[string]string{"ProductVersion": "99.0"},
	}
	var out bytes.Buffer
	if err := writeExtractionReport(&out, &report, nil); err != nil {
		t.Fatal(err)
	}
	var decoded extractionReport
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Complete || decoded.Artifacts[0].Devices[0] != "iPhone99,1" || string(decoded.Keybags) != `{"files":[]}` || decoded.SystemVersion == nil {
		t.Fatalf("metadata lost: %+v", decoded)
	}
}

func TestExtractDeviceModesReachInput(t *testing.T) {
	defaults := map[string]any{
		"kernel": false, "dyld": false, "dmg": "", "dtree": false,
		"iboot": false, "sep": false, "sptm": false, "kbag": false,
		"sys-ver": false, "exclave": false, "pattern": "", "fcs-key": false,
		"dyld-arch": []string{}, "files": false, "driverkit": false,
		"device": "Mac99,2", "remote": false, "lookup": false,
		"json-format": "legacy",
	}
	for key := range defaults {
		previous := viper.Get("extract." + key)
		t.Cleanup(func() { viper.Set("extract."+key, previous) })
	}
	for _, mode := range []struct {
		name   string
		flags  map[string]any
		reject bool
	}{
		{"kernel", map[string]any{"kernel": true}, false},
		{"dyld without arch", map[string]any{"dyld": true}, false},
		{"dyld with arch", map[string]any{"dyld": true, "dyld-arch": []string{"arm64e_x1"}}, false},
		{"files", map[string]any{"files": true, "pattern": `.*\.plist$`}, false},
		{"fcs-key", map[string]any{"fcs-key": true}, false},
		{"dmg", map[string]any{"dmg": "sys"}, false},
		{"iboot", map[string]any{"iboot": true}, true},
		{"dtree", map[string]any{"dtree": true}, true},
		{"sep", map[string]any{"sep": true}, true},
		{"sptm", map[string]any{"sptm": true}, true},
		{"kbag", map[string]any{"kbag": true}, true},
		{"sys-ver", map[string]any{"sys-ver": true}, true},
		{"exclave", map[string]any{"exclave": true}, true},
		{"zip pattern", map[string]any{"pattern": ".*"}, true},
		{"mixed kernel iboot", map[string]any{"kernel": true, "iboot": true}, true},
		{"mixed dyld zip pattern", map[string]any{"dyld": true, "dyld-arch": []string{"arm64e"}, "pattern": ".*"}, true},
		{"mixed dmg sep", map[string]any{"dmg": "sys", "sep": true}, true},
	} {
		for _, remote := range []bool{false, true} {
			name := mode.name + "/local"
			if remote {
				name = mode.name + "/remote"
			}
			t.Run(name, func(t *testing.T) {
				for key, value := range defaults {
					viper.Set("extract."+key, value)
				}
				for key, value := range mode.flags {
					viper.Set("extract."+key, value)
				}
				viper.Set("extract.remote", remote)
				input := filepath.Join(t.TempDir(), "missing.ipsw")
				// A missing local file or invalid remote URL proves RunE passed
				// flag validation without extracting or contacting a server.
				err := extractCmd.RunE(extractCmd, []string{input})
				if mode.reject {
					if err == nil || !strings.Contains(err.Error(), "--device can only be used with") {
						t.Fatalf("expected unsupported device mode error, got %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), input) {
					t.Fatalf("expected input error for %q, got %v", input, err)
				}
			})
		}
	}
}
