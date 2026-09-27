package fw

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestDCPInfoLeavesNoExtractedFiles(t *testing.T) {
	var data bytes.Buffer
	for _, header := range []any{bundle.Header{Magic: [4]byte{'D', 'N', 'U', 'B'}, Type: 4}, bundle.Type4{}} {
		if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := asn1.Marshal(img4.IM4P{Tag: "IM4P", Type: "dcpf", Version: "synthetic", Data: data.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	testFirmwareInfoFiles(t, dcpCmd, "fw.dcp", "Firmware/dcp/synthetic.im4p", payload)
}

// Exercise both success and parse failure through the actual command handlers.
func testFirmwareInfoFiles(t *testing.T, cmd *cobra.Command, key, member string, valid []byte) {
	t.Helper()
	for _, mode := range []string{"local", "remote", "direct"} {
		for _, malformed := range []bool{false, true} {
			name := mode + "/valid"
			data := valid
			if malformed {
				name = mode + "/malformed"
				data = []byte("invalid firmware")
			}
			t.Run(name, func(t *testing.T) {
				staging := t.TempDir()
				t.Setenv("TMPDIR", staging)
				out := t.TempDir()
				sentinel := filepath.Join(out, "keep.txt")
				if err := os.WriteFile(sentinel, []byte("existing output"), 0600); err != nil {
					t.Fatal(err)
				}
				for k, value := range map[string]any{"info": true, "output": out, "remote": mode == "remote"} {
					setting := key + "." + k
					old := viper.Get(setting)
					viper.Set(setting, value)
					t.Cleanup(func() { viper.Set(setting, old) })
				}
				in := filepath.Join(t.TempDir(), "synthetic.firmware")
				inputData := data
				if mode != "direct" {
					inputData = firmwareInfoArchive(t, member, data)
				}
				if err := os.WriteFile(in, inputData, 0600); err != nil {
					t.Fatal(err)
				}
				arg := in
				if mode == "remote" {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("ETag", `"synthetic-firmware"`)
						http.ServeContent(w, r, "synthetic.ipsw", time.Time{}, bytes.NewReader(inputData))
					}))
					defer server.Close()
					arg = server.URL + "/synthetic.ipsw"
				}
				err := cmd.RunE(cmd, []string{arg})
				if (err != nil) != malformed {
					t.Fatalf("error = %v, malformed = %v", err, malformed)
				}
				for _, dir := range []string{staging, out} {
					entries, err := os.ReadDir(dir)
					if err != nil {
						t.Fatal(err)
					}
					want := 0
					if dir == out {
						want = 1
					}
					if len(entries) != want {
						t.Fatalf("directory %s has %d entries, want %d: %v", dir, len(entries), want, entries)
					}
				}
				got, err := os.ReadFile(in)
				if err != nil || !bytes.Equal(got, inputData) {
					t.Fatalf("input changed or removed: %v", err)
				}
				got, err = os.ReadFile(sentinel)
				if err != nil || string(got) != "existing output" {
					t.Fatalf("existing output changed or removed: %v", err)
				}
			})
		}
	}
}

func firmwareInfoArchive(t *testing.T, member string, data []byte) []byte {
	t.Helper()
	manifest := []byte(`<plist version="1.0"><dict><key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string><key>SupportedProductTypes</key><array><string>iPhone99,1</string></array></dict></plist>`)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, contents := range map[string][]byte{"BuildManifest.plist": manifest, member: data} {
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
	return archive.Bytes()
}
