package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/crashlog"
)

func TestMicrostackshotDSCUsesHardwareModel(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	for _, products := range [][]string{{"Mac99,1", "Mac99,2"}, {"Mac99,1"}} {
		// Hand-authored metadata only: missing DMGs stop before any mounting.
		manifest := `<plist version="1.0"><dict><key>BuildIdentities</key><array>`
		for _, product := range products {
			manifest += fmt.Sprintf(`<dict><key>Ap,ProductType</key><string>%s</string><key>Manifest</key><dict><key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>missing-%s.dmg</string></dict></dict></dict></dict>`, product, product)
		}
		manifest += `</array></dict></plist>`
		var data bytes.Buffer
		zw := zip.NewWriter(&data)
		w, err := zw.Create("BuildManifest.plist")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(manifest)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(t.TempDir(), "synthetic.ipsw")
		if err := os.WriteFile(archive, data.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		for _, product := range products {
			ms := &crashlog.Microstackshot{HardwareModel: product}
			_, cleanup, err := openMicrostackshotDSC([]string{"synthetic-report", archive}, ms, "")
			if cleanup != nil {
				cleanup()
			}
			if err == nil || !strings.Contains(err.Error(), "missing-"+product+".dmg") || strings.Contains(err.Error(), "multiple SystemOS") {
				t.Fatalf("model %s: expected selected missing image, got %v", product, err)
			}
		}
		// An unmatched report may use a shared image, but must never guess
		// between different SystemOS variants.
		_, cleanup, err := openMicrostackshotDSC([]string{"synthetic-report", archive}, &crashlog.Microstackshot{HardwareModel: "Mac99,3"}, "")
		if cleanup != nil {
			cleanup()
		}
		want := "no BuildManifest identity"
		if len(products) == 1 {
			want = "missing-Mac99,1.dmg"
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("unmatched report with %d images: want %q, got %v", len(products), want, err)
		}
	}
}
