package search_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/commands/ent"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/syms"
	"github.com/blacktop/ipsw/pkg/launchd"
)

func multiSystemIPSW(t *testing.T) string {
	t.Helper()
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	manifest := `<plist version="1.0"><dict><key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string><key>SupportedProductTypes</key><array><string>Mac99,1</string><string>Mac99,2</string></array><key>BuildIdentities</key><array>`
	for idx, name := range []string{"missing-common.dmg", "missing-special.dmg"} {
		manifest += fmt.Sprintf(`<dict><key>Ap,ProductType</key><string>Mac99,%d</string><key>Info</key><dict><key>DeviceClass</key><string>j99%dap</string></dict><key>Manifest</key><dict>`, idx+1, idx+1)
		for _, component := range []string{"OS", "Cryptex1,SystemOS", "Cryptex1,AppOS"} {
			manifest += fmt.Sprintf(`<key>%s</key><dict><key>Info</key><dict><key>Path</key><string>%s</string></dict></dict>`, component, name)
		}
		manifest += `</dict></dict>`
	}
	manifest += `</array></dict></plist>`
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
	path := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDeviceSelectionReachesScanResources(t *testing.T) {
	ipsw := multiSystemIPSW(t)
	for _, device := range []string{"Mac99,2", "J992AP"} {
		dmgs, err := search.ListDMGsForDevice(ipsw, device)
		if err != nil || len(dmgs) != 3 {
			t.Fatalf("list: %v, %v", dmgs, err)
		}
		for _, dmg := range dmgs {
			if dmg.Path != "missing-special.dmg" {
				t.Fatalf("wrong selected DMG: %+v", dmg)
			}
		}
		for name, scan := range map[string]func() error{
			"macho": func() error {
				return search.ForEachMachoInIPSWForDevice(ipsw, "", device, func(string, *macho.File) error { t.Fatal("unexpected Mach-O"); return nil })
			},
			"plist": func() error {
				return search.ForEachPlistInIPSWForDevice(ipsw, "", "", device, func(string, string) error { return nil })
			},
			"file": func() error {
				return search.ForEachFileInIPSWForDevice(ipsw, "", "", device, func(string, string) error { return nil })
			},
			"all": func() error {
				return search.ScanAllDMGsForDevice(ipsw, "", device, nil, func(string, string) error { return nil })
			},
			"ent": func() error { _, err := ent.GetDatabase(&ent.Config{IPSW: ipsw, Device: device}); return err },
			"symbols": func() error {
				var out bytes.Buffer
				return syms.ScanJSONL(&syms.JSONLConfig{IPSW: ipsw, Device: device, FileSystem: true}, &out)
			},
		} {
			t.Run(device+"/"+name, func(t *testing.T) {
				// Missing members exercise selection through extraction dispatch
				// without mounting or requiring firmware keys.
				err := scan()
				if err == nil || !strings.Contains(err.Error(), "missing-special.dmg") || strings.Contains(err.Error(), "multiple SystemOS") {
					t.Fatalf("selection did not reach special image: %v", err)
				}
			})
		}
	}
}

func TestInvalidDeviceSelectionEmitsNothing(t *testing.T) {
	ipsw := multiSystemIPSW(t)
	for _, device := range []string{"", "Mac99,3"} {
		if err := mcmd.RunMTEScanIPSWForDevice(ipsw, "", device); err == nil || (!strings.Contains(err.Error(), "multiple SystemOS") && !strings.Contains(err.Error(), "no BuildManifest identity")) {
			t.Fatalf("MTE scan did not reject selection before starting its UI: %v", err)
		}
		called := false
		err := search.ForEachFileInIPSWForDevice(ipsw, "", "", device, func(string, string) error { called = true; return nil })
		if err == nil || called {
			t.Fatalf("invalid selection dispatched archive callback: %v", err)
		}
		records, skipped, launchErr := launchd.WalkIPSW(ipsw, &launchd.IPSWConfig{Device: device})
		if launchErr == nil || len(records) != 0 || len(skipped) != 0 {
			t.Fatalf("invalid launchd selection reached mounts: %v, %v", launchErr, skipped)
		}
		var out bytes.Buffer
		err = syms.ScanJSONL(&syms.JSONLConfig{IPSW: ipsw, Device: device, Kernel: true, FileSystem: true}, &out)
		if err == nil || out.Len() != 0 {
			t.Fatalf("invalid symbol selection emitted %q: %v", out.String(), err)
		}
	}
}

func TestFirmwareEntitlementIngestionReachesArchive(t *testing.T) {
	ipsw := multiSystemIPSW(t)
	_, err := ent.GetDatabase(&ent.Config{IPSW: ipsw, AllDevices: true})
	if err == nil || strings.Contains(err.Error(), "multiple SystemOS") || !strings.Contains(err.Error(), "missing-common.dmg") {
		t.Fatalf("firmware-wide ingestion did not reach its first image: %v", err)
	}
}

func TestSelectedEntitlementsBypassUnscopedBlob(t *testing.T) {
	ipsw := multiSystemIPSW(t)
	cache := filepath.Join(t.TempDir(), "old.gob")
	original := []byte("not a device-scoped entitlement cache")
	if err := os.WriteFile(cache, original, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := ent.GetDatabase(&ent.Config{IPSW: ipsw, Device: "Mac99,2", Database: cache})
	if err == nil || !strings.Contains(err.Error(), "missing-special.dmg") {
		t.Fatalf("used unscoped cache: %v", err)
	}
	after, err := os.ReadFile(cache)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("changed existing cache: %q, %v", after, err)
	}
}

func TestSymbolsJSONLReportsSelectedDevice(t *testing.T) {
	ipsw := multiSystemIPSW(t)
	var out bytes.Buffer
	// Kernel-only scans emit the ipsw header before failing on the fixture's
	// missing kernelcache, which is all this test needs.
	_ = syms.ScanJSONL(&syms.JSONLConfig{IPSW: ipsw, Device: "J992AP", Kernel: true}, &out)
	first, _, _ := strings.Cut(out.String(), "\n")
	for _, want := range []string{`"device":"J992AP"`, `"devices":["Mac99,2"]`} {
		if !strings.Contains(first, want) {
			t.Fatalf("selected ipsw header %s lacks %s", first, want)
		}
	}
	out.Reset()
	_ = syms.ScanJSONL(&syms.JSONLConfig{IPSW: ipsw, Kernel: true}, &out)
	first, _, _ = strings.Cut(out.String(), "\n")
	if !strings.Contains(first, `"devices":["Mac99,1","Mac99,2"]`) || strings.Contains(first, `"device":`) {
		t.Fatalf("unselected ipsw header %s", first)
	}
}
