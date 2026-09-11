package mount

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestMountDeviceSpecificSystemOS(t *testing.T) {
	for _, tc := range []struct {
		name, device, want string
		choose             bool
		index              int
		cancel             bool
	}{
		{name: "ambiguous"},
		{name: "product", device: "Mac99,2", want: "special"},
		{name: "board", device: "J992AP", want: "special"},
		{name: "unknown", device: "Mac99,3"},
		{name: "choose common", choose: true, index: 0, want: "common"},
		{name: "choose special", choose: true, index: 1, want: "special"},
		{name: "cancel", choose: true, cancel: true},
		{name: "negative index", choose: true, index: -1},
		{name: "out of range", choose: true, index: 2},
		{name: "explicit bypasses chooser", device: "Mac99,2", choose: true, cancel: true, want: "special"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			manifest := `<plist version="1.0"><dict><key>BuildIdentities</key><array>`
			for idx, path := range []string{"common.dmg.aea", "special.dmg.aea"} {
				manifest += fmt.Sprintf(`<dict><key>Ap,ProductType</key><string>Mac99,%d</string><key>Info</key><dict><key>DeviceClass</key><string>j99%dap</string></dict><key>Manifest</key><dict><key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>%s</string></dict></dict><key>OS</key><dict><key>Info</key><dict><key>Path</key><string>filesystem.dmg</string></dict></dict></dict></dict>`, idx+1, idx+1, path)
			}
			manifest += `</array></dict></plist>`
			for name, contents := range map[string]string{"BuildManifest.plist": manifest, "common.dmg.aea": "common encrypted bytes", "special.dmg.aea": "special encrypted bytes", "filesystem.dmg": "wrong fallback image"} {
				w, err := zw.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write([]byte(contents)); err != nil {
					t.Fatal(err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			ipsw := filepath.Join(root, "synthetic.ipsw")
			if err := os.WriteFile(ipsw, buf.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			extractDir := filepath.Join(root, "extract")
			attached, decrypted := false, false
			cfg := &Config{Device: tc.device, ExtractDir: extractDir}
			called := false
			if tc.choose {
				cfg.SelectSystemOS = func(dmgs []info.SystemOSDMG) (int, error) {
					called = true
					if len(dmgs) != 2 || dmgs[0].Path != "common.dmg.aea" || dmgs[1].Path != "special.dmg.aea" {
						t.Fatalf("wrong choices: %+v", dmgs)
					}
					if tc.cancel {
						return 0, fmt.Errorf("selection canceled")
					}
					return tc.index, nil
				}
			}
			ctx, err := dmgInIPSW(ipsw, "sys", cfg, func(path, _ string) (utils.DMGMount, error) {
				attached = true
				if filepath.Base(path) != tc.want+".dmg" {
					t.Fatalf("wrong attachment %q", path)
				}
				return utils.DMGMount{MountPoint: "/synthetic/system", OwnsDirectory: true}, nil
			}, func(cfg *aea.DecryptConfig) (string, error) {
				decrypted = true
				if filepath.Base(cfg.Input) != tc.want+".dmg.aea" {
					t.Fatalf("wrong decryption input %q", cfg.Input)
				}
				path := strings.TrimSuffix(cfg.Input, ".aea")
				return path, os.WriteFile(path, []byte("synthetic decrypted disk image bytes"), 0600)
			})
			if called != (tc.choose && tc.device == "") {
				t.Fatalf("chooser called = %v", called)
			}
			if tc.want == "" {
				if err == nil || ctx != nil || attached || decrypted {
					t.Fatalf("invalid selector reached IO: %v", err)
				}
				if _, err := os.Stat(extractDir); !os.IsNotExist(err) {
					t.Fatal("extracted before selection")
				}
			} else if err != nil || !attached || !decrypted || ctx == nil {
				t.Fatalf("mount selection failed: %v", err)
			}
		})
	}
}

func TestMountReusesPreParsedInfo(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("special.dmg.aea")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("special encrypted bytes")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	ipsw := filepath.Join(root, "no-manifest.ipsw")
	if err := os.WriteFile(ipsw, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	// The archive carries no BuildManifest, so only the supplied metadata can
	// resolve the SystemOS image; parsing it again would fail.
	pre := &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{BuildIdentities: []plist.BuildIdentity{{
		ApProductType: "Mac99,2",
		Manifest:      map[string]plist.IdentityManifest{"Cryptex1,SystemOS": {Info: map[string]any{"Path": "special.dmg.aea"}}},
	}}}}}
	attached := false
	ctx, err := dmgInIPSW(ipsw, "sys", &Config{Device: "Mac99,2", Info: pre, ExtractDir: filepath.Join(root, "extract")}, func(path, _ string) (utils.DMGMount, error) {
		attached = filepath.Base(path) == "special.dmg"
		return utils.DMGMount{MountPoint: "/synthetic/system", OwnsDirectory: true}, nil
	}, func(cfg *aea.DecryptConfig) (string, error) {
		path := strings.TrimSuffix(cfg.Input, ".aea")
		return path, os.WriteFile(path, []byte("synthetic decrypted disk image bytes"), 0600)
	})
	if err != nil || ctx == nil || !attached {
		t.Fatalf("pre-parsed metadata not used: %v", err)
	}
}
