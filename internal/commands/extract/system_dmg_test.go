package extract

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gplist "github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestKernelcacheKeepsBoardSelectionLocalAndRemote(t *testing.T) {
	paths := []string{"kernelcache.release.n66", "kernelcache.research.n66", "kernelcache.release.n66m"}
	metadata := testKernelInfo(paths...)
	metadata.Plists.BuildManifest.ProductBuildVersion = "99A1"
	manifest, err := gplist.Marshal(metadata.Plists.BuildManifest, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	contents := map[string][]byte{"BuildManifest.plist": manifest}
	plaintext := make(map[string][]byte)
	for _, path := range paths {
		plaintext[path] = append([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1}, bytes.Repeat([]byte(path), 32)...)
		contents[path] = makeUnencryptedKernelPayload(t, plaintext[path])
	}
	for name, data := range contents {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(file, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"synthetic-board-kernels"`)
		http.ServeContent(w, r, "synthetic.ipsw", time.Time{}, bytes.NewReader(archive.Bytes()))
	}))
	defer server.Close()
	for _, mode := range []string{"local", "remote", "remote with keys"} {
		for _, device := range []string{"N66AP", "n66map", "iPhone8,2", "unknown"} {
			t.Run(mode+"/"+device, func(t *testing.T) {
				c := &Config{KernelDevice: device, Output: t.TempDir()}
				if mode == "local" {
					c.IPSW = file
				} else {
					c.URL = server.URL + "/synthetic.ipsw"
				}
				if mode == "remote with keys" {
					c.FirmwareKeys = download.WikiFWKeys{"unused": {}}
				}
				defer c.Close()
				out, err := Kernelcache(c)
				if device == "unknown" {
					if err == nil || len(out) != 0 {
						t.Fatalf("unknown board accepted: %v, %v", out, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				want := paths
				if device == "N66AP" {
					want = paths[:2]
				}
				if device == "n66map" {
					want = paths[2:]
				}
				if len(out) != len(want) {
					t.Fatalf("extracted %d kernels, want %d: %v", len(out), len(want), out)
				}
				for path := range out {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					matched := false
					for _, source := range want {
						matched = matched || bytes.Equal(data, plaintext[source])
					}
					if !matched {
						t.Fatalf("extracted a sibling board's kernel: %s", path)
					}
				}
			})
		}
	}
}

func extractionMultiSystemInfo() *info.Info {
	i := &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{ProductBuildVersion: "99A1", SupportedProductTypes: []string{"Mac99,1", "Mac99,2"}}}}
	for idx, product := range []string{"Mac99,1", "Mac99,2"} {
		i.Plists.BuildIdentities = append(i.Plists.BuildIdentities, plist.BuildIdentity{
			ApProductType: product,
			Info:          plist.IdentityInfo{DeviceClass: []string{"j991ap", "j992ap"}[idx]},
			Manifest: map[string]plist.IdentityManifest{
				"Cryptex1,SystemOS": {Info: map[string]any{"Path": product + ".dmg.aea"}},
			},
		})
	}
	return i
}

func TestExtractDeviceSpecificDMGLocalAndRemote(t *testing.T) {
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	manifest, err := gplist.Marshal(extractionMultiSystemInfo().Plists.BuildManifest, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	w, err := zw.Create("BuildManifest.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Mac99,1.dmg.aea", "Mac99,2.dmg.aea"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("synthetic " + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(archive, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"synthetic-multi-system"`)
		http.ServeContent(w, r, "synthetic.ipsw", time.Time{}, bytes.NewReader(data.Bytes()))
	}))
	defer server.Close()
	for _, remote := range []bool{false, true} {
		for _, device := range []string{"", "Mac99,2", "J992AP", "Mac99,3"} {
			outDir := t.TempDir()
			c := &Config{DmgType: "sys", KernelDevice: device, Output: outDir}
			if remote {
				c.URL = server.URL + "/synthetic.ipsw"
			} else {
				c.IPSW = archive
			}
			out, err := DMG(c)
			if device == "" || device == "Mac99,3" {
				if err == nil || len(out) != 0 {
					t.Fatalf("remote=%t device=%q: accepted ambiguous/unknown target", remote, device)
				}
				entries, err := os.ReadDir(outDir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("wrote files before selection: %v", err)
				}
				continue
			}
			if err != nil || len(out) != 1 || filepath.Base(out[0]) != "Mac99,2.dmg.aea" {
				t.Fatalf("remote=%t device=%q: %v, %v", remote, device, out, err)
			}
			contents, err := os.ReadFile(out[0])
			if err != nil || string(contents) != "synthetic Mac99,2.dmg.aea" {
				t.Fatalf("wrong extracted bytes: %q, %v", contents, err)
			}
			if len(c.info.Plists.BuildIdentities) != 2 {
				t.Fatal("mutated cached source metadata")
			}
		}
	}
}

func TestRemoteDscDeviceAndSearchPreflight(t *testing.T) {
	i := extractionMultiSystemInfo()
	if _, err := remoteDmgPathForDscStep(i, dyld.SystemOSDscDMG); err == nil {
		t.Fatal("ambiguous remote DSC accepted")
	}
	selected, err := selectDmgInfo(i, "j992ap", true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := remoteDmgPathForDscStep(selected, dyld.SystemOSDscDMG)
	if err != nil || path != "Mac99,2.dmg.aea" {
		t.Fatalf("remote DSC selected %q, %v", path, err)
	}
	if _, err := selectDmgInfo(i, "", true); err == nil || !strings.Contains(err.Error(), "multiple SystemOS") {
		t.Fatalf("file search ambiguity: %v", err)
	}
	if _, err := selectDmgInfo(i, "", false); err != nil {
		t.Fatalf("archive-only search blocked: %v", err)
	}
}

func TestRemoteOTADSCRejectsDeviceSelection(t *testing.T) {
	manifest, err := gplist.Marshal(extractionMultiSystemInfo().Plists.BuildManifest, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	otaInfo, err := gplist.Marshal(&plist.OTAInfo{}, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, data := range map[string][]byte{"BuildManifest.plist": manifest, "Info.plist": otaInfo} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"synthetic-ota-selection"`)
		http.ServeContent(w, r, "synthetic.zip", time.Time{}, bytes.NewReader(archive.Bytes()))
	}))
	t.Cleanup(server.Close)
	for _, device := range []string{"Mac99,2", "J992AP", "Mac99,3"} {
		for _, arches := range [][]string{nil, {"arm64e"}} {
			t.Run(device+"/"+strings.Join(arches, ","), func(t *testing.T) {
				c := &Config{URL: server.URL + "/synthetic.zip", KernelDevice: device, Arches: arches, Output: t.TempDir()}
				t.Cleanup(func() { c.Close() })
				out, err := DSC(c)
				if err == nil || !strings.Contains(err.Error(), "device selection is not supported for dyld_shared_cache extraction from remote OTA") || len(out) != 0 {
					t.Fatalf("expected unsupported device selection, got %v, %v", out, err)
				}
				if c.info == nil || c.info.Plists.Type != "OTA" {
					t.Fatal("fixture did not reach the remote OTA path")
				}
				entries, err := os.ReadDir(c.Output)
				if err != nil || len(entries) != 0 {
					t.Fatalf("wrote files before rejecting device selection: %v, %v", entries, err)
				}
			})
		}
	}
}
