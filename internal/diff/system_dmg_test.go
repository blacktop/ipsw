package diff

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gplist "github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/diff/storage"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestDiffKernelExtractionUsesManifestOrder(t *testing.T) {
	inf := kernelcacheManifestInfo(
		kernelcacheManifestTestEntry{"zboard", "kernelcache.z", 0xaa},
		kernelcacheManifestTestEntry{"aboard", "kernelcache.a", 0xbb},
	)
	for idx := range inf.Plists.BuildIdentities {
		inf.Plists.BuildIdentities[idx].ApProductType = "iPhone99,1"
	}
	inf.Plists.BuildManifest.SupportedProductTypes = []string{"iPhone99,1"}
	want := make([]byte, 64)
	binary.LittleEndian.PutUint64(want, 0xfeedfacf)
	payload, err := img4.CreatePayload(&img4.CreatePayloadConfig{
		Type: img4.IM4P_KERNELCACHE, Version: "synthetic", Data: want, Compression: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	// ZIP order opposes manifest order. The sibling is deliberately invalid:
	// extracting unselected kernels would fail instead of silently passing.
	for idx, name := range []string{"kernelcache.a", "kernelcache.z"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		content := raw
		if idx == 0 {
			content = []byte("unused sibling kernel")
		}
		if _, err := w.Write(content); err != nil {
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
	for _, device := range []string{"", "iPhone99,1"} {
		selected, err := inf.SelectDevice(device)
		if err != nil {
			t.Fatal(err)
		}
		d := &Diff{conf: &Config{Device: device}}
		d.Old = Context{Info: selected, IPSWPath: archive, Folder: t.TempDir()}
		d.New = Context{Info: selected, IPSWPath: archive, Folder: t.TempDir()}
		if err := d.extractKernelcaches(); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{d.Old.Kernel.Path, d.New.Kernel.Path} {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("device %q: extracted wrong kernel %q: %v", device, path, err)
			}
		}
	}
}

func TestDeviceSpecificDiffReportNames(t *testing.T) {
	manifest := &plist.BuildManifest{ProductVersion: "99.0", ProductBuildVersion: "99A1", SupportedProductTypes: []string{"Mac99,1", "Mac99,2"}}
	for _, product := range manifest.SupportedProductTypes {
		manifest.BuildIdentities = append(manifest.BuildIdentities, plist.BuildIdentity{ApProductType: product, Manifest: map[string]plist.IdentityManifest{
			"Cryptex1,SystemOS": {Info: map[string]any{"Path": product + ".dmg"}},
		}})
	}
	data, err := gplist.Marshal(manifest, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.ipsw")
	writeMinimalIPSWZip(t, path, "BuildManifest.plist", string(data))
	filenames := make(map[string]bool)
	for _, product := range manifest.SupportedProductTypes {
		d := New(&Config{IpswOld: path, IpswNew: path, Device: product})
		if err := d.getInfo(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d.Title, product) {
			t.Fatalf("report title omits device: %q", d.Title)
		}
		name := d.TitleToFilename()
		if filenames[name] {
			t.Fatalf("device-specific reports overwrite %q", name)
		}
		filenames[name] = true
	}
	d := New(&Config{IpswOld: path, IpswNew: path, Device: "Mac99,2", Title: "Custom title"})
	if err := d.getInfo(); err != nil {
		t.Fatal(err)
	}
	if d.Title != "Custom title" {
		t.Fatalf("overrode custom title: %q", d.Title)
	}
}

var syntheticDSCMagic = map[string]string{"arm64e": "dyld_v1  arm64e", "arm64e_x1": "dyld_v1arm64ex1"}

func TestDiffNewDeviceAgainstSharedBaseline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kernels []string
		device  string
		wantErr string
	}{
		{"shared kernel", []string{"kernelcache.shared", "kernelcache.shared"}, "Mac99,2", ""},
		{"different kernels", []string{"kernelcache.first", "kernelcache.other"}, "Mac99,2", "multiple kernelcache paths"},
		{"no kernel", nil, "Mac99,2", "no kernelcache"},
		{"invalid kernel path", []string{"kernelcache.shared", ""}, "Mac99,2", "invalid kernelcache path"},
		{"matched device", []string{"kernelcache.first", "kernelcache.other"}, "Mac99,1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inputs []string
			for side, products := range [][]string{{"Mac99,1", "Mac99,3"}, {"Mac99,1", "Mac99,2"}} {
				manifest := &plist.BuildManifest{ProductVersion: "99.0", ProductBuildVersion: "99A1", SupportedProductTypes: products}
				for idx, product := range products {
					components := map[string]plist.IdentityManifest{
						"Cryptex1,SystemOS": {Info: map[string]any{"Path": product + ".dmg"}},
						"KernelCache":       {Info: map[string]any{"Path": "kernelcache." + product}},
					}
					if side == 0 {
						components["Cryptex1,SystemOS"].Info["Path"] = "shared.dmg"
						if tc.kernels == nil {
							delete(components, "KernelCache")
						} else {
							components["KernelCache"].Info["Path"] = tc.kernels[idx]
						}
					}
					manifest.BuildIdentities = append(manifest.BuildIdentities, plist.BuildIdentity{ApProductType: product, Manifest: components})
				}
				data, err := gplist.Marshal(manifest, gplist.XMLFormat)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "synthetic.ipsw")
				writeMinimalIPSWZip(t, path, "BuildManifest.plist", string(data))
				inputs = append(inputs, path)
			}
			// Check both input positions: fallback is used for old and new.
			for _, reversed := range []bool{false, true} {
				old, new := inputs[0], inputs[1]
				if reversed {
					old, new = new, old
				}
				d := New(&Config{IpswOld: old, IpswNew: new, Device: tc.device})
				err := d.getInfo()
				if tc.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("reversed=%t: expected %q before extraction, got %v", reversed, tc.wantErr, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				baseline := d.Old.Info
				if reversed {
					baseline = d.New.Info
				}
				if got, err := baseline.GetSystemOsDmg(); err != nil || got != "shared.dmg" {
					t.Fatalf("baseline SystemOS = %q, %v", got, err)
				}
				if got, err := selectedKernelcachePath(baseline); err != nil || got != tc.kernels[0] {
					t.Fatalf("baseline kernel = %q, %v", got, err)
				}
			}
		})
	}
}

// writeSyntheticDSC writes a minimal openable cache header for arch under root.
func writeSyntheticDSC(t *testing.T, root, arch string) {
	t.Helper()
	path := filepath.Join(root, "System/Library/dyld/dyld_shared_cache_"+arch)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	var header dyld.CacheHeader
	copy(header.Magic[:], syntheticDSCMagic[arch])
	header.UUID[0] = byte(len(arch))
	header.MappingOffset = uint32(binary.Size(header))
	header.CodeSignatureOffset = uint64(binary.Size(header))
	header.CodeSignatureSize = 12
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(f, binary.BigEndian, []uint32{0xfade0cc0, 12, 0}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDeviceSpecificDSCFromMount(t *testing.T) {
	for _, arch := range []string{"arm64e", "arm64e_x1"} {
		t.Run(arch, func(t *testing.T) {
			root := t.TempDir()
			writeSyntheticDSC(t, root, arch)
			cache, err := openDSCFromMount(root, true, inputModeIPSW, "Old")
			if err != nil {
				t.Fatal(err)
			}
			defer cache.Close()
			if got := cache.Headers[cache.UUID].Magic.String(); got != syntheticDSCMagic[arch] {
				t.Fatalf("opened %q, want %q", got, syntheticDSCMagic[arch])
			}
		})
	}
}

func TestOpenNumberedDSCReachesParser(t *testing.T) {
	for _, variant := range []string{"arm64e_x2", "arm64e_x12", "arm64e_xfoo"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "System/Library/dyld/dyld_shared_cache_"+variant)
			if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
				t.Fatal(err)
			}
			// Empty synthetic data proves discovery reaches the parser without
			// assuming an unverified cache magic or layout for future variants.
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := openDSCFromMount(root, true, inputModeIPSW, "Old")
			want := "failed to open DSC"
			if variant == "arm64e_xfoo" {
				want = "no dyld_shared_cache files found"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("wanted %q, got %v", want, err)
			}
		})
	}
}

func TestOpenDSCFromMountPrefersGenericCache(t *testing.T) {
	root := t.TempDir()
	writeSyntheticDSC(t, root, "arm64e_x1")
	writeSyntheticDSC(t, root, "arm64e")
	cache, err := openDSCFromMount(root, true, inputModeIPSW, "Old")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if got := cache.Headers[cache.UUID].Magic.String(); got != syntheticDSCMagic["arm64e"] {
		t.Fatalf("opened %q with both variants present", got)
	}
	x1 := filepath.Join(root, "System/Library/dyld/dyld_shared_cache_arm64e_x1")
	if got := preferGenericDSC([]string{x1}); got != x1 {
		t.Fatalf("lone variant not selected: %q", got)
	}
}

func TestDiffSystemOSDeviceSelectionAndCacheIdentity(t *testing.T) {
	i := &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{ProductBuildVersion: "99A1", ProductVersion: "99.0"}}}
	for idx, product := range []string{"Mac99,1", "Mac99,2"} {
		i.Plists.BuildIdentities = append(i.Plists.BuildIdentities, plist.BuildIdentity{ApProductType: product, Manifest: map[string]plist.IdentityManifest{
			"KernelCache":       {Info: map[string]any{"Path": "kernelcache." + product}, Digest: []byte{byte(idx + 10)}},
			"Cryptex1,SystemOS": {Info: map[string]any{"Path": product + ".dmg"}, Digest: []byte{byte(idx + 1)}},
		}})
	}
	if _, err := i.SelectDevice(""); err == nil {
		t.Fatal("ambiguous SystemOS would be skipped as absent")
	}
	var ids, volumes []string
	for _, product := range []string{"Mac99,1", "Mac99,2"} {
		selected, err := i.SelectDevice(product)
		if err != nil {
			t.Fatal(err)
		}
		if !volumeResolves(selected, "sys") {
			t.Fatal("selected SystemOS not dispatched")
		}
		path, err := selected.GetSystemOsDmg()
		if err != nil || path != product+".dmg" {
			t.Fatalf("wrong SystemOS: %s, %v", path, err)
		}
		kernel, err := selectedKernelcachePath(selected)
		if err != nil || kernel != "kernelcache."+product {
			t.Fatalf("kernel differs from selected device: %q, %v", kernel, err)
		}
		id, err := storage.IPSWCacheIdentity(selected)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		volumes = append(volumes, volumeDMGInputHashFor(selected, selected, "sys"))
	}
	// Selections of one IPSW share its cache identity so a later board hydrates
	// the walks an earlier board persisted; the tasks that read different
	// volumes still get distinct scopes through their volume input hashes.
	if ids[0] != ids[1] {
		t.Fatalf("target selections of one IPSW got different cache identities: %q != %q", ids[0], ids[1])
	}
	if volumes[0] == volumes[1] {
		t.Fatal("different SystemOS volumes share a task input hash")
	}
}

func TestSelectedKernelcachePathFirstInManifestOrder(t *testing.T) {
	identity := func(product, board, kernel string) plist.BuildIdentity {
		return plist.BuildIdentity{
			ApProductType: product,
			Info:          plist.IdentityInfo{DeviceClass: board},
			Manifest:      map[string]plist.IdentityManifest{"KernelCache": {Info: map[string]any{"Path": kernel}}},
		}
	}
	i := &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{BuildIdentities: []plist.BuildIdentity{
		identity("Phone99,1", "d99ap", "kernelcache.release.phone99"),
		identity("Phone99,1", "d99ap", "kernelcache.research.phone99"),
		identity("Phone98,1", "n71ap", "kernelcache.release.n71"),
		identity("Phone98,1", "n71map", "kernelcache.release.n71"),
		identity("Phone97,1", "d97ap", "kernelcache.release.d97"),
		identity("Phone97,1", "d97map", "kernelcache.release.d97m"),
	}}}}
	for product, want := range map[string]string{
		"Phone99,1": "kernelcache.release.phone99", // release before research
		"Phone98,1": "kernelcache.release.n71",     // two boards, one kernelcache
		"Phone97,1": "kernelcache.release.d97",     // two boards, first in manifest order
	} {
		selected, err := i.ForDevice(product)
		if err != nil {
			t.Fatal(err)
		}
		if kernel, err := selectedKernelcachePath(selected); err != nil || kernel != want {
			t.Fatalf("%s resolved to %q, %v; want %q", product, kernel, err, want)
		}
	}
	none := &info.Info{Plists: &plist.Plists{BuildManifest: &plist.BuildManifest{BuildIdentities: []plist.BuildIdentity{
		{ApProductType: "Phone96,1", Manifest: map[string]plist.IdentityManifest{}},
	}}}}
	if _, err := selectedKernelcachePath(none); err == nil {
		t.Fatal("identity without a kernelcache accepted")
	}
}
