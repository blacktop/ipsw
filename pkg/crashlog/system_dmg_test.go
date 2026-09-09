package crashlog

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gplist "github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/plist"
)

// This archive contains only hand-authored metadata and a minimal synthetic
// kernel. Its absent DMGs expose which SystemOS each symbolication path selects
// without invoking a disk-image mount.
func symbolicationMultiSystemIPSW(t *testing.T) string {
	t.Helper()
	manifest := plist.BuildManifest{
		ProductBuildVersion:   "99A1",
		SupportedProductTypes: []string{"Mac99,1", "Mac99,2"},
	}
	for idx, product := range manifest.SupportedProductTypes {
		manifest.BuildIdentities = append(manifest.BuildIdentities, plist.BuildIdentity{
			ApProductType: product,
			Info:          plist.IdentityInfo{DeviceClass: []string{"j991ap", "j992ap"}[idx]},
			Manifest: map[string]plist.IdentityManifest{
				"Cryptex1,SystemOS": {Info: map[string]any{"Path": "missing-" + product + ".dmg"}},
				"KernelCache":       {Info: map[string]any{"Path": "kernelcache.synthetic"}},
			},
		})
	}
	metadata, err := gplist.Marshal(manifest, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	// Mach-O 64 header, one LC_SEGMENT_64 with an empty __TEXT.__const
	// section, and a null byte. No functions, UUIDs, or real kernel data.
	kernel := make([]byte, 185)
	for offset, value := range map[int]uint32{
		0: 0xfeedfacf, 4: 0x0100000c, 12: 2, 16: 1, 20: 152,
		32: 0x19, 36: 152, 96: 1, 152: 184,
	} {
		binary.LittleEndian.PutUint32(kernel[offset:], value)
	}
	copy(kernel[40:], "__TEXT")
	binary.LittleEndian.PutUint64(kernel[64:], uint64(len(kernel)))
	binary.LittleEndian.PutUint64(kernel[80:], uint64(len(kernel)))
	copy(kernel[104:], "__const")
	copy(kernel[120:], "__TEXT")
	binary.LittleEndian.PutUint64(kernel[144:], 1)
	payload, err := asn1.Marshal(struct {
		Tag, Type, Version string
		Data               []byte
	}{"IM4P", "krnl", "synthetic", kernel})
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, data := range map[string][]byte{"BuildManifest.plist": metadata, "kernelcache.synthetic": payload} {
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
	path := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSymbolicate210SelectsCrashDeviceForFilesystem(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	i := &Ips{Config: &Config{}, Payload: IPSPayload{Product: "Mac99,2"}}
	err := i.Symbolicate210(symbolicationMultiSystemIPSW(t), nil, "")
	if err == nil || !strings.Contains(err.Error(), "failed to scan files in SystemOS missing-Mac99,2.dmg") {
		t.Fatalf("expected selected SystemOS scan to reach the absent image, got %v", err)
	}
}

func TestOpenDSCsSelectsDevice(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	archive := symbolicationMultiSystemIPSW(t)
	i := &Ips{Config: &Config{}, Payload: IPSPayload{Product: "Mac99,2"}}
	for _, device := range []string{i.Payload.Product, "Mac99,1"} {
		fs, cleanup, err := i.openDSCs(archive, nil, device)
		if cleanup != nil {
			cleanup()
		}
		if err == nil || !strings.Contains(err.Error(), "missing-"+device+".dmg") || strings.Contains(err.Error(), "multiple SystemOS") {
			t.Fatalf("device %q: expected selected absent image, got %v", device, err)
		}
		if len(fs) != 0 {
			t.Fatalf("opened caches from absent image: %v", fs)
		}
	}
}
