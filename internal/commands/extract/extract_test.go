package extract

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestFirmwareKeyForFileMatchesNormalizedSuffix(t *testing.T) {
	keys := download.WikiFWKeys{
		"kernel": {
			Filename: []string{"kernelcache release n66"},
			Iv:       []string{"00112233445566778899aabbccddeeff"},
			Key:      []string{"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"},
		},
	}

	iv, key, ok, err := firmwareKeyForFile(keys, "/tmp/out/kernelcache_release_n66")
	if err != nil {
		t.Fatalf("firmwareKeyForFile returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected matching key")
	}
	if got, want := len(iv), aes.BlockSize; got != want {
		t.Fatalf("iv length = %d, want %d", got, want)
	}
	if got, want := len(key), 32; got != want {
		t.Fatalf("key length = %d, want %d", got, want)
	}
}

func TestFirmwareKeyForFileUsesMatchingFilenameIndex(t *testing.T) {
	kbag := append(bytes.Repeat([]byte{0x11}, aes.BlockSize), bytes.Repeat([]byte{0x22}, 32)...)
	keys := download.WikiFWKeys{
		"kernel": {
			Filename: []string{"DeviceTree.n66ap.im4p", "kernelcache.release.n66"},
			Iv:       []string{"Unknown"},
			Key:      []string{"Unknown"},
			Kbag:     []string{"Unknown", "111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222"},
		},
	}

	iv, key, ok, err := firmwareKeyForFile(keys, "kernelcache.release.n66")
	if err != nil {
		t.Fatalf("firmwareKeyForFile returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected matching kbag")
	}
	if !bytes.Equal(iv, kbag[:aes.BlockSize]) {
		t.Fatalf("iv = %x, want %x", iv, kbag[:aes.BlockSize])
	}
	if !bytes.Equal(key, kbag[aes.BlockSize:]) {
		t.Fatalf("key = %x, want %x", key, kbag[aes.BlockSize:])
	}
}

func TestFirmwareKeyForFileIgnoresUnknownMaterial(t *testing.T) {
	keys := download.WikiFWKeys{
		"kernel": {
			Filename: []string{"kernelcache.release.n66"},
			Iv:       []string{"Unknown"},
			Key:      []string{"Unknown"},
		},
	}

	_, _, ok, err := firmwareKeyForFile(keys, "kernelcache.release.n66")
	if err != nil {
		t.Fatalf("firmwareKeyForFile returned error: %v", err)
	}
	if ok {
		t.Fatal("unexpected matching key")
	}
}

func TestRemoteKernelcacheWithKeysDecryptsSelectedMember(t *testing.T) {
	plaintext := append([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}, bytes.Repeat([]byte("kernel-data"), 128)...)
	iv := bytes.Repeat([]byte{0x11}, aes.BlockSize)
	key := bytes.Repeat([]byte{0x22}, 32)
	payloadData := makeEncryptedKernelPayload(t, plaintext, iv, key)

	zr := newKernelZipReader(t, payloadData, "kernelcache.release.n66")
	inf := testKernelInfo("kernelcache.release.n66")
	keys := download.WikiFWKeys{
		"kernel": {
			Filename: []string{"kernelcache.release.n66"},
			Iv:       []string{"11111111111111111111111111111111"},
			Key:      []string{"2222222222222222222222222222222222222222222222222222222222222222"},
		},
	}

	outDir := t.TempDir()
	out, err := remoteKernelcacheWithKeys(inf, zr, outDir, "iPhone8,2", keys, false)
	if err != nil {
		t.Fatalf("remoteKernelcacheWithKeys() error = %v", err)
	}
	if got, want := len(out), 1; got != want {
		t.Fatalf("output count = %d, want %d: %#v", got, want, out)
	}
	var outPath string
	for path := range out {
		outPath = path
	}
	if filepath.Dir(outPath) != outDir {
		t.Fatalf("output dir = %q, want %q", filepath.Dir(outPath), outDir)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted kernelcache mismatch: got %d bytes with prefix %x, want %d bytes with prefix %x",
			len(got), got[:8], len(plaintext), plaintext[:8])
	}
}

func TestRemoteKernelcacheWithKeysPreflightsAllSelectedMembers(t *testing.T) {
	plaintext := append([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}, bytes.Repeat([]byte("kernel-data"), 128)...)
	iv := bytes.Repeat([]byte{0x11}, aes.BlockSize)
	key := bytes.Repeat([]byte{0x22}, 32)
	payloadData := makeEncryptedKernelPayload(t, plaintext, iv, key)

	zr := newKernelZipReader(t, payloadData, "kernelcache.release.n66", "kernelcache.release.n66m")
	inf := testKernelInfo("kernelcache.release.n66", "kernelcache.release.n66m")
	keys := download.WikiFWKeys{
		"kernel": {
			Filename: []string{"kernelcache.release.n66"},
			Iv:       []string{"11111111111111111111111111111111"},
			Key:      []string{"2222222222222222222222222222222222222222222222222222222222222222"},
		},
	}

	outDir := t.TempDir()
	_, err := remoteKernelcacheWithKeys(inf, zr, outDir, "iPhone8,2", keys, false)
	if !errors.Is(err, ErrNoDecryptionKey) {
		t.Fatalf("remoteKernelcacheWithKeys() error = %v, want %v", err, ErrNoDecryptionKey)
	}
	if _, err := os.Stat(filepath.Join(outDir, "kernelcache.release.n66")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no partial output, stat error = %v", err)
	}
}

func TestRemoteKernelcacheWithKeysPassesThroughUnencrypted(t *testing.T) {
	plaintext := append([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}, bytes.Repeat([]byte("kernel-data"), 128)...)
	payloadData := makeUnencryptedKernelPayload(t, plaintext)

	zr := newKernelZipReader(t, payloadData, "kernelcache.release.n66")
	inf := testKernelInfo("kernelcache.release.n66")
	// Keys map is non-empty (so the keyed path runs) but contains no entry for this kernelcache.
	keys := download.WikiFWKeys{
		"unrelated": {
			Filename: []string{"DeviceTree.n66ap.im4p"},
			Iv:       []string{"11111111111111111111111111111111"},
			Key:      []string{"2222222222222222222222222222222222222222222222222222222222222222"},
		},
	}

	outDir := t.TempDir()
	out, err := remoteKernelcacheWithKeys(inf, zr, outDir, "iPhone8,2", keys, false)
	if err != nil {
		t.Fatalf("remoteKernelcacheWithKeys() error = %v", err)
	}
	if got, want := len(out), 1; got != want {
		t.Fatalf("output count = %d, want %d: %#v", got, want, out)
	}
	var outPath string
	for path := range out {
		outPath = path
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("kernelcache mismatch: got %d bytes with prefix %x, want %d bytes with prefix %x",
			len(got), got[:8], len(plaintext), plaintext[:8])
	}
}

func newKernelZipReader(t *testing.T, payloadData []byte, names ...string) *zip.Reader {
	t.Helper()

	var zipData bytes.Buffer
	zw := zip.NewWriter(&zipData)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("Create(%s) error = %v", name, err)
		}
		if _, err := w.Write(payloadData); err != nil {
			t.Fatalf("Write(%s) error = %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipData.Bytes()), int64(zipData.Len()))
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	return zr
}

func makeEncryptedKernelPayload(t *testing.T, plaintext, iv, key []byte) []byte {
	t.Helper()

	payload, err := img4.CreatePayload(&img4.CreatePayloadConfig{
		Type:        img4.IM4P_KERNELCACHE,
		Version:     "KernelCacheBuilder-test",
		Data:        plaintext,
		Compression: "lzss",
		Keybags: []img4.Keybag{
			{
				Type: img4.PRODUCTION,
				IV:   iv,
				Key:  key,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}
	if rem := len(payload.Data) % aes.BlockSize; rem != 0 {
		payload.Data = append(payload.Data, bytes.Repeat([]byte{0}, aes.BlockSize-rem)...)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(payload.Data, payload.Data)

	data, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return data
}

func makeUnencryptedKernelPayload(t *testing.T, plaintext []byte) []byte {
	t.Helper()

	payload, err := img4.CreatePayload(&img4.CreatePayloadConfig{
		Type:        img4.IM4P_KERNELCACHE,
		Version:     "KernelCacheBuilder-test",
		Data:        plaintext,
		Compression: "lzss",
	})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}
	data, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return data
}

func testKernelInfo(kernelPaths ...string) *info.Info {
	identities := make([]plist.BuildIdentity, 0, len(kernelPaths))
	for _, kernelPath := range kernelPaths {
		identities = append(identities, testKernelBuildIdentity(boardIDForKernelPath(kernelPath), kernelPath))
	}
	return &info.Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				SupportedProductTypes: []string{"iPhone8,2"},
				BuildIdentities:       identities,
			},
		},
	}
}

func boardIDForKernelPath(kernelPath string) string {
	switch {
	case strings.HasSuffix(kernelPath, ".n66m"):
		return "n66map"
	case strings.HasSuffix(kernelPath, ".n66"):
		return "n66ap"
	default:
		return filepath.Base(kernelPath)
	}
}

func testKernelBuildIdentity(deviceClass, kernelPath string) plist.BuildIdentity {
	return plist.BuildIdentity{
		Info: plist.IdentityInfo{
			DeviceClass: deviceClass,
		},
		Manifest: map[string]plist.IdentityManifest{
			"KernelCache": {
				Info: map[string]any{
					"Path": kernelPath,
				},
			},
		},
	}
}
