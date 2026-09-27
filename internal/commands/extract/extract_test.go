package extract

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestRemoteKeybagsStoredPayloadUsesSmallRanges(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	keybag, err := asn1.Marshal([]img4.Keybag{{Type: img4.PRODUCTION, IV: bytes.Repeat([]byte{0x11}, 16), Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := asn1.Marshal(img4.IM4P{
		Tag: "IM4P", Type: "test", Version: "synthetic", Data: bytes.Repeat([]byte{0x55}, 2<<20), Keybag: keybag,
	})
	if err != nil {
		t.Fatal(err)
	}
	c, transferred := exclaveTestSource(t, exclaveTestArchive(t, payload), true)
	defer c.Close()
	c.Pattern = `exclavecore_bundle\.runtime\.im4p$`
	c.JSON = true
	out, err := Keybags(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, hex.EncodeToString(key)) {
		t.Fatalf("keybag missing from output: %s", out)
	}
	if got := transferred.Load(); got >= 512<<10 {
		t.Fatalf("metadata lookup read %d bytes for a 2 MiB stored payload", got)
	}
}

func TestSearchHonorsTemporaryDirectory(t *testing.T) {
	data := exclaveTestArchive(t, []byte("synthetic firmware"))
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "remote"}[remote], func(t *testing.T) {
			c, _ := exclaveTestSource(t, data, remote)
			defer c.Close()
			c.Pattern = `exclavecore_bundle\.runtime\.im4p$`
			c.Output = filepath.Join(t.TempDir(), "output")
			staging := t.TempDir()
			out, err := Search(c, staging)
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(staging, "Firmware/exclavecore_bundle.runtime.im4p")
			if len(out) != 1 || out[0] != want {
				t.Fatalf("artifacts = %v, want [%s]", out, want)
			}
			if _, err := os.Stat(c.Output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output directory created: %v", err)
			}
		})
	}
}

func TestExclaveSelectsBeforeExtractingAndCleansInfoStaging(t *testing.T) {
	config, err := asn1.Marshal(bundle.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var bund bytes.Buffer
	for _, header := range []any{
		bundle.Header{Magic: [4]byte{'D', 'N', 'U', 'B'}, Type: 3},
		bundle.Type3{FooterOffset: uint64(len(config)), FooterSz: uint64(len(config))},
	} {
		if err := binary.Write(&bund, binary.LittleEndian, header); err != nil {
			t.Fatal(err)
		}
	}
	bund.Write(config)
	valid, err := asn1.Marshal(img4.IM4P{Tag: "IM4P", Type: "excl", Version: "synthetic", Data: bund.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	for _, remote := range []bool{false, true} {
		for _, malformed := range []bool{false, true} {
			name := map[bool]string{false: "local", true: "remote"}[remote] + map[bool]string{false: "/valid", true: "/malformed"}[malformed]
			t.Run(name, func(t *testing.T) {
				payload := valid
				if malformed {
					payload = []byte("invalid payload")
				}
				archive := exclaveTestArchive(t, payload)
				c, transferred := exclaveTestSource(t, archive, remote)
				defer c.Close()
				staging := t.TempDir()
				t.Setenv("TMPDIR", staging)
				c.Output = filepath.Join(t.TempDir(), "output")
				c.Info = true
				_, err := Exclave(c)
				if (err != nil) != malformed {
					t.Fatalf("error = %v, malformed = %v", err, malformed)
				}
				if _, err := os.Stat(c.Output); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("output directory created: %v", err)
				}
				entries, err := os.ReadDir(staging)
				if err != nil || len(entries) != 0 {
					t.Fatalf("temporary files remain: %v, %v", entries, err)
				}
				if remote && transferred.Load() >= int64(len(archive)/2) {
					t.Fatalf("read %d of %d archive bytes; restore bundle should be skipped", transferred.Load(), len(archive))
				}
			})
		}
	}
}

func TestSelectExclaveBundlesDefault(t *testing.T) {
	files := []*zip.File{
		{FileHeader: zip.FileHeader{Name: "Firmware/exclavecore_bundle.restore.im4p"}},
		{FileHeader: zip.FileHeader{Name: "Firmware/exclavecore_bundle.runtime.im4p"}},
		{FileHeader: zip.FileHeader{Name: "Firmware/other.im4p"}},
	}
	got, err := selectExclaveBundles(files, false)
	if err != nil || !reflect.DeepEqual(got, []string{files[1].Name}) {
		t.Fatalf("selection = %v, %v", got, err)
	}
	if _, err := selectExclaveBundles(files[:1], false); err == nil || !strings.Contains(err.Error(), "all 1 matches are restore") {
		t.Fatalf("restore-only selection error = %v", err)
	}
	if _, err := selectExclaveBundles(files[2:], false); err == nil || !strings.Contains(err.Error(), "no Exclave bundles found") {
		t.Fatalf("no-match selection error = %v", err)
	}
}

func TestExclaveRetainsSavedBundleOnCoreFailure(t *testing.T) {
	data := []byte("synthetic invalid bundle")
	payload, err := asn1.Marshal(img4.IM4P{Tag: "IM4P", Type: "excl", Version: "synthetic", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := exclaveTestSource(t, exclaveTestArchive(t, payload), false)
	defer c.Close()
	c.Output = t.TempDir()
	out, err := Exclave(c)
	if err == nil || !strings.Contains(err.Error(), "failed to extract files from exclave bundle") {
		t.Fatalf("expected core extraction failure, got %v", err)
	}
	want := filepath.Join(c.Output, "exclavecore_bundle.runtime")
	if len(out) != 1 || out[0] != want {
		t.Fatalf("completed bundle omitted: paths = %v, want [%s]", out, want)
	}
	saved, err := os.ReadFile(want)
	if err != nil || !bytes.Equal(saved, data) {
		t.Fatalf("reported bundle is not complete: bytes = %q, error = %v", saved, err)
	}
}

func exclaveTestArchive(t *testing.T, runtime []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"BuildManifest.plist", []byte(`<plist version="1.0"><dict><key>ProductVersion</key><string>99.0</string><key>ProductBuildVersion</key><string>99A1</string><key>SupportedProductTypes</key><array><string>iPhone99,1</string></array></dict></plist>`)},
		{"Restore.plist", []byte(`<plist version="1.0"><dict><key>SupportedProductTypes</key><array><string>iPhone99,1</string></array></dict></plist>`)},
		{"Firmware/exclavecore_bundle.runtime.im4p", runtime},
		// A large STORE member makes unintended restore downloads measurable.
		{"Firmware/exclavecore_bundle.restore.im4p", bytes.Repeat([]byte("restore"), 1<<20)},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

type countingZipResponse struct {
	http.ResponseWriter
	count *atomic.Int64
}

func (w countingZipResponse) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.count.Add(int64(n))
	return n, err
}

func exclaveTestSource(t *testing.T, data []byte, remote bool) (*Config, *atomic.Int64) {
	t.Helper()
	transferred := new(atomic.Int64)
	if remote {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"synthetic-exclave"`)
			http.ServeContent(countingZipResponse{w, transferred}, r, "synthetic.ipsw", time.Time{}, bytes.NewReader(data))
		}))
		t.Cleanup(server.Close)
		return &Config{URL: server.URL + "/synthetic.ipsw"}, transferred
	}
	path := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return &Config{IPSW: path}, transferred
}

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

func TestRemoteZipReaderCacheResetsWhenURLChanges(t *testing.T) {
	first := newRemoteZipServer(t, "first.txt")
	second := newRemoteZipServer(t, "second.txt")

	c := &Config{URL: first.URL}
	zr, err := c.remoteZipReader(download.DefaultRemoteZipBlockSize)
	if err != nil {
		t.Fatalf("remoteZipReader(first) error = %v", err)
	}
	if got, want := zr.File[0].Name, "first.txt"; got != want {
		t.Fatalf("first reader member = %q, want %q", got, want)
	}

	c.URL = second.URL
	zr, err = c.remoteZipReader(download.DefaultRemoteZipBlockSize)
	if err != nil {
		t.Fatalf("remoteZipReader(second) error = %v", err)
	}
	if got, want := zr.File[0].Name, "second.txt"; got != want {
		t.Fatalf("second reader member = %q, want %q", got, want)
	}
}

func newRemoteZipServer(t *testing.T, name string) *httptest.Server {
	t.Helper()

	var zipData bytes.Buffer
	zw := zip.NewWriter(&zipData)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("Create(%s) error = %v", name, err)
	}
	if _, err := w.Write([]byte(name)); err != nil {
		t.Fatalf("Write(%s) error = %v", name, err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	data := append([]byte(nil), zipData.Bytes()...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+name+`"`)
		http.ServeContent(w, r, "payload.zip", time.Unix(0, 0), bytes.NewReader(data))
	}))
	t.Cleanup(server.Close)
	return server
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

// resolvedDscStep pairs a planned step's resolved remote DMG path with its
// arches, mirroring what the remote DSC loop feeds extractRemoteDscDMG.
type resolvedDscStep struct {
	dmgPath    string
	arches     []string
	allowEmpty bool
}

func TestRemoteDscPlanRouting(t *testing.T) {
	tests := []struct {
		name        string
		info        *info.Info
		arches      []string
		driverKit   bool
		want        []resolvedDscStep
		wantErr     bool
		errContains string
	}{
		{
			name:   "macOS 27 routes rosetta arches to rosetta dmg",
			info:   testDscInfo(true, "27.0"),
			arches: []string{"arm64e", "x86_64"},
			want: []resolvedDscStep{
				{dmgPath: "system.dmg.aea", arches: []string{"arm64e"}},
				{dmgPath: "rosetta.dmg", arches: []string{"x86_64"}},
			},
		},
		{
			name:   "macOS 27 default arches cover both dmgs",
			info:   testDscInfo(true, "27.0"),
			arches: nil,
			want: []resolvedDscStep{
				{dmgPath: "system.dmg.aea"},
				{dmgPath: "rosetta.dmg"},
			},
		},
		{
			name:      "macOS 27 driverkit default treats rosetta as best effort",
			info:      testDscInfo(true, "27.0"),
			driverKit: true,
			want: []resolvedDscStep{
				{dmgPath: "system.dmg.aea", allowEmpty: true},
				{dmgPath: "rosetta.dmg", allowEmpty: true},
			},
		},
		{
			name:   "x86 stays in system os when rosetta is missing pre-27",
			info:   testDscInfo(false),
			arches: []string{"x86_64"},
			want:   []resolvedDscStep{{dmgPath: "system.dmg.aea", arches: []string{"x86_64"}}},
		},
		{
			name:   "manifest rosetta dmg routes x86 before macOS 27",
			info:   testDscInfo(true, "26.5"),
			arches: []string{"x86_64"},
			want:   []resolvedDscStep{{dmgPath: "rosetta.dmg", arches: []string{"x86_64"}}},
		},
		{
			name: "manifest rosetta dmg joins default picker before macOS 27",
			info: testDscInfo(true, "26.5"),
			want: []resolvedDscStep{
				{dmgPath: "system.dmg.aea"},
				{dmgPath: "rosetta.dmg"},
			},
		},
		{
			name:   "macOS 27 arm-only ignores malformed rosetta metadata",
			info:   testDscInfoWithConflictingRosetta(),
			arches: []string{"arm64e"},
			want:   []resolvedDscStep{{dmgPath: "system.dmg.aea", arches: []string{"arm64e"}}},
		},
		{
			name:    "macOS 27 x86 without rosetta dmg fails",
			info:    testDscInfo(false, "27.0"),
			arches:  []string{"x86_64"},
			wantErr: true,
		},
		{
			name:        "macOS 27 with conflicting rosetta dmgs fails instead of treating rosetta as absent",
			info:        testDscInfoWithConflictingRosetta(),
			arches:      []string{"x86_64"},
			wantErr:     true,
			errContains: "failed to determine RosettaOS DMG availability",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			steps, err := dyld.DscExtractionPlan(test.info, test.arches, test.driverKit)
			if test.wantErr {
				if err == nil {
					t.Fatal("DscExtractionPlan() error = nil, want error")
				}
				if test.errContains != "" && !strings.Contains(err.Error(), test.errContains) {
					t.Fatalf("DscExtractionPlan() error = %q, want it to contain %q", err, test.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("DscExtractionPlan() error = %v", err)
			}
			got := make([]resolvedDscStep, 0, len(steps))
			for _, step := range steps {
				dmgPath, err := remoteDmgPathForDscStep(test.info, step.Kind)
				if err != nil {
					t.Fatalf("remoteDmgPathForDscStep(%q) error = %v", step.Kind, err)
				}
				got = append(got, resolvedDscStep{dmgPath: dmgPath, arches: step.Arches, allowEmpty: step.AllowEmpty})
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("resolved steps = %#v, want %#v", got, test.want)
			}
		})
	}
}

func testDscInfo(hasRosetta bool, version ...string) *info.Info {
	manifest := map[string]plist.IdentityManifest{
		"Cryptex1,SystemOS": {
			Info: map[string]any{"Path": "system.dmg.aea"},
		},
	}
	if hasRosetta {
		manifest["Cryptex1,RosettaOS"] = plist.IdentityManifest{
			Info: map[string]any{"Path": "rosetta.dmg"},
		}
	}
	productVersion := "26.0"
	if len(version) > 0 {
		productVersion = version[0]
	}
	return &info.Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				ProductVersion:        productVersion,
				SupportedProductTypes: []string{"Mac17,1"},
				BuildIdentities: []plist.BuildIdentity{
					{Manifest: manifest},
				},
			},
		},
	}
}

func testDscInfoWithConflictingRosetta() *info.Info {
	i := testDscInfo(true, "27.0")
	i.Plists.BuildManifest.BuildIdentities = append(i.Plists.BuildManifest.BuildIdentities,
		plist.BuildIdentity{Manifest: map[string]plist.IdentityManifest{
			"Cryptex1,RosettaOS": {Info: map[string]any{"Path": "rosetta-other.dmg"}},
		}})
	return i
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
