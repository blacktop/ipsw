package diff

import (
	"encoding/gob"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/blacktop/ipsw/pkg/plist"
)

func TestUnsupportedFlagsForOTAMode(t *testing.T) {
	tests := []struct {
		name     string
		conf     Config
		expected []string
	}{
		{
			name:     "no flags",
			conf:     Config{},
			expected: nil,
		},
		{
			name:     "low-memory blocked",
			conf:     Config{LowMemory: true},
			expected: []string{"--low-memory"},
		},
		{
			name: "now-supported flags not blocked",
			conf: Config{
				LaunchD:      true,
				Firmware:     true,
				Features:     true,
				Entitlements: true,
				Files:        true,
				Sandbox:      true,
				CStrings:     true,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unsupportedFlagsForOTAMode(&tt.conf)
			if len(got) != len(tt.expected) {
				t.Fatalf(
					"got %v, want %v", got, tt.expected,
				)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf(
						"got[%d] = %q, want %q",
						i, got[i], tt.expected[i],
					)
				}
			}
		})
	}
}

func TestUnsupportedFlagsForDirectoryMode(t *testing.T) {
	tests := []struct {
		name     string
		conf     Config
		expected []string
	}{
		{
			name:     "no flags",
			conf:     Config{},
			expected: nil,
		},
		{
			name:     "launchd blocked",
			conf:     Config{LaunchD: true},
			expected: []string{"--launchd"},
		},
		{
			name:     "low-memory blocked",
			conf:     Config{LowMemory: true},
			expected: []string{"--low-memory"},
		},
		{
			name:     "sandbox blocked",
			conf:     Config{Sandbox: true},
			expected: []string{"--sandbox"},
		},
		{
			name: "supported flags not blocked",
			conf: Config{
				Files:        true,
				Features:     true,
				Entitlements: true,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unsupportedFlagsForDirectoryMode(&tt.conf)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %v, want %v", got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestLaunchdConfigFromRootsPrefersSbinLaunchd(t *testing.T) {
	tmpDir := t.TempDir()
	sbinDir := filepath.Join(tmpDir, "sbin")
	if err := os.MkdirAll(sbinDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	launchdPath := filepath.Join(sbinDir, "launchd")
	if err := os.WriteFile(launchdPath, []byte("not-a-macho"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := launchdConfigFromRoots([]string{tmpDir})
	if err == nil {
		t.Fatal("expected error for invalid launchd binary")
	}
	if !strings.Contains(err.Error(), launchdPath) && !strings.Contains(err.Error(), "launchd") {
		t.Fatalf("error = %q, want mention of launchd path", err)
	}
}

func TestOTALaunchdSearchRootsIncludesPayloadAndMounts(t *testing.T) {
	ctx := &Context{
		payloadRoot: "/tmp/payload",
		Mount: map[string]mount{
			"SystemOS": {MountPath: "/tmp/system"},
			"AppOS":    {MountPath: "/tmp/app"},
		},
	}

	got := otaLaunchdSearchRoots(ctx)
	want := []string{"/tmp/payload", "/tmp/app", "/tmp/system"}
	if len(got) != len(want) {
		t.Fatalf("roots = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("roots[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestValidateOTAScope(t *testing.T) {
	tests := []struct {
		name    string
		info    *info.Info
		wantErr bool
		errMsg  string
	}{
		{
			name: "full OTA passes",
			info: &info.Info{
				Plists: &plist.Plists{
					OTAInfo: &plist.OTAInfo{
						MobileAssetProperties: types.Asset{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "nil OTAInfo passes",
			info: &info.Info{
				Plists: &plist.Plists{},
			},
			wantErr: false,
		},
		{
			name: "partial OTA rejected",
			info: &info.Info{
				Plists: &plist.Plists{
					OTAInfo: &plist.OTAInfo{
						MobileAssetProperties: types.Asset{
							PrerequisiteBuild: "22A5282m",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "partial/delta OTA detected",
		},
		{
			name: "RSR OTA rejected",
			info: &info.Info{
				Plists: &plist.Plists{
					OTAInfo: &plist.OTAInfo{
						MobileAssetProperties: types.Asset{
							SplatOnly: true,
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "RSR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOTAScope(tt.info)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" {
					if !strings.Contains(
						err.Error(), tt.errMsg,
					) {
						t.Errorf(
							"error %q should contain %q",
							err.Error(), tt.errMsg,
						)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigureOTAContextFallbackFolderIncludesProduct(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := &Context{}
	inf := &info.Info{
		Plists: &plist.Plists{
			AssetDataInfo: &plist.AssetDataInfo{
				ProductVersion: "26.5",
				Build:          "23F5043k",
				ProductType:    "iPhone18,1",
			},
		},
	}

	configureOTAContext(ctx, inf, tmpDir)

	if ctx.InputMode != inputModeOTA {
		t.Fatalf("InputMode = %v, want %v", ctx.InputMode, inputModeOTA)
	}
	if ctx.Version != "26.5" {
		t.Fatalf("Version = %q, want %q", ctx.Version, "26.5")
	}
	if ctx.Build != "23F5043k" {
		t.Fatalf("Build = %q, want %q", ctx.Build, "23F5043k")
	}

	wantFolder := filepath.Join(tmpDir, "23F5043k__iPhone18,1")
	if ctx.Folder != wantFolder {
		t.Fatalf("Folder = %q, want %q", ctx.Folder, wantFolder)
	}
}

func TestIsMacOSOTAFallsBackToProductSystemName(t *testing.T) {
	tests := []struct {
		name string
		info *info.Info
		want bool
	}{
		{
			name: "macOS OTA without BuildManifest",
			info: &info.Info{
				Plists: &plist.Plists{
					OTAInfo: &plist.OTAInfo{
						MobileAssetProperties: types.Asset{
							ProductSystemName: "macOS",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "non-macOS OTA without BuildManifest",
			info: &info.Info{
				Plists: &plist.Plists{
					OTAInfo: &plist.OTAInfo{
						MobileAssetProperties: types.Asset{
							ProductSystemName: "iOS",
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMacOSOTA(tt.info); got != tt.want {
				t.Fatalf("isMacOSOTA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectFeatureFlagsFromMountsSkipsMissingMountDirs(t *testing.T) {
	tmpDir := t.TempDir()
	systemRoot := filepath.Join(tmpDir, "system")
	featureDir := filepath.Join(systemRoot, "System", "Library", "FeatureFlags", "Domain")
	if err := os.MkdirAll(featureDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	featurePath := filepath.Join(featureDir, "SoftwareUpdate.plist")
	wantContent := "<plist>system</plist>"
	if err := os.WriteFile(featurePath, []byte(wantContent), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	mounts := map[string]mount{
		"AppOS": {
			MountPath: filepath.Join(tmpDir, "app-missing"),
		},
		"SystemOS": {
			MountPath: systemRoot,
		},
	}

	out := make(map[string]string)
	if err := collectFeatureFlagsFromMounts(mounts, out); err != nil {
		t.Fatalf("collectFeatureFlagsFromMounts() error = %v", err)
	}

	got, ok := out[filepath.Join("Domain", "SoftwareUpdate.plist")]
	if !ok {
		t.Fatalf("expected extracted FeatureFlags entry, got map=%v", out)
	}
	if got != wantContent {
		t.Fatalf("FeatureFlags content = %q, want %q", got, wantContent)
	}
}

func TestDetectInputMode(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two temp directories.
	dir1 := filepath.Join(tmpDir, "dir1")
	dir2 := filepath.Join(tmpDir, "dir2")
	os.MkdirAll(dir1, 0o755)
	os.MkdirAll(dir2, 0o755)

	// Create two temp files (non-directories).
	file1 := filepath.Join(tmpDir, "file1.ipsw")
	file2 := filepath.Join(tmpDir, "file2.ipsw")
	os.WriteFile(file1, []byte("PK\x03\x04fake"), 0o644)
	os.WriteFile(file2, []byte("PK\x03\x04fake"), 0o644)

	tests := []struct {
		name     string
		old, new string
		wantMode inputMode
		wantErr  bool
	}{
		{
			name:     "both directories",
			old:      dir1,
			new:      dir2,
			wantMode: inputModeDirectory,
		},
		{
			name:     "both files (IPSW default)",
			old:      file1,
			new:      file2,
			wantMode: inputModeIPSW,
		},
		{
			name:    "mixed dir and file",
			old:     dir1,
			new:     file1,
			wantErr: true,
		},
		{
			name:    "nonexistent old",
			old:     filepath.Join(tmpDir, "nope"),
			new:     file1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := detectInputMode(tt.old, tt.new)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tt.wantMode {
				t.Errorf(
					"got mode %d, want %d",
					mode, tt.wantMode,
				)
			}
		})
	}
}

func TestSaveRoundtripWithOTAMode(t *testing.T) {
	tmpDir := t.TempDir()

	d := &Diff{
		Title: "OTA Test",
		Old: Context{
			InputMode: inputModeOTA,
			Version:   "18.4",
			Build:     "22E5230e",
			// otaFile is nil (already closed) — gob must not panic.
		},
		New: Context{
			InputMode: inputModeOTA,
			Version:   "18.4",
			Build:     "22E5246b",
		},
		conf: &Config{Output: tmpDir},
	}

	gob.Register([]any{})
	gob.Register(map[string]any{})

	if err := d.Save(); err != nil {
		t.Fatalf("Save() with OTA mode failed: %v", err)
	}

	// Verify the file was created.
	outPath := filepath.Join(tmpDir, d.TitleToFilename()+".idiff")
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected .idiff file at %s: %v", outPath, err)
	}
}

func TestTryOpenOTARejectsIPSW(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal zip file pretending to be an IPSW.
	ipswPath := filepath.Join(tmpDir, "test.ipsw")
	os.WriteFile(ipswPath, []byte("PK\x03\x04fake"), 0o644)

	conf := &Config{}
	o, inf, err := tryOpenOTA(ipswPath, conf)
	if err != nil {
		t.Fatalf("expected nil error for .ipsw, got: %v", err)
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle for .ipsw file")
	}
}

func TestTryOpenOTARejectsDMG(t *testing.T) {
	tmpDir := t.TempDir()

	// Test .dmg extension.
	dmgPath := filepath.Join(tmpDir, "test.dmg")
	os.WriteFile(dmgPath, []byte("fake"), 0o644)

	conf := &Config{}
	o, inf, err := tryOpenOTA(dmgPath, conf)
	if err != nil {
		t.Fatalf("expected nil error for .dmg, got: %v", err)
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle for .dmg file")
	}

	// Test numeric DMG payload name.
	payloadPath := filepath.Join(
		tmpDir, "090-43228-337.dmg.aea",
	)
	os.WriteFile(payloadPath, []byte("fake"), 0o644)

	o, inf, err = tryOpenOTA(payloadPath, conf)
	if err != nil {
		t.Fatalf(
			"expected nil error for DMG payload, got: %v", err,
		)
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle for DMG payload name")
	}
}

func TestTryOpenOTANonexistentFile(t *testing.T) {
	conf := &Config{}
	o, inf, err := tryOpenOTA("/nonexistent/path.ota", conf)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle for nonexistent file")
	}
}

func TestTryOpenOTAAEAMagicPropagatesError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with valid AEA magic but truncated/invalid
	// content. ota.Open should fail to decrypt, and since the
	// file has AEA magic, tryOpenOTA must propagate the error
	// rather than silently downgrading to "not an OTA".
	aeaPath := filepath.Join(tmpDir, "test.ota")
	// AEA1 magic: 0x41 0x45 0x41 0x31 (big-endian)
	aeaData := []byte{0x41, 0x45, 0x41, 0x31}
	// Pad with garbage to avoid trivial short-read rejections.
	aeaData = append(aeaData, make([]byte, 256)...)
	os.WriteFile(aeaPath, aeaData, 0o644)

	conf := &Config{}
	o, inf, err := tryOpenOTA(aeaPath, conf)
	if err == nil {
		// If handle was returned, close it to avoid leak.
		if o != nil {
			o.Close()
		}
		t.Fatal(
			"expected error for AEA file with invalid " +
				"content, got nil — decryption failure " +
				"should propagate, not be swallowed",
		)
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle on error")
	}
	// Verify error mentions the key flags.
	if !strings.Contains(err.Error(), "--key-db") &&
		!strings.Contains(err.Error(), "failed to open") {
		t.Errorf(
			"error should mention key flags or open failure, "+
				"got: %v", err,
		)
	}
}

func TestTryOpenOTAAAMagicPropagatesError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with valid YAA1 magic (little-endian:
	// 0x59 0x41 0x41 0x31) but invalid content.
	aaPath := filepath.Join(tmpDir, "test.ota")
	// YAA1 = 0x31414159 little-endian = bytes Y A A 1
	aaData := []byte{0x59, 0x41, 0x41, 0x31}
	aaData = append(aaData, make([]byte, 256)...)
	os.WriteFile(aaPath, aaData, 0o644)

	conf := &Config{}
	o, inf, err := tryOpenOTA(aaPath, conf)
	if err == nil {
		if o != nil {
			o.Close()
		}
		t.Fatal(
			"expected error for AA file with invalid " +
				"content, got nil — parse failure should " +
				"propagate for AA-magic files",
		)
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle on error")
	}
}

func TestTryOpenOTAZipNonOTASilentMiss(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with ZIP magic but obviously not a real
	// ZIP (let alone an OTA). For ZIP-magic files, tryOpenOTA
	// should downgrade to nil, nil, nil — not propagate.
	zipPath := filepath.Join(tmpDir, "test.zip")
	// ZIP magic: PK\x03\x04
	zipData := []byte{0x50, 0x4b, 0x03, 0x04}
	zipData = append(zipData, make([]byte, 256)...)
	os.WriteFile(zipPath, zipData, 0o644)

	conf := &Config{}
	o, inf, err := tryOpenOTA(zipPath, conf)
	if err != nil {
		t.Fatalf(
			"expected silent miss for non-OTA ZIP, got: %v",
			err,
		)
	}
	if o != nil || inf != nil {
		t.Fatal("expected nil handle for non-OTA ZIP")
	}
}

func TestLookupAEAKeyUsesArchiveStemFromDownloadedFilename(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "keys.json")
	data := `[{"filename":"e42aba0a3cb6684dc58eeef17d40bcdf987637c551987afd433ae1b31b1665f3.aea","key":"db-key"}]`
	if err := os.WriteFile(dbPath, []byte(data), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	otaPath := filepath.Join(tmpDir, "iPhone18,1_23F5054h_e42aba0a3cb6684dc58eeef17d40bcdf987637c551987afd433ae1b31b1665f3.aea")
	key, err := lookupAEAKey(otaPath, dbPath)
	if err != nil {
		t.Fatalf("lookupAEAKey() error = %v", err)
	}
	if key != "db-key" {
		t.Fatalf("lookupAEAKey() = %q, want %q", key, "db-key")
	}
}
