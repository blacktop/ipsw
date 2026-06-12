package device

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetDDIInfoPreservesExplicitDDIFolderWithManifestPath(t *testing.T) {
	tmp := t.TempDir()
	ddiFolder := filepath.Join(tmp, "iOS_DDI")
	restoreDir := filepath.Join(ddiFolder, "Restore")
	manifestDir := filepath.Join(tmp, "manifest")

	if err := os.MkdirAll(restoreDir, 0o750); err != nil {
		t.Fatalf("failed to create DDI restore directory: %v", err)
	}
	if err := os.MkdirAll(manifestDir, 0o750); err != nil {
		t.Fatalf("failed to create manifest directory: %v", err)
	}

	imagePath := filepath.Join(restoreDir, "DeveloperDiskImage.dmg")
	if err := os.WriteFile(imagePath, []byte("image"), 0o644); err != nil {
		t.Fatalf("failed to write DDI image: %v", err)
	}
	signaturePath := filepath.Join(tmp, "DeveloperDiskImage.dmg.signature")
	if err := os.WriteFile(signaturePath, []byte("signature"), 0o644); err != nil {
		t.Fatalf("failed to write DDI signature: %v", err)
	}

	manifestPath := filepath.Join(manifestDir, "BuildManifest.plist")
	if err := os.WriteFile(manifestPath, []byte(minimalDDIBuildManifest), 0o644); err != nil {
		t.Fatalf("failed to write BuildManifest.plist: %v", err)
	}

	cfg := &DDIConfig{
		ImageType:     "Personalized",
		DDIFolder:     ddiFolder,
		SignaturePath: signaturePath,
		ManifestPath:  manifestPath,
	}
	info, err := GetDDIInfo(cfg)
	if err != nil {
		t.Fatalf("GetDDIInfo() error = %v", err)
	}
	if err := info.Verify(); err != nil {
		t.Fatalf("DDIInfo.Verify() error = %v", err)
	}

	if cfg.DDIFolder != ddiFolder {
		t.Fatalf("DDIFolder = %q, want %q", cfg.DDIFolder, ddiFolder)
	}
	if cfg.DDIDmgPath != imagePath {
		t.Fatalf("DDIDmgPath = %q, want %q", cfg.DDIDmgPath, imagePath)
	}
	if info.ManifestPath != manifestPath {
		t.Fatalf("ManifestPath = %q, want %q", info.ManifestPath, manifestPath)
	}

	wantTrustcache := filepath.Join(restoreDir, "DeveloperDiskImage.trustcache")
	if info.TrustcachePath != wantTrustcache {
		t.Fatalf("TrustcachePath = %q, want %q", info.TrustcachePath, wantTrustcache)
	}
}

const minimalDDIBuildManifest = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BuildIdentities</key>
	<array>
		<dict>
			<key>Manifest</key>
			<dict>
				<key>LoadableTrustCache</key>
				<dict>
					<key>Info</key>
					<dict>
						<key>Path</key>
						<string>DeveloperDiskImage.trustcache</string>
					</dict>
				</dict>
				<key>PersonalizedDMG</key>
				<dict>
					<key>Info</key>
					<dict>
						<key>Path</key>
						<string>DeveloperDiskImage.dmg</string>
					</dict>
				</dict>
			</dict>
		</dict>
	</array>
</dict>
</plist>`
