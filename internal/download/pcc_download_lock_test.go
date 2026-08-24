//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package download

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blacktop/ipsw/internal/download/pcc"
)

func TestPCCAssetRequestIncludesSHA256(t *testing.T) {
	digest := sha256.Sum256([]byte("synthetic PCC asset"))
	asset := &pcc.ReleaseMetadata_Asset{
		Type: pcc.ReleaseMetadata_ASSET_TYPE_MODEL,
		Url:  "https://example.invalid/model.aar",
		Digest: &pcc.ReleaseMetadata_Digest{
			DigestAlg: pcc.ReleaseMetadata_DIGEST_ALG_SHA256,
			Value:     digest[:],
		},
	}
	request, err := pccAssetRequest(asset, "/tmp/model.aar")
	if err != nil {
		t.Fatal(err)
	}
	if request.URL != asset.Url || request.DestName != "/tmp/model.aar" {
		t.Fatalf("request routing = %#v", request)
	}
	if request.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("request SHA-256 = %q, want %x", request.SHA256, digest)
	}
}

func TestPCCAssetRequestRejectsUnsupportedDigest(t *testing.T) {
	asset := &pcc.ReleaseMetadata_Asset{
		Type: pcc.ReleaseMetadata_ASSET_TYPE_MODEL,
		Digest: &pcc.ReleaseMetadata_Digest{
			DigestAlg: pcc.ReleaseMetadata_DIGEST_ALG_SHA384,
			Value:     bytes.Repeat([]byte{0x42}, 48),
		},
	}
	if _, err := pccAssetRequest(asset, "/tmp/model.aar"); err == nil {
		t.Fatal("pccAssetRequest accepted an unsupported digest")
	}
}

func TestPCCDownloadContextVerifiesSHA256(t *testing.T) {
	payload := []byte("synthetic PCC asset")
	wrongDigest := sha256.Sum256([]byte("different asset"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "model.aar", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	release := &PCCRelease{
		Index: 1,
		ReleaseMetadata: pcc.ReleaseMetadata{Assets: []*pcc.ReleaseMetadata_Asset{{
			Type: pcc.ReleaseMetadata_ASSET_TYPE_MODEL,
			Url:  server.URL + "/model.aar",
			Digest: &pcc.ReleaseMetadata_Digest{
				DigestAlg: pcc.ReleaseMetadata_DIGEST_ALG_SHA256,
				Value:     wrongDigest[:],
			},
		}}},
	}
	output := t.TempDir()
	err := release.DownloadContext(t.Context(), output, "", false, false, false)
	if err == nil {
		t.Fatal("DownloadContext accepted an asset with the wrong SHA-256")
	}
	if _, statErr := os.Stat(filepath.Join(output, "MODEL.aar")); !os.IsNotExist(statErr) {
		t.Fatalf("destination stat error = %v, want failed download to remain unfinalized", statErr)
	}
}

func TestPCCDownloadContextHonorsSkipAndRestart(t *testing.T) {
	payload := []byte("synthetic PCC asset")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "model.aar", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	release := &PCCRelease{
		Index: 1,
		ReleaseMetadata: pcc.ReleaseMetadata{Assets: []*pcc.ReleaseMetadata_Asset{{
			Type: pcc.ReleaseMetadata_ASSET_TYPE_MODEL,
			Url:  server.URL + "/model.aar",
			Digest: &pcc.ReleaseMetadata_Digest{
				DigestAlg: pcc.ReleaseMetadata_DIGEST_ALG_SHA256,
				Value:     bytes.Repeat([]byte{0x42}, 32),
			},
		}}},
	}
	output := t.TempDir()
	destName := filepath.Join(output, "MODEL.aar")
	lockDownloadStage(t, destName)

	if err := release.DownloadContext(t.Context(), output, "", false, true, false); err != nil {
		t.Fatalf("DownloadContext() with skip-all error = %v, want nil", err)
	}
	if err := release.DownloadContext(t.Context(), output, "", false, true, true); err != nil {
		t.Fatalf("DownloadContext() with skip-all and restart-all error = %v, want nil", err)
	}
	if _, err := os.Stat(destName); !os.IsNotExist(err) {
		t.Fatalf("destination stat error = %v, want absent while stage is locked", err)
	}
	if _, err := os.Stat(filepath.Join(output, "instance.plist")); !os.IsNotExist(err) {
		t.Fatalf("instance.plist stat error = %v, want absent while an asset is locked", err)
	}
}
