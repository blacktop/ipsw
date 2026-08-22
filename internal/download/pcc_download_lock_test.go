//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package download

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blacktop/ipsw/internal/download/pcc"
)

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
