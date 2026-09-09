package syms

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gin-gonic/gin"
)

func TestSymbolScanRoutesRejectPartialGraphs(t *testing.T) {
	var data bytes.Buffer
	zw := zip.NewWriter(&data)
	manifest := `<plist version="1.0"><dict><key>SupportedProductTypes</key><array><string>Mac99,1</string><string>Mac99,2</string></array><key>BuildIdentities</key><array>`
	for idx := 1; idx <= 2; idx++ {
		manifest += fmt.Sprintf(`<dict><key>Ap,ProductType</key><string>Mac99,%d</string><key>Info</key><dict><key>DeviceClass</key><string>j99%dap</string></dict><key>Manifest</key><dict><key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>missing-%d.dmg</string></dict></dict></dict></dict>`, idx, idx, idx)
	}
	manifest += `</array></dict></plist>`
	w, err := zw.Create("BuildManifest.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "synthetic.ipsw")
	if err := os.WriteFile(archive, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	sha, err := utils.Sha1(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, device := range []string{"", "Mac99,2", "J992AP", "unknown"} {
			t.Run(method+"/"+device, func(t *testing.T) {
				database := &db.Memory{IPSWs: make(map[string]*model.Ipsw)}
				existing := &model.Ipsw{ID: sha, Name: "original graph"}
				path := "/syms/scan"
				if method == http.MethodPut {
					path = "/syms/rescan"
					database.IPSWs[sha] = existing
				}
				router := gin.New()
				AddRoutes(router.Group(""), database, "", "")
				query := url.Values{"path": {archive}, "device": {device}}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(method, path+"?"+query.Encode(), nil))
				wantCode, want := http.StatusBadRequest, "device-scoped database ingestion is not supported"
				if device == "" {
					wantCode, want = http.StatusInternalServerError, "multiple SystemOS DMGs"
				}
				if response.Code != wantCode || !strings.Contains(response.Body.String(), want) {
					t.Fatalf("status %d body %s; want %d %q", response.Code, response.Body.String(), wantCode, want)
				}
				if method == http.MethodPost && len(database.IPSWs) != 0 {
					t.Fatal("rejected scan created a database record")
				}
				if method == http.MethodPut && (len(database.IPSWs) != 1 || database.IPSWs[sha] != existing) {
					t.Fatal("rejected rescan replaced the existing graph")
				}
			})
		}
	}
}
