package mount

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMountRouteDeviceSelectionErrorsDoNotPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic.ipsw")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("BuildManifest.plist")
	if err != nil {
		t.Fatal(err)
	}
	// The absent image members ensure successful selection still stops before
	// decryption or a real mount. Distinct names prove which target was selected.
	manifest := `<plist version="1.0"><dict><key>BuildIdentities</key><array>`
	for _, product := range []string{"Mac99,1", "Mac99,2"} {
		manifest += `<dict><key>Ap,ProductType</key><string>` + product + `</string><key>Manifest</key><dict><key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key><string>synthetic-api-` + product + `.dmg</string></dict></dict></dict></dict>`
	}
	manifest += `</array></dict></plist>`
	if _, err := w.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for device, want := range map[string]string{"": "multiple SystemOS", "Mac99,2": "synthetic-api-Mac99,2.dmg", "unknown": "no BuildManifest identity"} {
		r := gin.New() // No recovery middleware: a nil context dereference fails the test.
		var routeError string
		r.Use(func(c *gin.Context) { c.Next(); routeError = c.Errors.String() })
		AddRoutes(r.Group(""), "")
		query := url.Values{"path": {path}, "device": {device}}
		response := httptest.NewRecorder()
		r.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/mount/sys?"+query.Encode(), nil))
		if response.Code != http.StatusInternalServerError || !strings.Contains(routeError, want) {
			t.Fatalf("device=%q: status=%d error=%q; want %q", device, response.Code, routeError, want)
		}
	}
}
