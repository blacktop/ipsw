//go:build !ios

package download

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/apex/log"
)

func TestLogHTTPResponseMetadataOmitsBody(t *testing.T) {
	handler := captureApexLog(t, log.DebugLevel)
	body := []byte(`{"passwordToken":"synthetic-secret","url":"https://cdn.invalid/file?token=synthetic-secret"}`)

	logHTTPResponseMetadata("POST Login", 200, len(body))

	if len(handler.Entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(handler.Entries))
	}
	message := handler.Entries[0].Message
	if strings.Contains(message, "synthetic-secret") {
		t.Fatalf("response metadata log leaks body: %s", message)
	}
	for _, want := range []string{"POST Login", "200", fmt.Sprintf("%d-byte body omitted", len(body))} {
		if !strings.Contains(message, want) {
			t.Errorf("response metadata log = %q, want %q", message, want)
		}
	}
}

func TestAuthenticatedClientDebugLogsDoNotStringifyResponseBodies(t *testing.T) {
	for _, name := range []string{"appstore.go", "dev_portal.go"} {
		t.Run(name, func(t *testing.T) {
			source, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(source), "\n") {
				if strings.Contains(line, "string(body)") {
					t.Fatalf("authenticated debug log emits a raw response body: %s", strings.TrimSpace(line))
				}
			}
		})
	}
}
