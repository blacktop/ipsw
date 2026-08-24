//go:build !ios

package download

import "github.com/apex/log"

// logHTTPResponseMetadata preserves useful verbose request diagnostics without
// recording response bodies, which may contain credentials or signed URLs.
func logHTTPResponseMetadata(operation string, statusCode, bodySize int) {
	log.Debugf("%s: (%d, %d-byte body omitted)", operation, statusCode, bodySize)
}
