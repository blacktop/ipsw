//go:build !darwin || ios || !cgo

package render

import (
	"strings"
	"testing"
)

func TestRenderUnavailable(t *testing.T) {
	for _, format := range []string{"HEIF", "PDF ", "SVG "} {
		if _, err := renderNative([]byte("fake"), format, 1, 1); err == nil || !strings.Contains(err.Error(), "requires macOS with cgo") {
			t.Fatalf("unsupported backend did not explain availability: %v", err)
		}
	}
}
