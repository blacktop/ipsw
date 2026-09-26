package render

import (
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func TestRenderPayloadBounds(t *testing.T) {
	for _, size := range [][2]int{{-1, 1}, {1, -1}, {0, 1}, {1, 0}, {pixel.MaxBytes, 2}, {1, pixel.MaxBytes}} {
		if _, err := Decode([]byte("fake"), "HEIF", size[0], size[1]); err == nil {
			t.Errorf("accepted dimensions %v", size)
		}
	}
	if _, err := Decode(nil, "PDF ", 0, 0); err == nil {
		t.Fatal("accepted an empty source")
	}
	if _, err := Decode([]byte("fake"), "FAKE", 0, 0); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected format error: %v", err)
	}
}
