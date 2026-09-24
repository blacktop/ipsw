//go:build darwin && wallpaper

package wallpaper

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractThumbnailBytes(t *testing.T) {
	got, err := ExtractThumbnailBytes(
		t.Context(),
		"https://updates.cdn-apple.com/2022/mobileassets/012-19617/B488E2A1-B291-4E42-AD9A-7111CB03A2AB/com_apple_MobileAsset_Wallpaper/605957001046c16663cb44a4b4ba12c3bcc9281b.zip",
		"",
		false,
	)
	if err != nil {
		t.Fatalf("ExtractThumbnailBytes() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("ExtractThumbnailBytes() returned no thumbnail bytes")
	}
}

func requireSips(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(sipsPath); err != nil {
		t.Skipf("sips not available: %v", err)
	}
}

func synthHEIC(t *testing.T) []byte {
	t.Helper()
	requireSips(t)

	tempDir := t.TempDir()
	pngPath := filepath.Join(tempDir, "source.png")
	heicPath := filepath.Join(tempDir, "source.heic")

	img := image.NewNRGBA(image.Rect(0, 0, 2, 3))
	for y := 0; y < 3; y++ {
		for x := 0; x < 2; x++ {
			img.Set(x, y, color.NRGBA{R: uint8(40 * x), G: uint8(60 * y), B: 200, A: 255})
		}
	}

	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, img); err != nil {
		t.Fatalf("png.Encode() error = %v", err)
	}
	if err := os.WriteFile(pngPath, pngBytes.Bytes(), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	cmd := exec.Command(sipsPath, "-s", "format", "heic", pngPath, "--out", heicPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sips HEIC encode failed: %v (%s)", err, bytes.TrimSpace(output))
	}

	heicBytes, err := os.ReadFile(heicPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	return heicBytes
}

func TestConvertWithSipsHEIC(t *testing.T) {
	converted, err := convertWithSips(t.Context(), synthHEIC(t), ".heic")
	if err != nil {
		t.Fatalf("convertWithSips() error = %v", err)
	}
	if len(converted) == 0 {
		t.Fatal("convertWithSips() returned no bytes")
	}

	cfg, format, err := image.DecodeConfig(bytes.NewReader(converted))
	if err != nil {
		t.Fatalf("image.DecodeConfig() error = %v", err)
	}
	if format != "png" {
		t.Fatalf("image.DecodeConfig() format = %s, want png", format)
	}
	if cfg.Height != 700 {
		t.Fatalf("converted height = %d, want 700", cfg.Height)
	}
	if cfg.Width == 0 {
		t.Fatal("converted width = 0")
	}
}

func TestConvertWithSipsEmptyInput(t *testing.T) {
	requireSips(t)

	_, err := convertWithSips(t.Context(), nil, ".heic")
	if err == nil {
		t.Fatal("convertWithSips() error = nil, want error for empty input")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sips produced no .heic preview") || !strings.Contains(msg, "not a valid file") {
		t.Fatalf("convertWithSips() error = %q, want sips skip warning", err)
	}
}

func TestConvertWithSipsTimeout(t *testing.T) {
	heicBytes := synthHEIC(t)

	ctx, cancel := context.WithTimeout(t.Context(), 0)
	defer cancel()

	_, err := convertWithSips(ctx, heicBytes, ".heic")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("convertWithSips() error = %v, want context.DeadlineExceeded", err)
	}
}
