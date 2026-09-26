package texture

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// DecodeASTC renders a two-dimensional texture to RGBA8. ImageIO is the
// default decoder on macOS; other platforms use Arm's astcenc executable. An
// explicit decoder path overrides ImageIO. Linear textures use astcenc's linear
// decode profile, because ImageIO exposes no ASTC profile selection option.
func DecodeASTC(data []byte, width, height int, decoderPath string, linear, opaque bool) (image.Image, error) {
	data, err := astcPayload(data, width, height)
	if err != nil {
		return nil, err
	}
	var nativeErr error
	if decoderPath == "" && !linear {
		var img *image.RGBA
		img, nativeErr = decodeNativeTexture(data, width, height)
		if nativeErr == nil {
			return finishTexture(img, opaque), nil
		}
	}
	if decoderPath == "" {
		decoderPath, err = exec.LookPath("astcenc")
		if err != nil {
			if nativeErr != nil {
				return nil, fmt.Errorf("ASTC decoding: %v; astcenc executable is unavailable (set ASTCDecoder)", nativeErr)
			}
			return nil, fmt.Errorf("ASTC decoding requires astcenc (set ASTCDecoder): %w", err)
		}
	}
	dir, err := os.MkdirTemp("", "ipsw-car-astc-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	input, output := filepath.Join(dir, "texture.astc"), filepath.Join(dir, "texture.png")
	if err := os.WriteFile(input, data, 0600); err != nil {
		return nil, err
	}
	mode := "-ds"
	if linear {
		mode = "-dl"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, decoderPath, mode, input, output, "-j", "1", "-silent")
	cmd.WaitDelay = time.Second
	var stderr textureDiagnostics
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("ASTC decoder timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("ASTC decoder failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	f, err := os.Open(output)
	if err != nil {
		return nil, fmt.Errorf("ASTC decoder output: %w", err)
	}
	defer f.Close()
	encoded, err := compression.ReadLimited(f, pixel.MaxBytes)
	if err != nil {
		return nil, err
	}
	return decodeTexturePNG(encoded, width, height, opaque)
}

func decodeTexturePNG(data []byte, width, height int, opaque bool) (*image.RGBA, error) {
	if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
		return nil, err
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ASTC decoder PNG: %w", err)
	}
	if config.Width != width || config.Height != height {
		return nil, fmt.Errorf("ASTC decoder returned unexpected image dimensions")
	}
	// astcenc's PNG contract is eight-bit output. Reject wider samples before
	// png.Decode can allocate beyond the four-byte-per-pixel bound above.
	switch config.ColorModel {
	case color.RGBA64Model, color.NRGBA64Model, color.Gray16Model:
		return nil, fmt.Errorf("ASTC decoder PNG must use 8-bit samples")
	}
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("ASTC decoder PNG: %w", err)
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			i := y*img.Stride + x*4
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
		}
	}
	return finishTexture(img, opaque), nil
}

type textureDiagnostics []byte

func (d *textureDiagnostics) Write(p []byte) (int, error) {
	const limit = 4096
	n := len(p)
	if len(*d) < limit {
		*d = append(*d, p[:min(n, limit-len(*d))]...)
	}
	return n, nil
}
