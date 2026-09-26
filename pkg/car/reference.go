package car

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg" // Internal references may target an original JPEG payload.

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
	"github.com/blacktop/ipsw/pkg/car/internal/render"
	_ "golang.org/x/image/webp" // Original WebP targets share the bounded image.Decode path.
)

const maxReferenceDepth = 16

// Cache original bytes and rendered pixels separately: they may have different
// color spaces, and raw links must not depend on optional rendering.
type referenceCacheKey struct {
	index int
	raw   bool
}

type referenceValue struct {
	asset any
	space colorSpaceID
	err   error
}

func validateKeyFormat(format []renditionAttributeType) error {
	if len(format) == 0 || len(format) > 65536 {
		return fmt.Errorf("invalid key format token count: %d", len(format))
	}
	seen := make(map[renditionAttributeType]bool, len(format))
	for _, token := range format {
		if token > 65535 {
			return fmt.Errorf("key format token exceeds reference attribute range: %d", token)
		}
		if seen[token] {
			return fmt.Errorf("duplicate key format token: %d", token)
		}
		seen[token] = true
	}
	return nil
}

func renditionKey(values []uint16) string {
	data := make([]byte, len(values)*2)
	for i, value := range values {
		binary.LittleEndian.PutUint16(data[i*2:], value)
	}
	return string(data)
}

func referenceKey(link *csiInternalLinkData, format []renditionAttributeType) (string, error) {
	indices := make(map[uint16]int, len(format))
	for i, token := range format {
		indices[uint16(token)] = i
	}
	values := make([]uint16, len(format))
	seen := make(map[uint16]bool)
	terminated := false
	for _, token := range link.Reference {
		if token.Name == 0 && token.Value == 0 {
			terminated = true
			continue
		}
		if terminated {
			return "", fmt.Errorf("nonzero reference token after terminator")
		}
		index, ok := indices[token.Name]
		if !ok {
			return "", fmt.Errorf("unknown reference attribute: %d", token.Name)
		}
		if seen[token.Name] {
			return "", fmt.Errorf("duplicate reference attribute: %d", token.Name)
		}
		seen[token.Name] = true
		values[index] = token.Value
	}
	return renditionKey(values), nil
}

func (r *Rendition) isRawLink() bool {
	return r.link != nil && renditionLayoutType(r.link.Layout) == RawData
}

// resolveReferences indexes every rendition, including those absent from FACETKEYS.
// A name never substitutes for the exact full key of the referenced variant.
func (a *Asset) resolveReferences() error {
	if len(a.ImageDB) == 0 {
		return nil
	}
	if err := validateKeyFormat(a.KeyFormat); err != nil {
		return err
	}
	byKey := make(map[string]int, len(a.ImageDB))
	for i := range a.ImageDB {
		rend := &a.ImageDB[i]
		if len(rend.Key) < len(a.KeyFormat) {
			return fmt.Errorf("invalid key length for rendition %q", rend.RenditionName)
		}
		key := renditionKey(rend.Key)
		if _, exists := byKey[key]; exists {
			return fmt.Errorf("duplicate rendition key for %q", rend.RenditionName)
		}
		byKey[key] = i
	}
	cache := make(map[referenceCacheKey]referenceValue)
	for i := range a.ImageDB {
		rend := &a.ImageDB[i]
		if !a.isSelected(i) || rend.link == nil || rend.DecodeError != nil {
			continue
		}
		value, _, err := a.resolveReference(i, byKey, cache, make(map[int]bool), 0, rend.isRawLink())
		rend.ResolveError = err
		if errors.Is(err, errUnsupportedRendition) {
			log.WithField("rendition", rend.RenditionName).Warn(err.Error())
		} else if err != nil {
			log.WithField("rendition", rend.RenditionName).Errorf("resolve: %v", err)
		}
		if err == nil {
			rend.Asset = value
		}
	}
	return nil
}

func (a *Asset) resolveReference(index int, byKey map[string]int, cache map[referenceCacheKey]referenceValue,
	visited map[int]bool, depth int, raw bool,
) (any, colorSpaceID, error) {
	if visited[index] {
		return nil, 0, fmt.Errorf("internal reference cycle at rendition %d", index)
	}
	visited[index] = true
	defer delete(visited, index)
	rend := &a.ImageDB[index]
	if rend.link == nil {
		key := referenceCacheKey{index, raw}
		result, ok := cache[key]
		if !ok {
			if raw {
				result.asset, result.space, result.err = decodeReferenceData(rend)
			} else if err := a.ensureDecoded(index); err != nil {
				result.err = fmt.Errorf("reference target %q: %w", rend.RenditionName, err)
			} else {
				result.asset, result.space, result.err = decodeReferenceImage(rend)
			}
			cache[key] = result
		}
		return result.asset, result.space, result.err
	}
	if err := a.ensureDecoded(index); err != nil {
		return nil, 0, fmt.Errorf("reference target %q: %w", rend.RenditionName, err)
	}
	if raw != rend.isRawLink() {
		return nil, 0, fmt.Errorf("%w: mixed raw and image reference chain", errUnsupportedRendition)
	}
	if depth >= maxReferenceDepth {
		return nil, 0, fmt.Errorf("internal reference depth exceeds %d", maxReferenceDepth)
	}
	key, err := referenceKey(rend.link, a.KeyFormat)
	if err != nil {
		return nil, 0, err
	}
	target, ok := byKey[key]
	if !ok {
		return nil, 0, fmt.Errorf("internal reference target not found for key %x", key)
	}
	source, space, err := a.resolveReference(target, byKey, cache, visited, depth+1, raw)
	if err != nil {
		return nil, 0, err
	}
	rend.ColorSpace = space
	rend.Colorspace = rend.ColorSpace.String()
	rend.Warnings = append([]string(nil), a.ImageDB[target].Warnings...)
	if raw {
		return source, space, nil
	}
	img, ok := source.(image.Image)
	if !ok {
		return nil, 0, fmt.Errorf("%w: reference target has no image", errUnsupportedRendition)
	}
	cropped, err := cropReference(img, rend.link.Frame)
	return cropped, space, err
}

// Raw references address the original DATA, independently of whether the
// source rendition is also selected for optional rendering.
func decodeReferenceData(rend *Rendition) ([]byte, colorSpaceID, error) {
	if rend.PixelFormat != PixFmtRawData {
		return nil, 0, fmt.Errorf("%w: raw link target is %q", errUnsupportedRendition, rend.PixelFormat)
	}
	if data, ok := rend.Asset.([]byte); ok && len(rend.rawCSI) != 0 {
		// Original bytes remain valid even if optional rendering failed.
		return data, rend.header.ColorSpace.ColorSpaceID(), nil
	}
	if len(rend.rawCSI) == 0 && !rend.Deferred {
		// Support caller-constructed renditions with an already decoded payload.
		if data, ok := rend.Asset.([]byte); ok || rend.DecodeError != nil {
			return data, rend.ColorSpace, rend.DecodeError
		}
	}
	data, err := decodeOriginalPayload(rend.payload, PixFmtRawData)
	return data, rend.header.ColorSpace.ColorSpaceID(), err
}

func decodeReferenceImage(rend *Rendition) (image.Image, colorSpaceID, error) {
	if img, ok := rend.Asset.(image.Image); ok {
		return img, rend.ColorSpace, nil
	}
	if data, ok := rend.Asset.([]byte); ok {
		if format := renderedPayloadFormat(data, rend.PixelFormat); isRenderableFormat(format) {
			img, err := render.Decode(data, format, int(rend.Width), int(rend.Height))
			return img, SRGB, err
		}
		config, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return nil, 0, fmt.Errorf("read reference target image: %w", err)
		}
		if _, _, err := pixel.Layout(config.Width, config.Height, 8, 0); err != nil {
			return nil, 0, err
		}
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, 0, fmt.Errorf("decode reference target %q: %w", rend.RenditionName, err)
		}
		return img, rend.ColorSpace, nil
	}
	return nil, 0, fmt.Errorf("reference target %q has no decoded image", rend.RenditionName)
}

func cropReference(source image.Image, frame linkRect) (image.Image, error) {
	bounds := source.Bounds()
	width, height := uint64(bounds.Dx()), uint64(bounds.Dy())
	right, top := uint64(frame.X)+uint64(frame.Width), uint64(frame.Y)+uint64(frame.Height)
	if frame.Width == 0 || frame.Height == 0 || right > width || top > height {
		return nil, fmt.Errorf("reference crop (%d,%d %dx%d) exceeds source %dx%d", frame.X, frame.Y, frame.Width, frame.Height, width, height)
	}
	// CoreUI frames use a bottom-left origin; Go images use a top-left origin.
	origin := image.Pt(bounds.Min.X+int(frame.X), bounds.Min.Y+int(height-top))
	bpp := 4
	model := source.ColorModel()
	if model == color.RGBA64Model || model == color.NRGBA64Model || model == color.Gray16Model {
		bpp = 8
	}
	if _, _, err := pixel.Layout(int(frame.Width), int(frame.Height), bpp, 0); err != nil {
		return nil, err
	}
	var cropped draw.Image
	rect := image.Rect(0, 0, int(frame.Width), int(frame.Height))
	if model == color.RGBA64Model {
		cropped = image.NewRGBA64(rect)
	} else if bpp == 8 {
		cropped = image.NewNRGBA64(rect)
	} else {
		cropped = image.NewNRGBA(rect)
	}
	draw.Draw(cropped, cropped.Bounds(), source, origin, draw.Src)
	return cropped, nil
}
