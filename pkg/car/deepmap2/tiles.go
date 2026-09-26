package deepmap2

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"slices"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

// decodeTiles accepts the nested KCBC grid used within a Deepmap2
// payload. The outer bitmap KCBC chunk list is handled by decodeImage.
func decodeTiles(data []byte, width, height int, pixelFormat string, floatingPoint, opaque bool) (image.Image, error) {
	type tile struct {
		col, row uint32
		pixels   image.Image
	}
	var tiles []tile
	columns, rows := make(map[uint32]int), make(map[uint32]int)
	seen := make(map[[2]uint32]bool)
	totalBytes := 0
	var wideModel color.Model
	for len(data) != 0 {
		if len(data) < 20 || string(data[:4]) != "KCBC" || len(tiles) >= 65536 {
			return nil, fmt.Errorf("deepmap2: truncated or oversized tile grid")
		}
		col, row := binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:])
		rowHint, length := binary.LittleEndian.Uint32(data[12:]), binary.LittleEndian.Uint32(data[16:])
		if length < 32 || uint64(length) > uint64(len(data)) || rowHint > 65535 || seen[[2]uint32{col, row}] {
			return nil, fmt.Errorf("deepmap2: invalid or duplicate tile (%d,%d)", col, row)
		}
		payload := data[20:int(length)]
		// Accept direct dmp2 data or a complete CoreUI wrapper. Never scan
		// pixel bytes for a header signature.
		if len(payload) >= 28 && string(payload[16:20]) == "dmp2" {
			if binary.LittleEndian.Uint32(payload) != 1 || binary.LittleEndian.Uint64(payload[8:]) != uint64(len(payload)-16) {
				return nil, fmt.Errorf("deepmap2: invalid tile CoreUI header")
			}
			payload = payload[16:]
		}
		h, _, err := readHeader(payload, pixelFormat)
		if err != nil {
			return nil, err
		}
		tileHeight := h.height
		if rowHint != 0 {
			tileHeight = int(rowHint)
		}
		if err := checkDimensions(h.width, tileHeight); err != nil {
			return nil, err
		}
		bpp := 4
		if h.storedFormat == 0x14 {
			bpp = 8
		}
		_, bytes, err := pixel.Layout(h.width, tileHeight, bpp, 0)
		if err != nil {
			return nil, err
		}
		if bytes > maxBytes-totalBytes {
			return nil, fmt.Errorf("deepmap2: tile grid exceeds size limit")
		}
		pixels, err := decodeImage(payload, h.width, tileHeight, pixelFormat, floatingPoint, opaque)
		if err != nil {
			return nil, err
		}
		if model := pixels.ColorModel(); model == color.NRGBA64Model || model == color.RGBA64Model {
			wideModel = model
		}
		if w, ok := columns[col]; ok && w != h.width {
			return nil, fmt.Errorf("deepmap2: inconsistent width for tile column %d", col)
		}
		if h, ok := rows[row]; ok && h != tileHeight {
			return nil, fmt.Errorf("deepmap2: inconsistent height for tile row %d", row)
		}
		columns[col], rows[row] = h.width, tileHeight
		totalBytes += bytes
		seen[[2]uint32{col, row}] = true
		tiles = append(tiles, tile{col, row, pixels})
		data = data[int(length):]
	}
	if len(tiles) == 0 || len(columns) > len(tiles)/len(rows) || len(columns)*len(rows) != len(tiles) {
		return nil, fmt.Errorf("deepmap2: incomplete tile grid")
	}
	xOffsets, gridWidth := deepmap2TileOffsets(columns)
	yOffsets, gridHeight := deepmap2TileOffsets(rows)
	if width != 0 && width != gridWidth || height != 0 && height != gridHeight {
		return nil, fmt.Errorf("deepmap2: tile grid dimensions %dx%d do not match %dx%d", gridWidth, gridHeight, width, height)
	}
	if err := checkDimensions(gridWidth, gridHeight); err != nil {
		return nil, err
	}
	var img draw.Image
	rect := image.Rect(0, 0, gridWidth, gridHeight)
	if wideModel != nil {
		if _, _, err := pixel.Layout(gridWidth, gridHeight, 8, 0); err != nil {
			return nil, err
		}
		// All wide tiles share the CSI color floatingPoint. Keep their alpha model to
		// avoid losing precision by unpremultiplying integer samples here.
		if wideModel == color.RGBA64Model {
			img = image.NewRGBA64(rect)
		} else {
			img = image.NewNRGBA64(rect)
		}
	} else {
		img = image.NewRGBA(rect)
	}
	for _, tile := range tiles {
		x, y := xOffsets[tile.col], yOffsets[tile.row]
		bounds := tile.pixels.Bounds()
		draw.Draw(img, image.Rect(x, y, x+bounds.Dx(), y+bounds.Dy()), tile.pixels, bounds.Min, draw.Src)
	}
	return img, nil
}

func deepmap2TileOffsets(sizes map[uint32]int) (map[uint32]int, int) {
	indices := make([]uint32, 0, len(sizes))
	for index := range sizes {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	offsets, total := make(map[uint32]int, len(sizes)), 0
	for _, index := range indices {
		offsets[index] = total
		total += sizes[index]
	}
	return offsets, total
}
