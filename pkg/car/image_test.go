package car

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"testing"
)

func rawDeepmapFixture(width, height uint16, format byte, pixels []byte) []byte {
	data := []byte{'d', 'm', 'p', '2', 1, 0, 1, format}
	data = binary.LittleEndian.AppendUint16(data, width)
	data = binary.LittleEndian.AppendUint16(data, height)
	data = append(data, pixels...)
	wrapper := binary.LittleEndian.AppendUint32(nil, 1)
	wrapper = binary.LittleEndian.AppendUint32(wrapper, uint32(format))
	wrapper = binary.LittleEndian.AppendUint64(wrapper, uint64(len(data)))
	return append(wrapper, data...)
}

func TestWidePredictorColorSpaces(t *testing.T) {
	// Native CoreUI reconstructs these two gray pixels as RGBA half words
	// {0x3800, 0x3800, 0x3800, 0x3c00}. A CGContext draw in sRGB produces
	// {56,56,56,60} for ordinary spaces and {128,128,128,255} for ExtendedSRGB.
	planes := []byte{255, 255, 0, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	literal := append([]byte{0xef}, planes[:15]...)
	literal = append(literal, 0xe1, planes[15], 6, 0, 0, 0, 0, 0, 0, 0)
	chunk := binary.LittleEndian.AppendUint32(nil, uint32(len(literal)))
	chunk = append(chunk, literal...)
	for _, encoding := range []compressionType{DeepmapLZFSE, Deepmap2} {
		data := []byte{'d', 'm', 'a', 'p', 2, 0, 10, 20}
		if encoding == Deepmap2 {
			data = []byte{'d', 'm', 'p', '2', 2, 0, 10, 20, 2, 0, 1, 0}
		}
		data = append(data, chunk...)
		wrapper := binary.LittleEndian.AppendUint32(nil, 1)
		wrapper = binary.LittleEndian.AppendUint32(wrapper, 20)
		wrapper = binary.LittleEndian.AppendUint64(wrapper, uint64(len(data)))
		wrapper = append(wrapper, data...)
		for _, space := range []colorSpaceID{SRGB, DisplayP3, ExtendedSRGB, ExtendedLinear} {
			header := csiHeader{Width: 2, Height: 1, PixelFormat: [4]byte{'R', 'G', 'B', 'W'},
				ColorSpace: csiColorSpace(space)}
			bitmap := bitmapFixture(t, encoding, nil, wrapper)
			img, err := decodeImage(bytes.NewReader(bitmap), header, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := color.RGBA64{0x3800, 0x3800, 0x3800, 0x3c00}
			if space == ExtendedSRGB || space == ExtendedLinear {
				want = color.RGBA64{32768, 32768, 32768, 65535}
			}
			for x := range 2 {
				if got := color.RGBA64Model.Convert(img.At(x, 0)); got != want {
					t.Fatalf("%s %s pixel %d = %v, want %v", encoding, space, x, got, want)
				}
			}
		}
	}
}

func TestDecodeImageDeepmapChunks(t *testing.T) {
	ci := csiHeader{Width: 1, Height: 2, PixelFormat: [4]byte{'A', 'R', 'G', 'B'}}
	// Source pixel hint 0x14 must not turn decoded RGBA8 into RGBA16 indexing.
	first := rawDeepmapFixture(1, 1, 4, []byte{1, 2, 3, 255})
	second := rawDeepmapFixture(1, 1, 4, []byte{4, 5, 6, 255})
	binary.LittleEndian.PutUint32(first[4:], 0x14)
	binary.LittleEndian.PutUint32(second[4:], 0x14)
	data := bitmapFixture(t, Deepmap2, []uint32{1, 1}, first, second)
	img, err := decodeImage(bytes.NewReader(data), ci, nil, 999)
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 1)).(color.RGBA); got != (color.RGBA{6, 5, 4, 255}) {
		t.Fatalf("second row = %v", got)
	}
	var pngData bytes.Buffer
	if err := png.Encode(&pngData, img); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeImage(bytes.NewReader(data[:len(data)-1]), ci, nil, 0); err == nil {
		t.Fatal("accepted truncated chunk")
	}
	ci.Height = 3
	if _, err := decodeImage(bytes.NewReader(data), ci, nil, 0); err == nil {
		t.Fatal("accepted missing row")
	}
}

func TestDecodeImageDeepColorChunks(t *testing.T) {
	ci := csiHeader{Width: 1, Height: 2, PixelFormat: [4]byte{'R', 'G', 'B', 'W'}}
	// Integer RGBA16 uses the CSI's ordinary sRGB space. Neither chunk assembly
	// nor PNG encoding may truncate channels to multiples of 257 (8-bit values).
	ci.ColorSpace = csiColorSpace(SRGB)
	pixel := []byte{0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a, 0xff, 0xff}
	chunk := rawDeepmapFixture(1, 1, 0x14, pixel)
	data := bitmapFixture(t, Deepmap2, []uint32{1, 1}, chunk, chunk)
	img, err := decodeImage(bytes.NewReader(data), ci, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for y := range 2 {
		if got := color.NRGBA64Model.Convert(img.At(0, y)); got != (color.NRGBA64{R: 0x1234, G: 0x5678, B: 0x9abc, A: 0xffff}) {
			t.Fatalf("wide row %d = %v", y, got)
		}
	}
}

func TestBitmapChunkAssemblyPreservesPremultiplied16(t *testing.T) {
	pixel := color.RGBA64{R: 12944, G: 1234, B: 5678, A: 32768}
	chunks := []bitmapChunk{{rows: 1}, {rows: 1}}
	img, err := assembleBitmapChunks(chunks, 1, 2, func(_ []byte, _ int) (image.Image, error) {
		row := image.NewRGBA64(image.Rect(0, 0, 1, 1))
		row.SetRGBA64(0, 0, pixel)
		return row, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBA64Model.Convert(img.At(0, 1)); got != pixel {
		t.Fatalf("chunk assembly rounded premultiplied samples: %v", got)
	}
	cropped, err := cropReference(img, linkRect{0, 0, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBA64Model.Convert(cropped.At(0, 0)); got != pixel {
		t.Fatalf("crop rounded premultiplied samples: %v", got)
	}
}

func TestDecodeImageOpaqueAndStride(t *testing.T) {
	ci := csiHeader{Width: 1, Height: 1, PixelFormat: [4]byte{'A', 'R', 'G', 'B'}}
	data := bitmapFixture(t, Deepmap2, nil, rawDeepmapFixture(1, 1, 4, []byte{10, 20, 30, 0}))
	data[4] = 2
	img, err := decodeImage(bytes.NewReader(data), ci, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA); got != (color.RGBA{30, 20, 10, 255}) {
		t.Fatalf("opaque pixel = %v", got)
	}
	ci.Height = 2
	data = bitmapFixture(t, Uncompressed, nil, []byte{1, 2, 3, 255, 99, 99, 99, 99, 4, 5, 6, 255})
	img, err = decodeImage(bytes.NewReader(data), ci, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 1)).(color.RGBA); got != (color.RGBA{6, 5, 4, 255}) {
		t.Fatalf("padded pixel = %v", got)
	}
	data = bitmapFixture(t, Uncompressed, nil, []byte{1, 2, 3, 255, 4, 5, 6, 255})
	if _, err := decodeImage(bytes.NewReader(data), ci, nil, 8); err == nil {
		t.Fatal("accepted short padded row")
	}
	for _, encoding := range []compressionType{HEVC, ASTCImage, JPEGLZFSE, DXTC} {
		if _, err := decodeImage(bytes.NewReader(bitmapFixture(t, encoding, nil, make([]byte, 32))), ci, nil, 0); err == nil {
			t.Fatalf("treated %s compressed data as pixels", encoding)
		}
	}
}

func TestBGRAReferenceCropChannels(t *testing.T) {
	img, err := decodePixels([]byte{10, 20, 30, 255}, 1, 1, PixFmtARGB, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	cropped := image.NewRGBA(img.Bounds())
	draw.Draw(cropped, cropped.Bounds(), img, img.Bounds().Min, draw.Src)
	if got := color.RGBAModel.Convert(cropped.At(0, 0)).(color.RGBA); got != (color.RGBA{30, 20, 10, 255}) {
		t.Fatalf("crop changed channels: %v", got)
	}
}

func TestDecodeImageOrdinaryIcon(t *testing.T) {
	ci := csiHeader{Width: 2, Height: 1, PixelFormat: [4]byte{'A', 'R', 'G', 'B'}}
	ci.Metadata.Layout = IconImage
	for _, opaque := range []bool{false, true} {
		data := bitmapFixture(t, Uncompressed, nil, []byte{10, 20, 30, 128, 40, 50, 60, 128})
		alpha := uint8(128)
		if opaque {
			data[4] = 2
			alpha = 255
		}
		img, err := decodeImage(bytes.NewReader(data), ci, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := color.RGBAModel.Convert(img.At(1, 0)).(color.RGBA); got != (color.RGBA{60, 50, 40, alpha}) {
			t.Fatalf("icon pixel (opaque=%v) = %v", opaque, got)
		}
	}
}

func TestDecodeImageRLERows(t *testing.T) {
	ci := csiHeader{Width: 2, Height: 2, PixelFormat: [4]byte{'A', 'R', 'G', 'B'}}
	one := []byte{2, 0, 0, 128, 10, 20, 30, 0}
	two := []byte{2, 0, 0, 0, 40, 50, 60, 0, 70, 80, 90, 0}
	for _, data := range [][]byte{
		bitmapFixture(t, RLE, nil, rleFixture(2, one, two)),
		bitmapFixture(t, RLE, []uint32{1, 1}, rleFixture(2, one), rleFixture(2, two)),
	} {
		data[4] |= 2
		img, err := decodeImage(bytes.NewReader(data), ci, nil, 16)
		if err != nil {
			t.Fatal(err)
		}
		if got := color.RGBAModel.Convert(img.At(1, 1)).(color.RGBA); got != (color.RGBA{90, 80, 70, 255}) {
			t.Fatalf("RLE padded pixel = %v", got)
		}
	}
	for _, rows := range [][]uint32{{0, 1}, {2, 1}, {1, 3}, {1, 1}} {
		data := bitmapFixture(t, RLE, rows, rleFixture(2, one), rleFixture(2, two))
		ci.Height = 3
		if _, err := decodeImage(bytes.NewReader(data), ci, nil, 0); err == nil {
			t.Fatalf("accepted invalid chunk rows %v", rows)
		}
	}
}

// Exercise the catalog-to-decoder color-space and opacity mapping.
func TestDeepmap2WideColorSpaceAndOpacity(t *testing.T) {
	pixel := []byte{0, 0x34, 0, 0x30, 0, 0, 0, 0}
	stream := binary.LittleEndian.AppendUint32([]byte("bvx-"), uint32(len(pixel)))
	stream = append(stream, pixel...)
	stream = append(stream, "bvx$"...)
	blob := rawDeepmapFixture(1, 1, 0x14, stream)
	blob[20] = 3 // Lossless dmp2 compression.
	data := bitmapFixture(t, Deepmap2, nil, blob)
	data[4] = 2 // Opaque CSI bitmap.

	for _, tc := range []struct {
		space colorSpaceID
		want  color.RGBA64
	}{
		{ExtendedSRGB, color.RGBA64{16384, 8192, 0, 65535}},
		{ExtendedLinear, color.RGBA64{16384, 8192, 0, 65535}},
		{SRGB, color.RGBA64{0x3400, 0x3000, 0, 65535}},
		{DisplayP3, color.RGBA64{0x3400, 0x3000, 0, 65535}},
	} {
		ci := csiHeader{Width: 1, Height: 1, PixelFormat: [4]byte{'R', 'G', 'B', 'W'}, ColorSpace: csiColorSpace(tc.space)}
		decoded, err := decodeImage(bytes.NewReader(data), ci, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := color.RGBA64Model.Convert(decoded.At(0, 0)).(color.RGBA64); got != tc.want {
			t.Errorf("space %d opaque pixel = %v, want %v", tc.space, got, tc.want)
		}
	}
}
