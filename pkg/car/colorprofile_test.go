package car

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"testing"
)

func TestEncodePNGColorProfiles(t *testing.T) {
	rgb := image.NewNRGBA64(image.Rect(0, 0, 2, 1))
	rgb.SetNRGBA64(0, 0, color.NRGBA64{R: 12345, G: 54321, B: 731, A: 45000})
	rgb.SetNRGBA64(1, 0, color.NRGBA64{R: 60001, G: 421, B: 23999, A: 65535})
	for _, space := range []colorSpaceID{Generic, SRGB, Mono, DisplayP3, ExtendedSRGB, ExtendedLinear, ExtendedGray, 15} {
		for _, img := range []image.Image{rgb, image.NewGray(image.Rect(0, 0, 1, 1))} {
			var encoded bytes.Buffer
			if err := encodePNG(&encoded, img, space); err != nil {
				t.Fatal(err)
			}
			data := encoded.Bytes()
			var profile []byte
			for pos := 8; pos < len(data); {
				if len(data)-pos < 12 {
					t.Fatal("truncated PNG chunk")
				}
				n := int(binary.BigEndian.Uint32(data[pos:]))
				if n > len(data)-pos-12 {
					t.Fatal("chunk exceeds PNG")
				}
				chunk := data[pos+4 : pos+8+n]
				if crc32.ChecksumIEEE(chunk) != binary.BigEndian.Uint32(data[pos+8+n:]) {
					t.Fatal("incorrect PNG CRC")
				}
				if string(chunk[:4]) == "iCCP" {
					if pos != 33 || profile != nil {
						t.Fatal("profile missing before image data or duplicated")
					}
					end := bytes.IndexByte(chunk[4:], 0) + 4
					if end < 5 || end > 83 || chunk[end+1] != 0 {
						t.Fatal("invalid profile name or compression method")
					}
					zr, err := zlib.NewReader(bytes.NewReader(chunk[end+2:]))
					if err != nil {
						t.Fatal(err)
					}
					profile, err = io.ReadAll(zr)
					if err != nil {
						t.Fatal(err)
					}
					zr.Close()
				}
				pos += n + 12
			}
			if space == Generic || space == 15 {
				if profile != nil {
					t.Fatalf("unknown space %d was assigned a profile", space)
				}
				continue
			}
			tags := readProfileTags(t, profile)
			model, curve := "RGB ", "rTRC"
			if img.ColorModel() == color.GrayModel {
				model, curve = "GRAY", "kTRC"
			}
			if string(profile[16:20]) != model {
				t.Fatalf("space %s has profile model %q for %q PNG", space, profile[16:20], model)
			}
			mid := evalProfileCurve(t, tags[curve], 0.5)
			want := math.Pow((0.5+0.055)/1.055, 2.4)
			if space == ExtendedLinear {
				want = 0.5
			}
			if math.Abs(mid-want) > 0.00003 {
				t.Fatalf("space %s middle gray = %g, want %g", space, mid, want)
			}
			decoded, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			for y := range img.Bounds().Dy() {
				for x := range img.Bounds().Dx() {
					if decoded.At(x, y) != img.At(x, y) {
						t.Fatalf("profile encoding changed sample %d,%d", x, y)
					}
				}
			}
		}
	}
}

func readProfileTags(t *testing.T, profile []byte) map[string][]byte {
	t.Helper()
	if len(profile) < 132 || int(binary.BigEndian.Uint32(profile)) != len(profile) ||
		string(profile[36:40]) != "acsp" || string(profile[20:24]) != "XYZ " {
		t.Fatal("invalid ICC header")
	}
	n := int(binary.BigEndian.Uint32(profile[128:132]))
	if n > (len(profile)-132)/12 {
		t.Fatal("invalid ICC tag count")
	}
	tags := make(map[string][]byte)
	end := 132 + 12*n
	for i := range n {
		entry := profile[132+i*12:][:12]
		offset := int(binary.BigEndian.Uint32(entry[4:8]))
		size := int(binary.BigEndian.Uint32(entry[8:12]))
		if offset != end || offset%4 != 0 || offset > len(profile) || size > len(profile)-offset {
			t.Fatal("invalid or overlapping ICC tag")
		}
		tags[string(entry[:4])] = profile[offset : offset+size]
		end = (offset + size + 3) &^ 3
	}
	for _, required := range []string{"desc", "cprt", "wtpt", "chad"} {
		if len(tags[required]) < 8 {
			t.Fatalf("missing ICC tag %s", required)
		}
	}
	return tags
}

func profileNumber(data []byte) float64 {
	return float64(int32(binary.BigEndian.Uint32(data))) / 65536
}

func evalProfileCurve(t *testing.T, data []byte, sample float64) float64 {
	t.Helper()
	if len(data) < 16 || string(data[:4]) != "para" {
		t.Fatal("invalid curve")
	}
	g := profileNumber(data[12:])
	switch binary.BigEndian.Uint16(data[8:10]) {
	case 0:
		return math.Pow(sample, g)
	case 3:
		if len(data) != 32 {
			t.Fatal("invalid sRGB curve size")
		}
		a, b := profileNumber(data[16:]), profileNumber(data[20:])
		c, d := profileNumber(data[24:]), profileNumber(data[28:])
		if sample < d {
			return c * sample
		}
		return math.Pow(a*sample+b, g)
	default:
		t.Fatal("unexpected curve function")
		return 0
	}
}

func TestPNGProfilePrimaries(t *testing.T) {
	// D50-adapted primary XYZ values establish that P3 was not simply given
	// an sRGB label. Values are independent rounded colorimetry expectations.
	for _, tc := range []struct {
		space colorSpaceID
		red   [3]float64
	}{
		{SRGB, [3]float64{0.4361, 0.2225, 0.0139}},
		{DisplayP3, [3]float64{0.5151, 0.2412, -0.0010}},
	} {
		tags := readProfileTags(t, pngColorProfile(tc.space, false))
		for i, want := range tc.red {
			if got := profileNumber(tags["rXYZ"][8+4*i:]); math.Abs(got-want) > 0.00015 {
				t.Fatalf("space %s red XYZ[%d] = %g, want %g", tc.space, i, got, want)
			}
		}
		for i, want := range [3]float64{0.9642, 1, 0.8249} {
			var sum float64
			for _, name := range []string{"rXYZ", "gXYZ", "bXYZ"} {
				sum += profileNumber(tags[name][8+4*i:])
			}
			if math.Abs(sum-want) > 0.0002 {
				t.Fatalf("space %s white XYZ[%d] = %g, want %g", tc.space, i, sum, want)
			}
		}
	}
}

type pngFailWriter struct{ remaining int }

func (w *pngFailWriter) Write(p []byte) (int, error) {
	n := min(w.remaining, len(p))
	w.remaining -= n
	if n < len(p) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func TestPNGProfileWriteErrors(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	for _, limit := range []int{0, 8, 33, 45, 128} {
		if err := encodePNG(&pngFailWriter{remaining: limit}, img, DisplayP3); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("limit %d: got %v, want write failure", limit, err)
		}
	}
}
