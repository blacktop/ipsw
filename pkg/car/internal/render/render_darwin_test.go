//go:build darwin && !ios && cgo

package render

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"strings"
	"sync"
	"testing"
)

func TestRenderSVGNative(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><path fill="red" d="M0 0h2v2H0z"/><path fill="blue" opacity="0.5" d="M0 2h4v2H0z"/></svg>`)
	for _, size := range []int{0, 8} {
		img, err := Decode(svg, "SVG ", size, size)
		if err != nil {
			t.Fatal(err)
		}
		width := size
		if width == 0 {
			width = 4
		}
		if img.Bounds() != image.Rect(0, 0, width, width) {
			t.Fatalf("bounds = %v", img.Bounds())
		}
		for _, sample := range []struct {
			x, y int
			want color.RGBA
		}{
			{0, 0, color.RGBA{255, 0, 0, 255}},
			{width - 1, 0, color.RGBA{}},
			{0, width - 1, color.RGBA{0, 0, 128, 128}},
		} {
			if got := color.RGBAModel.Convert(img.At(sample.x, sample.y)); got != sample.want {
				t.Errorf("pixel %d,%d = %v, want %v", sample.x, sample.y, got, sample.want)
			}
		}
	}
	gray, err := Decode([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><path fill="#808080" d="M0 0h1v1H0z"/></svg>`), "SVG ", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(gray.At(0, 0)); got != (color.RGBA{128, 128, 128, 255}) {
		t.Errorf("sRGB gray = %v", got)
	}
}

func renderTestPDF(width, height, rotation int, crop ...int) []byte {
	stream := fmt.Sprintf("1 0 0 rg 0 %d %d %d re f 0 0 1 rg 0 0 %d %d re f\n", height/2, width, height/2, width, height/2)
	cropBox := ""
	if len(crop) == 4 {
		cropBox = fmt.Sprintf(" /CropBox [%d %d %d %d]", crop[0], crop[1], crop[2], crop[3])
	}
	objects := []string{
		`<< /Type /Catalog /Pages 2 0 R >>`,
		`<< /Type /Pages /Kids [3 0 R] /Count 1 >>`,
		fmt.Sprintf(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d]%s /Rotate %d /Resources << >> /Contents 4 0 R >>`, width, height, cropBox, rotation),
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	var offsets []int
	for i, object := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

func TestRenderPDFNative(t *testing.T) {
	img, err := Decode(renderTestPDF(4, 4, 0), "PDF ", 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds() != image.Rect(0, 0, 8, 8) {
		t.Fatalf("bounds = %v", img.Bounds())
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)); got != (color.RGBA{255, 0, 0, 255}) {
		t.Errorf("top pixel = %v", got)
	}
	if got := color.RGBAModel.Convert(img.At(0, 7)); got != (color.RGBA{0, 0, 255, 255}) {
		t.Errorf("bottom pixel = %v", got)
	}
	rotated, err := Decode(renderTestPDF(4, 2, 90), "PDF ", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Bounds() != image.Rect(0, 0, 2, 4) {
		t.Fatalf("rotated bounds = %v", rotated.Bounds())
	}
	cropped, err := Decode(renderTestPDF(4, 4, 0, 1, 1, 3, 3), "PDF ", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cropped.Bounds() != image.Rect(0, 0, 2, 2) || color.RGBAModel.Convert(cropped.At(0, 0)) != (color.RGBA{255, 0, 0, 255}) {
		t.Fatalf("crop-box geometry or origin mismatch: %v %v", cropped.Bounds(), cropped.At(0, 0))
	}
}

func TestRenderNativeRejectsInvalidSources(t *testing.T) {
	for _, format := range []string{"HEIF", "PDF "} {
		if _, err := Decode([]byte("fake source"), format, 0, 0); err == nil {
			t.Errorf("accepted invalid %s", format)
		}
	}
	for _, input := range []struct {
		format string
		data   []byte
	}{
		{"SVG ", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100000" height="100000"/>`)},
		{"PDF ", renderTestPDF(100000, 100000, 0)},
	} {
		if _, err := Decode(input.data, input.format, 1, 1); err == nil || !strings.Contains(err.Error(), "source dimensions") {
			t.Errorf("accepted excessive %s source: %v", input.format, err)
		}
	}
}

func TestRenderSVGConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 4 {
				img, err := Decode([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2"><path fill="red" d="M0 0h2v2H0z"/></svg>`), "SVG ", 0, 0)
				if err != nil {
					t.Error(err)
					return
				}
				if got := color.RGBAModel.Convert(img.At(0, 0)); got != (color.RGBA{255, 0, 0, 255}) {
					t.Errorf("pixel = %v", got)
				}
			}
		})
	}
	wg.Wait()
}

func TestRenderSVGNativeDeclaredEncoding(t *testing.T) {
	data := []byte("<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"><!--caf\xe9--><path fill=\"red\" d=\"M0 0h1v1H0z\"/></svg>")
	img, err := Decode(data, "SVG ", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := color.RGBAModel.Convert(img.At(0, 0)); got != (color.RGBA{255, 0, 0, 255}) {
		t.Fatalf("encoded SVG pixel = %v", got)
	}
}
