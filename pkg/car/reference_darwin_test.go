//go:build darwin && !ios && cgo

package car

import (
	"bytes"
	"image"
	"os"
	"testing"
)

func TestRenderedReferencesPreserveOriginalMetadata(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2"><path fill="red" d="M0 0h2v2H0z"/></svg>`)
	a := Asset{
		KeyFormat: []renditionAttributeType{Identifier, Scale},
		conf:      &Config{Export: true, Output: t.TempDir()},
		ImageDB: []Rendition{
			{Key: []uint16{1, 0}, PixelFormat: PixFmtSVG, Asset: svg, Width: 2, Height: 2,
				ColorSpace: DisplayP3, Colorspace: DisplayP3.String()},
			referenceRendition(2, 1, linkRect{0, 0, 2, 2}),
			referenceRendition(3, 1, linkRect{1, 0, 1, 1}),
			referenceRendition(4, 2, linkRect{0, 0, 1, 1}),
		},
	}
	if err := resolveTestReferences(&a); err != nil {
		t.Fatal(err)
	}
	original := &a.ImageDB[0]
	if original.ColorSpace != DisplayP3 || original.Colorspace != DisplayP3.String() {
		t.Fatal("rendering a reference changed the original color space")
	}
	for _, rend := range a.ImageDB[1:] {
		if rend.ResolveError != nil || rend.ColorSpace != SRGB || rend.Colorspace != SRGB.String() {
			t.Fatalf("reference metadata: %s, %v", rend.Colorspace, rend.ResolveError)
		}
		if _, ok := rend.Asset.(image.Image); !ok {
			t.Fatalf("reference was not rendered: %T", rend.Asset)
		}
	}
	a.exportRenditions(a.indexRenditions())
	data, err := os.ReadFile(original.ExportPath)
	if err != nil || !bytes.Equal(data, svg) {
		t.Fatalf("original export changed: %v", err)
	}
	for i, entry := range a.PlanExport(a.conf.Output) {
		want := SRGB.String()
		if i == 0 {
			want = DisplayP3.String()
		}
		if entry.Status != "exported" || entry.ColorSpace != want {
			t.Fatalf("manifest color space or result: %+v", entry)
		}
	}
}
