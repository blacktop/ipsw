package car

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"slices"
	"strings"
	"testing"
)

func resolveTestReferences(a *Asset) error {
	index := a.indexRenditions()
	if err := index.validate(a); err != nil {
		return err
	}
	a.resolveReferences(index)
	return nil
}

func TestReferenceCacheRetainsLeafImageAndFailure(t *testing.T) {
	var data bytes.Buffer
	if err := jpeg.Encode(&data, image.NewRGBA(image.Rect(0, 0, 1, 1)), nil); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []bool{false, true} {
		source := data.Bytes()
		if invalid {
			source = []byte("invalid JPEG")
		}
		a := Asset{ImageDB: []Rendition{{Asset: source, PixelFormat: PixFmtJPEG, ColorSpace: DisplayP3}}}
		cache := make(map[referenceCacheKey]referenceValue)
		first, space, firstErr := a.resolveReference(
			0, a.indexRenditions(), cache, make(map[int]bool), 0, false)
		if (firstErr != nil) != invalid || !invalid && space != DisplayP3 {
			t.Fatalf("unexpected first decode: %v, %v", space, firstErr)
		}
		// Changing the source after the first access proves this pass reuses
		// both successful rasters and failures instead of decoding again.
		a.ImageDB[0].Asset = data.Bytes()
		if !invalid {
			a.ImageDB[0].Asset = []byte("changed source")
		}
		second, _, secondErr := a.resolveReference(
			0, a.indexRenditions(), cache, make(map[int]bool), 0, false)
		if first != second || firstErr != secondErr {
			t.Fatal("shared target was decoded again")
		}
	}
}

func referenceRendition(id, target uint16, frame linkRect) Rendition {
	return Rendition{RenditionName: "synthetic", Key: []uint16{id, 0}, link: &csiInternalLinkData{Reference: []renditionAttribute{{uint16(Identifier), target}}, Frame: frame}}
}

func TestResolveReferencesUsesExactKeysAndNestedCrops(t *testing.T) {
	atlas := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	for y := range 4 {
		for x := range 4 {
			atlas.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 40), G: uint8(y * 40), A: 255})
		}
	}
	inner := referenceRendition(2, 3, linkRect{1, 1, 2, 2})
	inner.link.Reference = append(inner.link.Reference, renditionAttribute{uint16(Scale), 200})
	a := Asset{KeyFormat: []renditionAttributeType{Identifier, Scale}, ImageDB: []Rendition{
		referenceRendition(1, 2, linkRect{0, 0, 1, 1}),
		inner,
		{RenditionName: "synthetic", Key: []uint16{3, 100}, Asset: image.NewNRGBA(image.Rect(0, 0, 1, 1))},
		{RenditionName: "hidden atlas", Key: []uint16{3, 200}, Asset: atlas},
	}}
	if err := resolveTestReferences(&a); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1} {
		if err := a.ImageDB[index].ResolveError; err != nil {
			t.Fatalf("rendition %d: %v", index, err)
		}
	}
	got, ok := a.ImageDB[0].Asset.(image.Image)
	if !ok {
		t.Fatalf("unresolved asset: %T", a.ImageDB[0].Asset)
	}
	if got.Bounds() != image.Rect(0, 0, 1, 1) {
		t.Fatalf("bounds = %v", got.Bounds())
	}
	want := atlas.NRGBAAt(1, 2) // Each frame has a bottom-left origin.
	if pixel := color.NRGBAModel.Convert(got.At(0, 0)); pixel != want {
		t.Fatalf("pixel = %v, want %v", pixel, want)
	}
}

func TestResolveReferencesErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Asset)
		want   string
	}{
		{"missing exact variant", func(a *Asset) {
			a.ImageDB[0].link.Reference = append(a.ImageDB[0].link.Reference, renditionAttribute{uint16(Scale), 300})
		}, "not found"},
		{"cycle", func(a *Asset) { a.ImageDB[1] = referenceRendition(2, 1, linkRect{0, 0, 1, 1}) }, "cycle"},
		{"unknown attribute", func(a *Asset) {
			a.ImageDB[0].link.Reference = append(a.ImageDB[0].link.Reference, renditionAttribute{65535, 1})
		}, "unknown reference attribute"},
		{"duplicate attribute", func(a *Asset) {
			a.ImageDB[0].link.Reference = append(a.ImageDB[0].link.Reference, renditionAttribute{uint16(Identifier), 2})
		}, "duplicate reference attribute"},
		{"after terminator", func(a *Asset) {
			a.ImageDB[0].link.Reference = append(a.ImageDB[0].link.Reference, renditionAttribute{}, renditionAttribute{uint16(Scale), 200})
		}, "after terminator"},
		{"crop bounds", func(a *Asset) { a.ImageDB[0].link.Frame.X = ^uint32(0) }, "exceeds source"},
		{"source decode", func(a *Asset) { a.ImageDB[1].DecodeError = fmt.Errorf("synthetic decode failure") }, "synthetic decode failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Asset{KeyFormat: []renditionAttributeType{Identifier, Scale}, ImageDB: []Rendition{referenceRendition(1, 2, linkRect{0, 0, 1, 1}), {RenditionName: "synthetic", Key: []uint16{2, 0}, Asset: image.NewNRGBA(image.Rect(0, 0, 2, 2))}}}
			tc.mutate(&a)
			if err := resolveTestReferences(&a); err != nil {
				t.Fatal(err)
			}
			if err := a.ImageDB[0].ResolveError; err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("resolve error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestResolveReferencesDepthAndDuplicateKeys(t *testing.T) {
	a := Asset{KeyFormat: []renditionAttributeType{Identifier, Scale}}
	for id := uint16(1); id <= maxReferenceDepth+1; id++ {
		a.ImageDB = append(a.ImageDB, referenceRendition(id, id+1, linkRect{0, 0, 1, 1}))
	}
	a.ImageDB = append(a.ImageDB, Rendition{Key: []uint16{maxReferenceDepth + 2, 0}, Asset: image.NewNRGBA(image.Rect(0, 0, 1, 1))})
	if err := resolveTestReferences(&a); err != nil {
		t.Fatal(err)
	}
	if err := a.ImageDB[0].ResolveError; err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("depth error = %v", err)
	}
	if err := a.ImageDB[1].ResolveError; err != nil {
		t.Fatalf("16 links should resolve: %v", err)
	}
	a.ImageDB = append(a.ImageDB, a.ImageDB[0])
	err := resolveTestReferences(&a)
	if err == nil || !strings.Contains(err.Error(), "duplicate rendition key") {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestValidateKeyFormat(t *testing.T) {
	for _, tokens := range [][]renditionAttributeType{nil, {Identifier, Identifier}, {65536}} {
		if err := validateKeyFormat(tokens); err == nil {
			t.Fatalf("accepted invalid tokens: %v", tokens)
		}
	}
	if err := validateKeyFormat([]renditionAttributeType{Identifier, 65535}); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceCropPreservesDeepColor(t *testing.T) {
	source := image.NewNRGBA64(image.Rect(10, 20, 11, 22))
	source.SetNRGBA64(10, 21, color.NRGBA64{R: 1234, G: 5678, B: 9012, A: 65535})
	cropped, err := cropReference(source, linkRect{0, 0, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := color.NRGBA64Model.Convert(cropped.At(0, 0)); got != source.NRGBA64At(10, 21) {
		t.Fatalf("deep color changed: %v", got)
	}
}

func TestRawReferencesExportUnchangedDATA(t *testing.T) {
	link := func(target uint16) []byte {
		data := syntheticLink(t, target)
		binary.LittleEndian.PutUint16(data[24:], uint16(RawData))
		return data
	}
	original := []byte("synthetic animation archive\x00\xff")
	items := []syntheticRendition{
		{[]uint16{1}, syntheticCSI(t, "selected.caar", PixFmtARGB, InternalLink, 0, 0, nil, link(2))},
		{[]uint16{2}, syntheticCSI(t, "middle", PixFmtARGB, InternalLink, 0, 0, nil, link(3))},
		{[]uint16{3}, syntheticCSI(t, "source.caar", PixFmtRawData, RawData, 0, 0, nil, original)},
	}
	input := writeCatalog(t, syntheticCatalog(t, items, []renditionAttributeType{Identifier}))
	for _, metadataOnly := range []bool{true, false} {
		a, err := Parse(input, &Config{MetadataOnly: metadataOnly, Export: !metadataOnly,
			Render: true, Output: t.TempDir(), Query: &VariantQuery{Names: []string{"selected*"}}})
		if err != nil {
			t.Fatal(err)
		}
		plan := a.PlanExport(a.conf.Output)
		if len(plan) != 1 || plan[0].Format != "caar" || len(plan[0].Crops) != 0 ||
			!slices.Equal(plan[0].SourceKey, []uint16{3}) || plan[0].Error != "" {
			t.Fatalf("raw reference plan = %+v", plan)
		}
		if !metadataOnly {
			got, err := os.ReadFile(plan[0].Path)
			if err != nil || !bytes.Equal(got, original) || plan[0].Status != "exported" {
				t.Fatalf("raw reference output = %q, %v (%+v)", got, err, plan[0])
			}
		}
	}
}

func TestRawReferenceReusesDecodedDATA(t *testing.T) {
	link := syntheticLink(t, 2)
	binary.LittleEndian.PutUint16(link[24:], uint16(RawData))
	original := []byte("synthetic animation archive")
	items := []syntheticRendition{
		{[]uint16{1}, syntheticCSI(t, "link.caar", PixFmtARGB, InternalLink, 0, 0, nil, link)},
		{[]uint16{2}, syntheticCSI(t, "source.caar", PixFmtRawData, RawData, 0, 0, nil,
			bitmapFixture(t, Uncompressed, nil, original))},
	}
	a, err := Parse(writeCatalog(t, syntheticCatalog(t, items, []renditionAttributeType{Identifier})), nil)
	if err != nil {
		t.Fatal(err)
	}
	linked, linkOK := a.ImageDB[0].Asset.([]byte)
	source, sourceOK := a.ImageDB[1].Asset.([]byte)
	if !linkOK || !sourceOK || !bytes.Equal(linked, original) || !bytes.Equal(source, original) {
		t.Fatalf("raw reference lost original DATA: %v", a.ImageDB[0].ResolveError)
	}
	if &linked[0] != &source[0] {
		t.Fatal("raw reference retained a second decoded DATA buffer")
	}
}

func TestRawReferenceFailures(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(*Asset)
	}{
		{"cycle", "failed", func(a *Asset) { a.ImageDB[0].link.Reference[0].Value = 1 }},
		{"image target", "unsupported", func(a *Asset) { a.ImageDB[1].PixelFormat = PixFmtARGB }},
		{"bad target", "failed", func(a *Asset) { a.ImageDB[1].DecodeError = fmt.Errorf("invalid DATA") }},
		{"mixed chain", "unsupported", func(a *Asset) { a.ImageDB[1] = referenceRendition(2, 1, linkRect{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := referenceRendition(1, 2, linkRect{})
			r.link.Layout = uint16(RawData)
			r.Selected = true
			a := Asset{KeyFormat: []renditionAttributeType{Identifier, Scale}, selectionReady: true,
				ImageDB: []Rendition{r, {Key: []uint16{2, 0}, PixelFormat: PixFmtRawData, Asset: []byte("data")}}}
			tc.mutate(&a)
			if err := resolveTestReferences(&a); err != nil {
				t.Fatal(err)
			}
			if got := a.PlanExport("output")[0]; got.Status != tc.want {
				t.Fatalf("raw reference status = %+v", got)
			}
			if tc.want == "unsupported" && a.Stats().ResolveFailures != 0 {
				t.Fatal("unsupported target counted as failed")
			}
		})
	}
}

func TestRawReferenceBypassesRendering(t *testing.T) {
	for _, body := range []string{`<path fill="red" d="M0 0h1v1H0z"/>`, `<text>unsupported renderer element</text>`} {
		data := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">` + body + `</svg>`)
		link := syntheticLink(t, 2)
		binary.LittleEndian.PutUint16(link[24:], uint16(RawData))
		source := syntheticCSI(t, "source.svg", PixFmtRawData, RawData, 1, 1, nil, data)
		binary.LittleEndian.PutUint32(source[28:], uint32(DisplayP3))
		input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{
			{[]uint16{1}, syntheticCSI(t, "selected.svg", PixFmtARGB, InternalLink, 0, 0, nil, link)},
			{[]uint16{2}, source},
		}, []renditionAttributeType{Identifier}))
		for _, selectedOnly := range []bool{false, true} {
			conf := &Config{Render: true, Export: true, Output: t.TempDir()}
			if selectedOnly {
				conf.Query = &VariantQuery{Names: []string{"selected*"}}
			}
			a, err := Parse(input, conf)
			if err != nil {
				t.Fatal(err)
			}
			entry := a.PlanExport(conf.Output)[0]
			got, err := os.ReadFile(entry.Path)
			if err != nil || entry.Status != "exported" || entry.Format != "svg" ||
				entry.ColorSpace != DisplayP3.String() || !bytes.Equal(got, data) {
				t.Fatalf("raw reference depended on rendering: %+v, %v", entry, err)
			}
			if selectedOnly && !a.ImageDB[1].Deferred {
				t.Fatal("raw link activated target rendering")
			}
		}
	}
}
