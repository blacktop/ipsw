package car

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func writeCatalog(t *testing.T, data []byte) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "synthetic.car")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestMetadataOnlyAndRawSkipPixelDecoding(t *testing.T) {
	var orientation bytes.Buffer
	for _, value := range []any{MetaDataEXIFOrientationID, uint32(4), uint32(6)} {
		writeValue(t, &orientation, binary.LittleEndian, value)
	}
	var payload bytes.Buffer
	writeValue(t, &payload, binary.LittleEndian, csiBitmap{Signature: [4]byte{'M', 'L', 'E', 'C'}, Encoding: Deepmap2, Length: 100})
	// An intentionally absent stream proves metadata inspection never activates
	// decompression. The dimensions also exceed the raster allocation limit.
	csi := syntheticCSI(t, "sample", PixFmtARGB, OnePart, 20000, 20000, orientation.Bytes(), payload.Bytes())
	binary.LittleEndian.PutUint32(csi[20:], 200)
	binary.LittleEndian.PutUint32(csi[28:], uint32(DisplayP3))
	input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{{[]uint16{1, 2}, csi}}, []renditionAttributeType{Identifier, Scale}))
	for _, conf := range []*Config{{MetadataOnly: true, Export: true, Output: filepath.Join(t.TempDir(), "absent")}, {Raw: true}} {
		a, err := Parse(input, conf)
		if err != nil {
			t.Fatal(err)
		}
		r := a.ImageDB[0]
		if !r.Deferred || !r.Selected || r.DecodeError != nil || r.Asset != nil || !bytes.Equal(r.rawCSI, csi) {
			t.Fatalf("metadata path decoded or lost source: %+v", r)
		}
		if r.Width != 20000 || r.Height != 20000 || r.Scale != 200 || r.Compression != Deepmap2.String() || r.Orientation != 6 || r.ColorSpace != DisplayP3 {
			t.Fatalf("missing metadata: %+v", r)
		}
		if stats := a.Stats(); stats != (CatalogStats{Total: 1, Selected: 1, Deferred: 1, SelectedDeferred: 1}) {
			t.Fatalf("metadata stats = %+v", stats)
		}
		if conf.Export {
			if _, err := os.Stat(conf.Output); !os.IsNotExist(err) {
				t.Fatalf("metadata inspection created export directory: %v", err)
			}
		}
	}
	a, err := Parse(input, nil)
	if err != nil || a.ImageDB[0].DecodeError == nil || a.ImageDB[0].Deferred {
		t.Fatalf("default parse did not decode malformed input: %v", err)
	}
}

func TestFilteredParseDecodesExactReferenceDependency(t *testing.T) {
	var raster bytes.Buffer
	writeValue(t, &raster, binary.LittleEndian, csiBitmap{Signature: [4]byte{'M', 'L', 'E', 'C'}, Length: 8})
	raster.Write([]byte{0, 0, 255, 255, 0, 255, 0, 255})
	items := []syntheticRendition{
		{[]uint16{1}, syntheticCSI(t, "selected", PixFmtARGB, InternalLink, 1, 1, nil, syntheticLink(t, 3))},
		{[]uint16{2}, syntheticCSI(t, "broken", PixFmtARGB, OnePart, 1, 1, nil, []byte("invalid"))},
		{[]uint16{3}, syntheticCSI(t, "hidden", PixFmtARGB, PackedImage, 2, 1, nil, raster.Bytes())},
	}
	a, err := Parse(writeCatalog(t, syntheticCatalog(t, items, []renditionAttributeType{Identifier})), &Config{Query: &VariantQuery{Names: []string{"select*"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.ImageDB) != 3 || a.ImageDB[1].DecodeError != nil || !a.ImageDB[1].Deferred || a.ImageDB[2].Deferred || a.ImageDB[2].Selected {
		t.Fatalf("filter lost inventory or decoded wrong entries: %+v", a.Stats())
	}
	img, ok := a.ImageDB[0].Asset.(image.Image)
	if !ok || color.NRGBAModel.Convert(img.At(0, 0)) != (color.NRGBA{G: 255, A: 255}) {
		t.Fatalf("filtered reference was not resolved: %v", a.ImageDB[0].ResolveError)
	}
	if stats := a.Stats(); stats != (CatalogStats{Total: 3, Selected: 1, Deferred: 1}) {
		t.Fatalf("filtered stats = %+v", stats)
	}
}

func TestVariantQueryMatchesExactAttributesAndLogicalNames(t *testing.T) {
	zero, one, two := uint16(0), uint16(1), uint16(2)
	format := []renditionAttributeType{Identifier, Scale, Idiom, ThemeAppearance, Localization, DisplayGamut}
	base := []uint16{42, 2, 0, 1, 2, 1}
	a := Asset{
		KeyFormat: format,
		FacetKeyDB: map[string]renditionKeyToken{
			"a-first-alias": {Attributes: []renditionAttribute{{Name: uint16(Identifier), Value: 42}}},
			"logical-icon":  {Attributes: []renditionAttribute{{Name: uint16(Identifier), Value: 42}}},
		},
		conf: &Config{MetadataOnly: true, Query: &VariantQuery{Names: []string{"logical-*"}, Scale: &two, Idiom: &zero, Appearance: &one, Localization: &two, DisplayGamut: &one}},
	}
	for i := range len(format) {
		key := append([]uint16(nil), base...)
		if i > 0 {
			key[i]++
		}
		attributes := make(map[string]uint16)
		for j, token := range format {
			attributes[token.String()] = key[j]
		}
		a.ImageDB = append(a.ImageDB, Rendition{Key: key, Attributes: attributes, RenditionName: "stored-file.png", Deferred: true})
	}
	if err := a.selectRenditions(a.indexRenditions()); err != nil {
		t.Fatal(err)
	}
	if a.Stats().Selected != 1 || !a.ImageDB[0].Selected {
		t.Fatalf("exact variant query selected wrong keys: %+v", a.Stats())
	}
	delete(a.ImageDB[0].Attributes, Idiom.String())
	if a.conf.Query.matches(&a.ImageDB[0], "logical-icon") {
		t.Fatal("missing idiom matched explicit zero")
	}
	a.conf.Query.Names = []string{"["}
	if err := a.selectRenditions(a.indexRenditions()); err == nil {
		t.Fatal("invalid glob was accepted")
	}
}

func TestParseRetainsOptionalBlocksAndRejectsCorruptDirectories(t *testing.T) {
	optional := OpaqueBlock{Name: "FUTURE_METADATA", Data: []byte{1, 2, 3, 4}}
	data := syntheticCatalog(t, nil, []renditionAttributeType{Identifier}, optional)
	a, err := Parse(writeCatalog(t, data), &Config{MetadataOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.UnknownBlocks) != 1 || a.UnknownBlocks[0].Name != optional.Name || !bytes.Equal(a.UnknownBlocks[0].Data, optional.Data) || len(a.Diagnostics) != 1 || a.Diagnostics[0].Block != optional.Name {
		t.Fatalf("unknown block was lost: %+v, %+v", a.UnknownBlocks, a.Diagnostics)
	}
	for _, mutate := range []struct {
		name string
		fn   func([]byte)
	}{
		{"unknown block extent", func(data []byte) {
			count := binary.BigEndian.Uint32(data[32:])
			binary.BigEndian.PutUint32(data[36+8*(count-1)+4:], 100000)
		}},
		{"pointer count", func(data []byte) { binary.BigEndian.PutUint32(data[32:], ^uint32(0)) }},
		{"variable count", func(data []byte) {
			offset := binary.BigEndian.Uint32(data[24:])
			binary.BigEndian.PutUint32(data[offset:], ^uint32(0))
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			corrupt := append([]byte(nil), data...)
			mutate.fn(corrupt)
			if _, err := Parse(writeCatalog(t, corrupt), &Config{MetadataOnly: true}); err == nil || !strings.Contains(err.Error(), "invalid CAR BOM") {
				t.Fatalf("corrupt directory accepted: %v", err)
			}
		})
	}
}

func TestMetadataOnlyRejectsDuplicateExactKeys(t *testing.T) {
	item := syntheticRendition{[]uint16{1}, syntheticCSI(t, "duplicate", PixFmtARGB, OnePart, 1, 1, nil, nil)}
	input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{item, item}, []renditionAttributeType{Identifier}))
	if _, err := Parse(input, &Config{MetadataOnly: true}); err == nil || !strings.Contains(err.Error(), "duplicate rendition key") {
		t.Fatalf("metadata-only accepted ambiguous catalog: %v", err)
	}
}

func TestParseRejectsMissingRequiredBlocks(t *testing.T) {
	item := syntheticRendition{[]uint16{1}, syntheticCSI(t, "sample", PixFmtARGB, OnePart, 1, 1, nil, nil)}
	original := syntheticCatalog(t, []syntheticRendition{item}, []renditionAttributeType{Identifier})
	for _, tc := range []struct{ old, renamed, want string }{
		{"CARHEADER", "FUTUREHDR", "CARHEADER"},
		{"RENDITIONS", "FUTURETREE", "RENDITIONS"},
	} {
		t.Run(tc.old, func(t *testing.T) {
			data := bytes.Replace(original, []byte(tc.old), []byte(tc.renamed), 1)
			if _, err := Parse(writeCatalog(t, data), &Config{MetadataOnly: true}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("missing required block accepted: %v", err)
			}
		})
	}
}

func TestOptionalBlockRetentionHasAggregateLimit(t *testing.T) {
	data := syntheticCatalog(t, nil, []renditionAttributeType{Identifier}, OpaqueBlock{Name: "FUTURE", Data: []byte{1, 2, 3, 4}})
	bm, err := bom.New(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	a := Asset{retainedBlockBytes: pixel.MaxBytes - 3}
	if err := a.retainBlock(bm, "FUTURE", "retained"); err == nil || len(a.UnknownBlocks) != 0 || a.retainedBlockBytes != pixel.MaxBytes-3 {
		t.Fatalf("retained bytes exceeded aggregate limit: %v", err)
	}
	a.retainedBlockBytes = pixel.MaxBytes - 4
	if err := a.retainBlock(bm, "FUTURE", "retained"); err != nil || len(a.UnknownBlocks) != 1 || a.retainedBlockBytes != pixel.MaxBytes {
		t.Fatalf("exact retention limit failed: %v", err)
	}
}

func TestParseRejectsBOMForwardCycle(t *testing.T) {
	data := syntheticCatalog(t, nil, []renditionAttributeType{Identifier})
	bm, err := bom.New(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	// syntheticCatalog puts the RENDITIONS leaf in block 3.
	leaf := bm.BlockTable.BlockPointers[3]
	binary.BigEndian.PutUint32(data[int(leaf.Address)+4:], 3)
	input := writeCatalog(t, data)
	for _, conf := range []*Config{nil, {MetadataOnly: true}, {Raw: true}} {
		if _, err := Parse(input, conf); err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("cyclic catalog parse = %v", err)
		}
	}
}
