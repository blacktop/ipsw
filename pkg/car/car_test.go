package car

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/bom"
)

type syntheticRendition struct {
	key  []uint16
	data []byte
}

func writeValue(t *testing.T, buffer *bytes.Buffer, order binary.ByteOrder, value any) {
	t.Helper()
	if err := binary.Write(buffer, order, value); err != nil {
		t.Fatal(err)
	}
}

func syntheticCSI(t *testing.T, name, format string, layout renditionLayoutType, width, height uint32, resources, payload []byte) []byte {
	t.Helper()
	var header csiHeader
	header.Version = 1
	header.Width = width
	header.Height = height
	header.Metadata.Layout = layout
	copy(header.Metadata.Name[:], name)
	for i := range min(4, len(format)) {
		header.PixelFormat[3-i] = format[i]
	}
	var b bytes.Buffer
	writeValue(t, &b, binary.BigEndian, CsiFileSignature)
	for _, value := range []any{header.Version, header.Flags, header.Width, header.Height, header.ScaleFactor, header.PixelFormat, header.ColorSpace, header.Metadata, uint32(len(resources)), uint32(0), uint32(len(payload))} {
		writeValue(t, &b, binary.LittleEndian, value)
	}
	b.Write(resources)
	b.Write(payload)
	return b.Bytes()
}

func syntheticLink(t *testing.T, target uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	writeValue(t, &b, binary.BigEndian, CsiInternalLinkSignature)
	for _, value := range []any{uint32(0), linkRect{1, 0, 1, 1}, uint16(OnePart), uint32(8), []renditionAttribute{{uint16(Identifier), target}, {0, 0}}} {
		writeValue(t, &b, binary.LittleEndian, value)
	}
	return b.Bytes()
}

// A complete in-memory BOM with CAR header, key format and rendition B-tree.
func syntheticCatalog(t *testing.T, items []syntheticRendition, format []renditionAttributeType, optional ...OpaqueBlock) []byte {
	t.Helper()
	var blocks [][]byte
	add := func(data []byte) uint32 {
		index := uint32(len(blocks))
		blocks = append(blocks, append([]byte(nil), data...))
		return index
	}
	var b bytes.Buffer
	var header Header
	header.Tag = [4]byte{'R', 'A', 'T', 'C'}
	header.RenditionCount = uint32(len(items))
	writeValue(t, &b, binary.LittleEndian, header)
	headerIndex := add(b.Bytes())
	b.Reset()
	writeValue(t, &b, binary.LittleEndian, [4]byte{'t', 'm', 'f', 'k'})
	writeValue(t, &b, binary.LittleEndian, uint32(1))
	writeValue(t, &b, binary.LittleEndian, uint32(len(format)))
	writeValue(t, &b, binary.LittleEndian, format)
	keyFormatIndex := add(b.Bytes())
	b.Reset()
	treeIndex := add(nil)
	leafIndex := add(nil)
	var indices [][2]uint32
	for _, item := range items {
		writeValue(t, &b, binary.LittleEndian, item.key)
		keyIndex := add(b.Bytes())
		b.Reset()
		valueIndex := add(item.data)
		indices = append(indices, [2]uint32{valueIndex, keyIndex})
	}
	writeValue(t, &b, binary.BigEndian, bom.TreeHeader{Magic: [4]byte{'t', 'r', 'e', 'e'}, Version: 1, Child: leafIndex, PathCount: uint32(len(items))})
	blocks[treeIndex] = append([]byte(nil), b.Bytes()...)
	b.Reset()
	for _, value := range []any{uint16(1), uint16(len(items)), uint32(0), uint32(0), indices} {
		writeValue(t, &b, binary.BigEndian, value)
	}
	blocks[leafIndex] = append([]byte(nil), b.Bytes()...)
	b.Reset()
	vars := []bom.Var{{BlockTableIndex: headerIndex, Name: "CARHEADER"}, {BlockTableIndex: treeIndex, Name: "RENDITIONS"}, {BlockTableIndex: keyFormatIndex, Name: "KEYFORMAT"}}
	for _, block := range optional {
		vars = append(vars, bom.Var{BlockTableIndex: add(block.Data), Name: block.Name})
	}
	writeValue(t, &b, binary.BigEndian, uint32(len(vars)))
	for _, v := range vars {
		writeValue(t, &b, binary.BigEndian, v.BlockTableIndex)
		writeValue(t, &b, binary.BigEndian, uint8(len(v.Name)))
		b.WriteString(v.Name)
	}
	varsData := append([]byte(nil), b.Bytes()...)
	b.Reset()
	indexOffset := uint32(32)
	indexLength := uint32(4 + 8*len(blocks))
	varsOffset := indexOffset + indexLength
	offset := varsOffset + uint32(len(varsData))
	b.WriteString("BOMStore")
	writeValue(t, &b, binary.BigEndian, []uint32{1, uint32(len(blocks)), indexOffset, indexLength, varsOffset, uint32(len(varsData))})
	writeValue(t, &b, binary.BigEndian, uint32(len(blocks)))
	for _, block := range blocks {
		writeValue(t, &b, binary.BigEndian, bom.Pointer{Address: offset, Length: uint32(len(block))})
		offset += uint32(len(block))
	}
	b.Write(varsData)
	for _, block := range blocks {
		b.Write(block)
	}
	return b.Bytes()
}

func TestParseResolvesHiddenTargetAndContinuesAfterPayloadFailure(t *testing.T) {
	var raster bytes.Buffer
	writeValue(t, &raster, binary.LittleEndian, csiBitmap{Signature: [4]byte{'M', 'L', 'E', 'C'}, Length: 16})
	raster.Write([]byte{0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255, 255, 255, 255, 255})
	var raw bytes.Buffer
	raw.WriteString("DWAR")
	writeValue(t, &raw, binary.LittleEndian, []uint32{0, 4})
	raw.WriteString("data")
	var reference bytes.Buffer
	link := syntheticLink(t, 3)
	writeValue(t, &reference, binary.LittleEndian, InternalLinkID)
	writeValue(t, &reference, binary.LittleEndian, uint32(len(link)))
	reference.Write(link)
	items := []syntheticRendition{
		{[]uint16{1}, syntheticCSI(t, "../../logical", PixFmtARGB, InternalLink, 1, 1, reference.Bytes(), nil)},
		{[]uint16{2}, syntheticCSI(t, "broken", PixFmtARGB, OnePart, 2, 2, nil, []byte("truncated"))},
		{[]uint16{3}, syntheticCSI(t, "hidden atlas", PixFmtARGB, PackedImage, 2, 2, nil, raster.Bytes())},
		{[]uint16{4}, syntheticCSI(t, "raw.bin", PixFmtRawData, RawData, 0, 0, nil, raw.Bytes())},
	}
	input := filepath.Join(t.TempDir(), "synthetic.car")
	if err := os.WriteFile(input, syntheticCatalog(t, items, []renditionAttributeType{Identifier}), 0600); err != nil {
		t.Fatal(err)
	}
	// Nil configuration still decodes and retains raw payloads.
	a, err := Parse(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.ImageDB) != 4 {
		t.Fatalf("inventory = %d", len(a.ImageDB))
	}
	if a.ImageDB[1].DecodeError == nil || a.ImageDB[0].ResolveError != nil {
		t.Fatalf("decode/resolve errors: %v, %v", a.ImageDB[1].DecodeError, a.ImageDB[0].ResolveError)
	}
	if got, ok := a.ImageDB[3].Asset.([]byte); !ok || string(got) != "data" {
		t.Fatalf("raw payload = %v", a.ImageDB[3].Asset)
	}
	resolved, ok := a.ImageDB[0].Asset.(image.Image)
	if !ok {
		t.Fatalf("link asset %T", a.ImageDB[0].Asset)
	}
	if got := color.NRGBAModel.Convert(resolved.At(0, 0)); got != (color.NRGBA{255, 255, 255, 255}) {
		t.Fatalf("reference pixel = %v", got)
	}
	output := t.TempDir()
	a, err = Parse(input, &Config{Export: true, Output: output})
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(output)
	if err != nil || len(files) != 3 {
		t.Fatalf("exports = %d, error = %v", len(files), err)
	}
	for _, i := range []int{0, 2, 3} {
		if a.ImageDB[i].ExportPath == "" || a.ImageDB[i].ExportError != nil {
			t.Fatalf("rendition %d not exported: %v", i, a.ImageDB[i].ExportError)
		}
	}
	f, err := os.Open(a.ImageDB[0].ExportPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil || img.Bounds() != image.Rect(0, 0, 1, 1) {
		t.Fatalf("exported crop: %v, %v", img, err)
	}
}

func TestParseRejectsStructuralCorruption(t *testing.T) {
	for _, tc := range []struct {
		name     string
		key      []uint16
		format   []renditionAttributeType
		resource []byte
		want     string
	}{
		{"short key", nil, []renditionAttributeType{Identifier}, nil, "key has"},
		{"duplicate key token", []uint16{1, 1}, []renditionAttributeType{Identifier, Identifier}, nil, "duplicate key format"},
		{"short resource", []uint16{1}, []renditionAttributeType{Identifier}, []byte{1}, "EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := syntheticCSI(t, "test", PixFmtRawData, RawData, 0, 0, tc.resource, nil)
			input := filepath.Join(t.TempDir(), "synthetic.car")
			if err := os.WriteFile(input, syntheticCatalog(t, []syntheticRendition{{tc.key, data}}, tc.format), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(input, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parse error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseInternalLinkPayloadCompatibility(t *testing.T) {
	a := Asset{KeyFormat: []renditionAttributeType{Identifier}, conf: &Config{}}
	data := syntheticCSI(t, "legacy", "", InternalLink, 1, 1, nil, syntheticLink(t, 3))
	rend, err := a.parseRendition([]byte{1, 0}, data)
	if err != nil {
		t.Fatal(err)
	}
	if rend.DecodeError != nil || rend.link == nil {
		t.Fatalf("legacy payload reference: %v", rend.DecodeError)
	}
}

func TestParsePreservesLongKeys(t *testing.T) {
	items := []syntheticRendition{
		{[]uint16{7, 1}, syntheticCSI(t, "first", PixFmtRawData, RawData, 0, 0, nil, []byte("a"))},
		{[]uint16{7, 2}, syntheticCSI(t, "second", PixFmtRawData, RawData, 0, 0, nil, []byte("b"))},
	}
	input := writeCatalog(t, syntheticCatalog(t, items, []renditionAttributeType{Identifier}))
	for _, metadataOnly := range []bool{false, true} {
		a, err := Parse(input, &Config{MetadataOnly: metadataOnly})
		if err != nil {
			t.Fatal(err)
		}
		for i, rend := range a.ImageDB {
			if !slices.Equal(rend.Key, items[i].key) || rend.ID() != 7 || len(rend.Attributes) != 1 {
				t.Fatalf("long key or named attributes lost: %+v", rend)
			}
		}
		plan := a.PlanExport("output")
		if plan[0].Path == plan[1].Path || !slices.Equal(plan[1].Key, items[1].key) {
			t.Fatalf("long keys collapsed during export: %+v", plan)
		}
		// A link with only the declared attributes cannot identify either suffix.
		link := referenceRendition(8, 7, linkRect{0, 0, 1, 1})
		link.Key = []uint16{8}
		link.Selected = true
		a.ImageDB = append(a.ImageDB, link)
		if err := a.resolveReferences(); err != nil {
			t.Fatal(err)
		}
		if err := a.ImageDB[2].ResolveError; err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("reference guessed an unknown key suffix: %v", err)
		}
	}
}

func TestParseEmptyKeyFormatWorkaround(t *testing.T) {
	item := syntheticRendition{[]uint16{42}, syntheticCSI(t, "sample", PixFmtRawData, RawData, 0, 0, nil, nil)}
	data := syntheticCatalog(t, []syntheticRendition{item}, []renditionAttributeType{Identifier},
		OpaqueBlock{Name: "KEYFORMATWORKAROUND", Data: make([]byte, 4)})
	// Put the empty workaround before KEYFORMAT so it must leave the format unset.
	start := int(binary.BigEndian.Uint32(data[24:])) + 4
	length := int(binary.BigEndian.Uint32(data[28:])) - 4
	vars := bytes.Clone(data[start : start+length])
	last := len(vars) - 5 - len("KEYFORMATWORKAROUND")
	copy(data[start:], append(vars[last:], vars[:last]...))
	a, err := Parse(writeCatalog(t, data), &Config{MetadataOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.KeyFormat, []renditionAttributeType{Identifier}) || a.ImageDB[0].ID() != 42 {
		t.Fatalf("empty workaround prevented KEYFORMAT parsing: %+v", a.KeyFormat)
	}
}

func TestParseMetadataTreesAcrossLeaves(t *testing.T) {
	var blocks []OpaqueBlock
	for _, name := range []string{"APPEARANCEKEYS", "BITMAPKEYS", "LOCALIZATIONKEYS"} {
		base := uint32(4 + len(blocks)) // Header, key format, and empty rendition tree occupy four blocks.
		var tree, first, second bytes.Buffer
		writeValue(t, &tree, binary.BigEndian, bom.TreeHeader{
			Magic: [4]byte{'t', 'r', 'e', 'e'}, Version: 1, Child: base + 1, PathCount: 2,
		})
		for _, value := range []any{uint16(1), uint16(1), base + 2, uint32(0), base + 4, base + 3} {
			writeValue(t, &first, binary.BigEndian, value)
		}
		for _, value := range []any{uint16(1), uint16(1), uint32(0), base + 1, base + 6, base + 5} {
			writeValue(t, &second, binary.BigEndian, value)
		}
		key1, key2 := []byte("first"), []byte("second")
		if name == "BITMAPKEYS" {
			// Bitmap identifiers are inline, even when they name a valid BOM block.
			binary.BigEndian.PutUint32(first.Bytes()[16:20], 1)
			binary.BigEndian.PutUint32(second.Bytes()[16:20], 0x10203040)
		}
		blocks = append(blocks, OpaqueBlock{Name: name, Data: tree.Bytes()})
		for i, data := range [][]byte{first.Bytes(), second.Bytes(), key1, {1, 0}, key2, {2, 0}} {
			blocks = append(blocks, OpaqueBlock{Name: name + string(rune('a'+i)), Data: data})
		}
	}
	path := writeCatalog(t, syntheticCatalog(t, nil, []renditionAttributeType{Identifier}, blocks...))
	for _, verbose := range []bool{false, true} {
		a, err := Parse(path, &Config{MetadataOnly: true, Verbose: verbose})
		if err != nil {
			t.Fatal(err)
		}
		if len(a.AppearanceDB) != 2 || a.AppearanceDB["second"] != 2 ||
			len(a.Localizations) != 2 || a.Localizations["second"] != 2 ||
			len(a.BitmapKeyDB) != 2 || !bytes.Equal(a.BitmapKeyDB[uint32(1)], []byte{1, 0}) ||
			!bytes.Equal(a.BitmapKeyDB[uint32(0x10203040)], []byte{2, 0}) {
			t.Fatalf("verbose=%t: incomplete trees: %v, %v, %v",
				verbose, a.AppearanceDB, a.Localizations, a.BitmapKeyDB)
		}
	}
}

func TestParsePayloadSharesCSIWithoutMutatingIt(t *testing.T) {
	payload := bitmapFixture(t, Uncompressed, nil, []byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint32(payload[4:], 2) // Opaque conversion replaces stored alpha.
	csi := syntheticCSI(t, "opaque", PixFmtARGB, OnePart, 1, 1, nil, payload)
	input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{{[]uint16{1}, csi}},
		[]renditionAttributeType{Identifier}))
	a, err := Parse(input, &Config{Query: &VariantQuery{Names: []string{"unselected"}}})
	if err != nil {
		t.Fatal(err)
	}
	rend := &a.ImageDB[0]
	if !rend.Deferred || &rend.payload[0] != &rend.rawCSI[len(csi)-len(payload)] {
		t.Fatal("unselected payload does not share its CSI storage")
	}
	if err := a.ensureDecoded(0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rend.rawCSI, csi) {
		t.Fatal("opaque image decoding mutated the original CSI")
	}
	if _, _, _, alpha := rend.Asset.(image.Image).At(0, 0).RGBA(); alpha != 65535 {
		t.Fatalf("opaque conversion did not run: %d", alpha)
	}
}

// BITMAPKEYS uses inline identifiers and may precede the rendition key format.
func TestParseBitmapKeysUseInlineIDsBeforeKeyFormat(t *testing.T) {
	data := syntheticCatalog(t, []syntheticRendition{{key: []uint16{42, 0}, data: []byte("bitmap payload")}}, []renditionAttributeType{Identifier})
	// The equal-length name replacement reuses the fixture's independent BOM tree.
	data = bytes.Replace(data, []byte("RENDITIONS"), []byte("BITMAPKEYS"), 1)
	// This fixture now contains only bitmap keys, so it advertises no renditions.
	bm, err := bom.New(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	headerOffset := bm.BlockTable.BlockPointers[0].Address
	binary.LittleEndian.PutUint32(data[headerOffset+16:], 0)
	// Block 4 contains the four-byte key value 42; block 5 contains a longer
	// payload. Neither block's contents may replace a small inline identifier.
	leafOffset := bm.BlockTable.BlockPointers[3].Address
	for _, key := range []uint32{0, 4, 5, 0x10203040} {
		binary.BigEndian.PutUint32(data[leafOffset+16:], key)
		a, err := Parse(writeCatalog(t, data), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(a.BitmapKeyDB[key]); len(a.BitmapKeyDB) != 1 || got != "bitmap payload" {
			t.Fatalf("inline bitmap key %d: got %q, map=%v", key, got, a.BitmapKeyDB)
		}
	}
}

func TestSetOriginalPayloadPreservesSource(t *testing.T) {
	data := []byte(`<svg width="1" height="1"/>`)
	for _, format := range []string{PixFmtRawData, PixFmtSVG, PixFmtPDF, PixFmtHEIF} {
		for _, conf := range []*Config{nil, {}} {
			asset := Asset{conf: conf}
			rend := Rendition{PixelFormat: format}
			if err := asset.setOriginalPayload(&rend, data); err != nil {
				t.Fatal(err)
			}
			if original, ok := rend.Asset.([]byte); !ok || !bytes.Equal(original, data) {
				t.Fatalf("original %s was changed without Render", format)
			}
		}
	}
	asset := Asset{conf: &Config{Render: true}}
	rend := Rendition{RenditionName: "fake.svg", PixelFormat: PixFmtRawData}
	if err := asset.setOriginalPayload(&rend, []byte("ordinary data")); err != nil {
		t.Fatal(err)
	}
	if _, ok := rend.Asset.([]byte); !ok {
		t.Fatal("rendition filename selected a renderer for non-image data")
	}
}

func TestUnsupportedImageCodecs(t *testing.T) {
	for _, format := range []byte{0x12, 0x22} { // Unimplemented wide grayscale storage variants.
		blob := []byte{'d', 'm', 'p', '2', 1, 0, 0, format, 1, 0, 1, 0}
		data := binary.LittleEndian.AppendUint32(nil, 1)
		data = binary.LittleEndian.AppendUint32(data, uint32(format))
		data = binary.LittleEndian.AppendUint64(data, uint64(len(blob)))
		data = append(data, blob...)
		var payload bytes.Buffer
		writeValue(t, &payload, binary.LittleEndian, csiBitmap{
			Signature: [4]byte{'M', 'L', 'E', 'C'}, Encoding: Deepmap2, Length: uint32(len(data))})
		payload.Write(data)
		csi := syntheticCSI(t, "mask", PixFmtGray16, OnePart, 1, 1, nil, payload.Bytes())
		input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{{[]uint16{1}, csi}},
			[]renditionAttributeType{Identifier}))
		a, err := Parse(input, &Config{Export: true, Output: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(a.ImageDB[0].DecodeError, errUnsupportedRendition) ||
			a.PlanExport(a.conf.Output)[0].Status != "unsupported" || a.Stats().DecodeFailures != 0 {
			t.Fatalf("unsupported Deepmap2 format became a failure: %+v", a.ImageDB[0])
		}
	}
	for _, encoding := range []compressionType{BlurredImage, HEVC} {
		var payload bytes.Buffer
		writeValue(t, &payload, binary.LittleEndian, csiBitmap{
			Signature: [4]byte{'M', 'L', 'E', 'C'}, Encoding: encoding, Length: 1})
		payload.WriteByte(0)
		h := csiHeader{Width: 1, Height: 1, PixelFormat: [4]byte{'B', 'G', 'R', 'A'}}
		if _, err := decodeImage(&payload, h, nil, 0); !errors.Is(err, errUnsupportedRendition) {
			t.Fatalf("unsupported %s classification: %v", encoding, err)
		}
	}
}

func TestHEVCExportClassification(t *testing.T) {
	heif := []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1', 0, 0, 0, 0, 'h', 'e', 'i', 'c'}
	wrapper := binary.LittleEndian.AppendUint32(nil, 0)
	wrapper = binary.LittleEndian.AppendUint32(wrapper, uint32(len(heif)))
	wrapper = append(wrapper, heif...)
	for _, tc := range []struct {
		name, status string
		payload      []byte
	}{
		{"heif", "exported", bitmapFixture(t, HEVC, nil, wrapper)},
		{"chunks", "unsupported", bitmapFixture(t, HEVC, []uint32{1, 1}, wrapper, wrapper)},
		{"bad wrapper", "failed", bitmapFixture(t, HEVC, nil, []byte("bad"))},
		{"blurred", "unsupported", bitmapFixture(t, BlurredImage, nil, []byte{0})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := writeCatalog(t, syntheticCatalog(t, []syntheticRendition{{[]uint16{1},
				syntheticCSI(t, "sample", PixFmtARGB, OnePart, 1, 1, nil, tc.payload)}},
				[]renditionAttributeType{Identifier}))
			a, err := Parse(input, &Config{Export: true, Output: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			if got := a.PlanExport(a.conf.Output)[0]; got.Status != tc.status {
				t.Fatalf("HEVC public export = %+v, want %s", got, tc.status)
			}
		})
	}
}
