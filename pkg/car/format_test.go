package car

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"strings"
	"testing"
)

func TestRenditionDiagnostics(t *testing.T) {
	a := Asset{ImageDB: []Rendition{{RenditionName: "fake", Key: []uint16{1, 2}, Asset: image.NewNRGBA64(image.Rect(0, 0, 2, 3)), DecodeError: errors.New("bad payload"), ResolveError: errors.New("missing target"), ExportError: errors.New("write failed")}}}
	data, err := a.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"DecodeError": "bad payload", "ResolveError": "missing target", "ExportError": "write failed"} {
		if result[1][key] != want {
			t.Fatalf("%s = %v", key, result[1][key])
		}
		if !strings.Contains(a.String(), want) {
			t.Fatalf("text missing %s", want)
		}
	}
	if result[1]["PixelWidth"] != float64(2) || result[1]["PixelHeight"] != float64(3) {
		t.Fatalf("missing image dimensions: %v", result[1])
	}
}

func TestFilteredMetadataOutputKeepsInventoryCounts(t *testing.T) {
	a := Asset{
		selectionReady: true,
		ImageDB: []Rendition{
			{RenditionName: "selected", Selected: true, Deferred: true, Key: []uint16{1}, Width: 12, Height: 34, Scale: 200, PixelFormat: PixFmtARGB, Compression: "Deepmap2", Colorspace: "Display P3", Orientation: 6, Warnings: []string{"example warning"}, Resources: []csiResource{{ID: resourceID(9999), Data: []byte{1, 2}}}},
			{RenditionName: "not-selected", Deferred: true, Key: []uint16{2}},
		},
		UnknownBlocks: []OpaqueBlock{{Name: "FUTURE", Data: []byte{1, 2, 3}}},
		Diagnostics:   []CatalogDiagnostic{{Block: "FUTURE", Message: "unknown optional block retained"}},
	}
	data, err := a.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result[1]["Deferred"] != true || result[1]["PixelWidth"] != float64(12) || result[1]["PixelHeight"] != float64(34) || result[1]["Compression"] != "Deepmap2" {
		t.Fatalf("selected metadata missing: %s", data)
	}
	stats, ok := result[0]["CatalogStats"].(map[string]any)
	if !ok || stats["total"] != float64(2) || stats["selected"] != float64(1) || stats["deferred"] != float64(2) {
		t.Fatalf("inventory counts = %v", result[0]["CatalogStats"])
	}
	for _, field := range []string{"UnknownBlocks", "Diagnostics"} {
		if result[0][field] == nil {
			t.Fatalf("missing %s", field)
		}
	}
	text := a.String()
	for _, expected := range []string{"2 total, 1 selected", "12x34", "Decoding: deferred", "Deepmap2", "example warning", "unknown optional block retained"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("metadata text missing %q", expected)
		}
	}
	if strings.Contains(text, "not-selected") || bytes.Contains(data, []byte("not-selected")) {
		t.Fatal("filter included an unselected rendition")
	}
}

func TestMalformedResourceFormattingStopsAtDiagnostic(t *testing.T) {
	var b bytes.Buffer
	writeValue(t, &b, binary.LittleEndian, []uint32{4, 0})
	a := Asset{ImageDB: []Rendition{{RenditionName: "malformed", Resources: []csiResource{
		{ID: SliceID, Data: b.Bytes()}, {ID: MetricsID, Data: b.Bytes()},
		{ID: LayerReferenceID, Data: b.Bytes()}, {ID: MetaDataID, Data: b.Bytes()},
	}}}}
	text := a.String()
	for _, invented := range []string{"SliceID: (4)", "MetricsID: (4)", "Layers: (4)"} {
		if strings.Contains(text, invented) {
			t.Fatalf("formatter displayed invalid structured fields: %s", invented)
		}
	}
}
