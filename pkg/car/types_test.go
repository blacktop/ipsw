package car

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInternalLinkRejectsMalformedLengths(t *testing.T) {
	valid := syntheticLink(t, 3)
	if string(valid[:4]) != "KLNI" {
		t.Fatalf("incorrect reference wire signature: %q", valid[:4])
	}
	for _, tc := range []struct {
		name     string
		length   uint32
		truncate int
	}{{"partial token", 7, 0}, {"missing bytes", 12, 0}, {"huge length", ^uint32(0), 0}, {"truncated header", 8, 29}} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(data[26:30], tc.length)
			if tc.truncate != 0 {
				data = data[:tc.truncate]
			}
			var link csiInternalLinkData
			if err := link.UnmarshalBinary(bytes.NewReader(data)); err == nil {
				t.Fatal("malformed reference accepted")
			}
		})
	}
	var link csiInternalLinkData
	if err := link.UnmarshalBinary(bytes.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
}

func TestResourceCountsAreBoundedBeforeAllocation(t *testing.T) {
	var slices sliceResource
	var samples sampleResource
	var metrics metricsResource
	var layers layerResource
	var metadata metadataResource
	for _, tc := range []struct {
		name      string
		decode    func([]byte) error
		allocated func() int
		header    []uint32
	}{
		{"slices", slices.UnmarshalBinary, func() int { return len(slices.Slices) }, []uint32{4}},
		{"samples", samples.UnmarshalBinary, func() int { return len(samples.Samples) }, []uint32{4}},
		{"metrics", metrics.UnmarshalBinary, func() int { return len(metrics.Metrics) }, []uint32{4}},
		{"layers", layers.UnmarshalBinary, func() int { return len(layers.Layers) }, []uint32{4, 0}},
		{"metadata", metadata.UnmarshalBinary, func() int { return len(metadata.Data) }, []uint32{4, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			writeValue(t, &data, binary.LittleEndian, tc.header)
			if err := tc.decode(data.Bytes()); err == nil || tc.allocated() != 0 {
				t.Fatalf("unbacked count allocated %d entries: %v", tc.allocated(), err)
			}
		})
	}
}

func TestLayerAndMetadataPayloadLengths(t *testing.T) {
	var layerData bytes.Buffer
	writeValue(t, &layerData, binary.LittleEndian, []uint32{1, 0, 0, 1, 2, 3, 4, 0, 0, 3})
	layerData.Write([]byte{1, 2})
	var layer layerResource
	if err := layer.UnmarshalBinary(layerData.Bytes()); err == nil || len(layer.Layers[0].Data) != 0 {
		t.Fatalf("truncated layer payload accepted: %v", err)
	}
	layerData.WriteByte(3)
	if err := layer.UnmarshalBinary(layerData.Bytes()); err != nil || !bytes.Equal(layer.Layers[0].Data, []byte{1, 2, 3}) {
		t.Fatalf("valid layer payload failed: %v", err)
	}
	var metadata metadataResource
	var data bytes.Buffer
	writeValue(t, &data, binary.LittleEndian, []uint32{3, 0})
	data.Write([]byte{1, 2})
	if err := metadata.UnmarshalBinary(data.Bytes()); err == nil {
		t.Fatal("truncated metadata payload accepted")
	}
	data.WriteByte(3)
	if err := metadata.UnmarshalBinary(data.Bytes()); err != nil || !bytes.Equal(metadata.Data, []byte{1, 2, 3}) {
		t.Fatalf("valid metadata payload failed: %v", err)
	}
}
