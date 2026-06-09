package bundle

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"testing"
)

func TestParseType4ConfigFromUrstRange(t *testing.T) {
	config, err := asn1.Marshal(Config{
		Unk1: 1,
		Unk2: 2,
		Assets: []Asset{
			{
				Name:   rawString("__MACHOHEADERLC"),
				Type:   2,
				Offset: 0x1000,
				Size:   0x100,
			},
		},
		TOC: []TocEntry{{Index: 1}},
		Compartments: []Compartment{
			{
				AppUID: 1,
				Metadata: []metadata{
					{Key: rawString("__COMPONENTNAME"), Value: rawString("kernel")},
					{Key: rawString("__COMPONENTTYPE"), Value: rawString("SYSTEM")},
					{Key: rawString("__MACHOHEADEROFF"), Value: rawUint(0x1000)},
					{Key: rawString("__MACHOHEADERSZ"), Value: rawUint(0x100)},
					{Key: rawString("__MACHO__TEXTOFF"), Value: rawUint(0x2000)},
					{Key: rawString("__MACHO__TEXTSZ"), Value: rawUint(0x3000)},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal test config: %v", err)
	}

	var data bytes.Buffer
	header := Header{
		Unknown1: 0x200,
		Unknown2: 0x1400,
		Magic:    [4]byte{'D', 'N', 'U', 'B'},
		Type:     4,
	}

	urstOffset := uint64(binary.Size(header) + binary.Size(Type4{}) + 0x100)
	configOffset := uint64(0x40)
	t4 := Type4{
		ConfigOff: configOffset,
		ConfigPad: 0x100,
		ConfigSz:  uint64(len(config)),
	}
	t4.Ranges[0] = typ4Range{
		Type:   21,
		Name:   [4]byte{'t', 's', 'r', 'u'},
		Offset: urstOffset,
		Size:   0x200,
	}

	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatalf("failed to write test bundle header: %v", err)
	}
	if err := binary.Write(&data, binary.LittleEndian, t4); err != nil {
		t.Fatalf("failed to write test bundle type 4 header: %v", err)
	}
	data.Write(make([]byte, int(urstOffset+configOffset)-data.Len()))
	data.Write(config)

	bn, err := Parse(bytes.NewReader(data.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse type 4 bundle: %v", err)
	}
	if bn.Type != 4 {
		t.Fatalf("expected type 4 bundle, got %d", bn.Type)
	}
	if len(bn.Files) != 1 {
		t.Fatalf("expected 1 parsed file, got %d", len(bn.Files))
	}
	if bn.Files[0].Name != "kernel" {
		t.Fatalf("expected parsed file name kernel, got %q", bn.Files[0].Name)
	}
	if bn.Files[0].Segment("HEADER") == nil {
		t.Fatal("expected parsed HEADER segment")
	}
}

func rawString(value string) asn1.RawValue {
	return asn1.RawValue{
		Tag:   asn1.TagOctetString,
		Bytes: []byte(value),
	}
}

func rawUint(value uint64) asn1.RawValue {
	var out []byte
	for shift := 56; shift >= 0; shift -= 8 {
		b := byte(value >> uint(shift))
		if len(out) > 0 || b != 0 {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		out = []byte{0}
	}
	return asn1.RawValue{
		Tag:   asn1.TagOctetString,
		Bytes: out,
	}
}
