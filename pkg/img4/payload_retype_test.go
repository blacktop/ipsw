package img4

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"strings"
	"testing"
)

func lzssKernelPayload(t testing.TB) (*Payload, []byte) {
	t.Helper()
	payload, err := CreatePayload(&CreatePayloadConfig{
		Type:        IM4P_KERNELCACHE,
		Version:     "SyntheticKernelBuilder-1",
		Data:        bytes.Repeat([]byte("synthetic kernel text "), 200),
		Compression: "lzss",
	})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return payload, raw
}

func sequenceElements(t testing.TB, der []byte) []asn1.RawValue {
	t.Helper()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatalf("Unmarshal sequence: %v", err)
	}
	var elems []asn1.RawValue
	rest := seq.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			t.Fatalf("Unmarshal element: %v", err)
		}
		elems = append(elems, el)
	}
	return elems
}

func TestLZSSPayloadOmitsCompressionRecord(t *testing.T) {
	_, raw := lzssKernelPayload(t)
	elems := sequenceElements(t, raw)
	if len(elems) != 4 {
		t.Fatalf("LZSS IM4P has %d elements, want 4 (tag, type, version, data)", len(elems))
	}

	parsed, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	if parsed.Compression.UncompressedSize != 0 {
		t.Errorf("parsed LZSS payload carries an encoded compression record: %+v", parsed.Compression)
	}
	comp, ok := parsed.CompressionInfo()
	if !ok || comp.Algorithm != CompressionAlgorithmLZSS || comp.UncompressedSize != 4400 {
		t.Errorf("CompressionInfo() = %+v, %t; want LZSS/4400, true", comp, ok)
	}
}

func TestLZFSEPayloadKeepsCompressionRecord(t *testing.T) {
	payload, err := CreatePayload(&CreatePayloadConfig{
		Type:        IM4P_IBOOT,
		Data:        bytes.Repeat([]byte("iboot text "), 400),
		Compression: "lzfse",
	})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	elems := sequenceElements(t, raw)
	if len(elems) != 5 {
		t.Fatalf("LZFSE IM4P has %d elements, want 5", len(elems))
	}
	if elems[4].Tag != asn1.TagSequence {
		t.Errorf("fifth element tag = %d, want SEQUENCE", elems[4].Tag)
	}
}

func TestPayloadInspectionReportsLZSSWithoutMutating(t *testing.T) {
	_, raw := lzssKernelPayload(t)
	parsed, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}

	if s := parsed.String(); !strings.Contains(s, "LZSS") {
		t.Errorf("first String() lacks LZSS label:\n%s", s)
	}

	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(out), `"algorithm":"LZSS"`) || !strings.Contains(string(out), `"uncompressed_size":4400`) {
		t.Errorf("JSON lacks detected compression: %s", out)
	}

	remarshaled, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !bytes.Equal(remarshaled, raw) {
		t.Errorf("inspecting the payload changed its encoding (%d -> %d bytes)", len(raw), len(remarshaled))
	}
}

func TestUncompressedPayloadJSONHasNullCompression(t *testing.T) {
	payload, err := CreatePayload(&CreatePayloadConfig{Type: "logo", Data: []byte("plain")})
	if err != nil {
		t.Fatalf("CreatePayload() error = %v", err)
	}
	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(out), `"compression":null`) {
		t.Errorf("JSON should report null compression: %s", out)
	}
}

func TestRetypePreservesEveryOtherByte(t *testing.T) {
	_, raw := lzssKernelPayload(t)
	parsed, err := ParsePayload(raw)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}

	retyped, err := parsed.Retype(IM4P_RESTORE_KERNEL_CACHE, "")
	if err != nil {
		t.Fatalf("Retype() error = %v", err)
	}
	got, err := retyped.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want := bytes.Replace(raw, []byte(IM4P_KERNELCACHE), []byte(IM4P_RESTORE_KERNEL_CACHE), 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("retyped IM4P differs from original beyond the type field (%d vs %d bytes)", len(got), len(want))
	}
	if retyped.Type != IM4P_RESTORE_KERNEL_CACHE || retyped.Version != "SyntheticKernelBuilder-1" {
		t.Errorf("Type/Version = %q/%q", retyped.Type, retyped.Version)
	}
}

func TestRetypeWithVersion(t *testing.T) {
	parsed, _ := lzssKernelPayload(t)
	retyped, err := parsed.Retype(IM4P_RESTORE_KERNEL_CACHE, "RestoreKernel")
	if err != nil {
		t.Fatalf("Retype() error = %v", err)
	}
	if retyped.Version != "RestoreKernel" {
		t.Errorf("Version = %q, want RestoreKernel", retyped.Version)
	}
	if !bytes.Equal(retyped.Data, parsed.Data) {
		t.Errorf("payload data changed during retype")
	}
	if _, ok := retyped.CompressionInfo(); !ok {
		t.Errorf("retyped payload lost its LZSS compression")
	}
}

func TestRetypeKeepsUnmodeledFields(t *testing.T) {
	_, raw := lzssKernelPayload(t)
	extra, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, IsCompound: true, Bytes: []byte("future-field")})
	if err != nil {
		t.Fatalf("Marshal extra: %v", err)
	}
	elems := sequenceElements(t, raw)
	var body []byte
	for _, el := range elems {
		body = append(body, el.FullBytes...)
	}
	body = append(body, extra...)
	withExtra, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatalf("Marshal sequence: %v", err)
	}

	parsed, err := ParsePayload(withExtra)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	retyped, err := parsed.Retype(IM4P_RESTORE_KERNEL_CACHE, "")
	if err != nil {
		t.Fatalf("Retype() error = %v", err)
	}
	got, err := retyped.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want := bytes.Replace(withExtra, []byte(IM4P_KERNELCACHE), []byte(IM4P_RESTORE_KERNEL_CACHE), 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("retype dropped or altered an unmodeled trailing field")
	}
}

func TestCreateRetypeDoesNotRebuildPayload(t *testing.T) {
	_, raw := lzssKernelPayload(t)
	img, err := Create(&CreateConfig{PayloadData: raw, PayloadType: IM4P_RESTORE_KERNEL_CACHE})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	got, err := img.Payload.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want := bytes.Replace(raw, []byte(IM4P_KERNELCACHE), []byte(IM4P_RESTORE_KERNEL_CACHE), 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("Create rebuilt the payload instead of retyping it in place (%d vs %d bytes)", len(got), len(want))
	}

	img4Data, err := img.Marshal()
	if err != nil {
		t.Fatalf("Image.Marshal() error = %v", err)
	}
	reparsed, err := Parse(img4Data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if reparsed.Payload.Type != IM4P_RESTORE_KERNEL_CACHE {
		t.Errorf("IMG4 payload type = %q", reparsed.Payload.Type)
	}
	if !bytes.Equal(reparsed.Payload.Raw, want) {
		t.Errorf("IMG4 embedded payload differs from retyped IM4P")
	}
}

func TestCreateRejectsRecompressingExistingPayload(t *testing.T) {
	_, raw := lzssKernelPayload(t)
	if _, err := Create(&CreateConfig{PayloadData: raw, PayloadType: "rkrn", PayloadCompression: "lzss"}); err == nil {
		t.Error("Create() accepted a compression override for an existing IM4P")
	}
	if _, err := Create(&CreateConfig{PayloadData: raw, PayloadExtraData: []byte("x")}); err == nil {
		t.Error("Create() accepted extra data for an existing IM4P")
	}
	if _, err := Create(&CreateConfig{PayloadData: raw, PayloadCompression: "none"}); err != nil {
		t.Errorf("Create() rejected the CLI default compression value: %v", err)
	}
}
