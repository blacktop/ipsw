package kalloctype

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestLayoutSizesMatchXNU1237710115(t *testing.T) {
	if fixedViewSize != 0x40 {
		t.Fatalf("fixedViewSize = %#x, want 0x40", fixedViewSize)
	}
	if varViewSize != 0x50 {
		t.Fatalf("varViewSize = %#x, want 0x50", varViewSize)
	}
	if fixedSignatureOffset != 0x20 || fixedFlagsOffset != 0x28 || fixedSizeOffset != 0x2c {
		t.Fatalf("fixed offsets changed: signature=%#x flags=%#x size=%#x", fixedSignatureOffset, fixedFlagsOffset, fixedSizeOffset)
	}
	if varNameOffset != 0x10 || varHdrSignatureOffset != 0x38 || varElemSignatureOffset != 0x40 || varFlagsOffset != 0x48 {
		t.Fatalf("var offsets changed: name=%#x hdr=%#x elem=%#x flags=%#x", varNameOffset, varHdrSignatureOffset, varElemSignatureOffset, varFlagsOffset)
	}
}

func TestDecodeFlags(t *testing.T) {
	got := DecodeFlags(0x8000008a)
	want := []string{"PRIV_ACCT", "DATA_ONLY", "PTR_ARRAY", "HASH"}
	if !slices.Equal(got, want) {
		t.Fatalf("DecodeFlags = %v, want %v", got, want)
	}
}

func TestWriteJSONLFixedAndVar(t *testing.T) {
	records := []Record{
		{
			Kind:          KindVar,
			Name:          "var_type",
			Signature:     "2",
			Size:          16,
			Flags:         0x4,
			FlagsDecoded:  DecodeFlags(0x4),
			Site:          0x1000,
			HdrSignature:  "1",
			ElemSignature: "2",
		},
		{
			Kind:         KindFixed,
			Name:         "fixed_type",
			Signature:    "1221",
			Size:         48,
			Flags:        0x8,
			FlagsDecoded: DecodeFlags(0x8),
			Site:         0x2000,
		},
	}
	var out bytes.Buffer
	if err := WriteJSONL(&out, records); err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}
	want := "{\"kind\":\"var\",\"name\":\"var_type\",\"signature\":\"2\",\"size\":16,\"flags\":\"0x4\",\"flags_decoded\":[\"SHARED_ACCT\"],\"site\":\"0x1000\",\"hdr_signature\":\"1\",\"elem_signature\":\"2\"}\n" +
		"{\"kind\":\"fixed\",\"name\":\"fixed_type\",\"signature\":\"1221\",\"size\":48,\"flags\":\"0x8\",\"flags_decoded\":[\"DATA_ONLY\"],\"site\":\"0x2000\"}\n"
	if out.String() != want {
		t.Fatalf("jsonl = %s, want %s", out.String(), want)
	}
}

func TestSortRecordsUsesSizeSignatureNameTuple(t *testing.T) {
	records := []Record{
		{Kind: KindFixed, Name: "z_type", Signature: "1", Size: 16, Site: 3},
		{Kind: KindFixed, Name: "b_type", Signature: "", Size: 4, Site: 1},
		{Kind: KindFixed, Name: "a_type", Signature: "2", Size: 16, Site: 2},
	}
	SortRecords(records)
	want := []Record{
		{Kind: KindFixed, Name: "b_type", Signature: "", Size: 4, Site: 1},
		{Kind: KindFixed, Name: "z_type", Signature: "1", Size: 16, Site: 3},
		{Kind: KindFixed, Name: "a_type", Signature: "2", Size: 16, Site: 2},
	}
	for idx := range want {
		if records[idx].Size != want[idx].Size ||
			records[idx].Signature != want[idx].Signature ||
			records[idx].Name != want[idx].Name ||
			records[idx].Site != want[idx].Site {
			t.Fatalf("records[%d] = %#v, want %#v", idx, records[idx], want[idx])
		}
	}
}

func TestWriteJSONLNormalizesInvalidUTF8(t *testing.T) {
	var out bytes.Buffer
	records := []Record{{
		Kind:      KindFixed,
		Name:      string([]byte{'b', 'a', 'd', 0xff}),
		Signature: "1",
		Size:      8,
		Site:      0x1000,
	}}
	if err := WriteJSONL(&out, records); err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}
	line := bytes.TrimSpace(out.Bytes())
	if !json.Valid(line) {
		t.Fatalf("jsonl line is not valid JSON: %q", line)
	}
}

func TestCollisionsGroupBySizeSignature(t *testing.T) {
	records := []Record{
		{Kind: KindFixed, Name: "b_type", Signature: "1221", Size: 48},
		{Kind: KindFixed, Name: "a_type", Signature: "1221", Size: 48},
		{Kind: KindFixed, Name: "other_size", Signature: "1221", Size: 64},
		{Kind: KindVar, Name: "same_name", Signature: "2", Size: 16},
		{Kind: KindVar, Name: "same_name", Signature: "2", Size: 16},
	}
	collisions := Collisions(records)
	if len(collisions) != 1 {
		t.Fatalf("Collisions length = %d, want 1 (%v)", len(collisions), collisions)
	}
	got := collisions[0]
	if got.Size != 48 || got.Signature != "1221" {
		t.Fatalf("collision key = (%d,%q), want (48,%q)", got.Size, got.Signature, "1221")
	}
	wantTypes := []string{"a_type", "b_type"}
	if !slices.Equal(got.Types, wantTypes) {
		t.Fatalf("types = %v, want %v", got.Types, wantTypes)
	}
}
