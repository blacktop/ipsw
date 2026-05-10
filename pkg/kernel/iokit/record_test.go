package iokit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

func TestWriteJSONLMethodRecordUsesStableSortedKeys(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := WriteJSONL(&out, []Record{
		{
			Kind:              KindMethod,
			Class:             "ExampleUserClient",
			Bundle:            "com.apple.example",
			Selector:          2,
			MethodAddr:        "0xfffffe0000001000",
			MethodSymbol:      "ExampleUserClient::method",
			DispatchKind:      DispatchExternalMethod,
			ScalarInputCount:  1,
			ScalarOutputCount: 2,
			StructInputSize:   3,
			StructOutputSize:  4,
			Flags:             0,
			Resolved:          true,
			Extra:             map[string]string{},
		},
	})
	if err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}

	got := strings.TrimSpace(out.String())
	want := `{"bundle":"com.apple.example","class":"ExampleUserClient","dispatch_kind":"IOExternalMethodDispatch","extra":{},"flags":0,"kind":"iokit_method","method_addr":"0xfffffe0000001000","method_symbol":"ExampleUserClient::method","resolved":true,"scalar_input_count":1,"scalar_output_count":2,"selector":2,"struct_input_size":3,"struct_output_size":4}`
	if got != want {
		t.Fatalf("jsonl = %s, want %s", got, want)
	}
}

func TestWriteJSONLSortsByContractKey(t *testing.T) {
	t.Parallel()

	records := []Record{
		{Kind: KindMethod, Bundle: "b", Class: "B", Selector: 1, MethodAddr: "0x2", DispatchKind: DispatchUnknown, Extra: map[string]string{}},
		{Kind: KindMethod, Bundle: "a", Class: "A", Selector: 1, MethodAddr: "0x2", DispatchKind: DispatchUnknown, Extra: map[string]string{}},
		{Kind: KindMethod, Bundle: "a", Class: "A", Selector: 0, MethodAddr: "0x1", DispatchKind: DispatchUnknown, Extra: map[string]string{}},
	}

	SortRecords(records)
	if records[0].Bundle != "a" || records[0].Selector != 0 {
		t.Fatalf("first record after sort = %+v", records[0])
	}
	if records[1].Bundle != "a" || records[1].Selector != 1 {
		t.Fatalf("second record after sort = %+v", records[1])
	}
	if records[2].Bundle != "b" {
		t.Fatalf("third record after sort = %+v", records[2])
	}
}

func TestReachesClassFollowsSuperIndex(t *testing.T) {
	t.Parallel()

	classes := []cpp.Class{
		{Name: "OSObject", SuperIndex: -1},
		{Name: "IOService", SuperIndex: 0},
		{Name: "IOUserClient", SuperIndex: 1},
		{Name: "ExampleUserClient", SuperIndex: 2},
	}
	if !reachesClass(classes, 3, "IOUserClient") {
		t.Fatal("expected ExampleUserClient to reach IOUserClient")
	}
	if !reachesClass(classes, 3, "IOService") {
		t.Fatal("expected ExampleUserClient to reach IOService")
	}
	if reachesClass(classes, 1, "IOUserClient") {
		t.Fatal("IOService should not reach IOUserClient")
	}
}

func TestCombineExprPreservesAlternateBases(t *testing.T) {
	t.Parallel()

	got := combineExpr(
		linearExpr{valid: true, base: 0x1000, alts: []uint64{0x2000, 0x1000}},
		linearExpr{valid: true, base: 0x80, coeff: dispatchSize2022},
	)
	bases := exprBases(got)
	want := []uint64{0x1080, 0x2080}
	if got.coeff != dispatchSize2022 {
		t.Fatalf("coeff = %#x, want %#x", got.coeff, dispatchSize2022)
	}
	assertUint64sEqual(t, bases, want)
}

func TestAddImmediateExprDoesNotMutateSourceAlternates(t *testing.T) {
	t.Parallel()

	src := linearExpr{valid: true, base: 0x1000, alts: []uint64{0x2000, 0x1000}}
	got := addImmediateExpr(src, 0x80)

	if src.base != 0x1000 {
		t.Fatalf("source base mutated to %#x", src.base)
	}
	wantSrc := []uint64{0x2000, 0x1000}
	for idx := range wantSrc {
		if src.alts[idx] != wantSrc[idx] {
			t.Fatalf("source alts mutated to %#v", src.alts)
		}
	}
	assertUint64sEqual(t, exprBases(got), []uint64{0x1080, 0x2080})
}

func TestTiedDispatchStrideUses2022EvidenceBeforeClassicHint(t *testing.T) {
	t.Parallel()

	stride, kind, ok := tiedDispatchStride(DispatchExternalMethod, true)
	if !ok {
		t.Fatal("expected tie to resolve")
	}
	if stride != dispatchSize2022 || kind != DispatchExternalMethod2022 {
		t.Fatalf("tie resolved to %s/%d, want %s/%d", kind, stride, DispatchExternalMethod2022, dispatchSize2022)
	}
}

func assertUint64sEqual(t *testing.T, got []uint64, want []uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}
