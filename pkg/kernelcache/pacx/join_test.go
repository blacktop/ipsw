package pacx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

// indexWith builds a vtable index from synthetic method tables.
func indexWith(tables ...cpp.MethodTable) *Index {
	return BuildIndex(Meta{Kernelcache: "kc"}, tables)
}

// csiWith is a one-key call-site index for a single call site.
func csiWith(offset uint64, hash uint16, callsite, caller uint64) CallSiteIndex {
	return CallSiteIndex{
		CallKey{Offset: offset, Hash: hash}: {{Addr: callsite, CallerFuncAddr: caller}},
	}
}

func authSlotWithKey(index int, vtable, target uint64, pac uint16, key uint8, addrDiv bool, sym string) cpp.VtableEntry {
	e := authSlot(index, vtable, target, pac, addrDiv, sym)
	e.Key = key
	return e
}

func TestJoinSingleCandidateIsExact(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	const target = uint64(0xfffffe0000010000)
	// slot index 2 => offset 0x10.
	ix := indexWith(cpp.MethodTable{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{
		authSlot(2, vt, target, 0x1234, true, "Foo::run()"),
	}})
	csi := csiWith(0x10, 0x1234, 0xfffffe0007111000, 0xfffffe0007110000)

	records := Join(ix, csi, nil, false)
	if len(records) != 1 {
		t.Fatalf("Join produced %d records, want 1: %+v", len(records), records)
	}
	rec := records[0]
	if !rec.Resolved || rec.Ambiguous || rec.Confidence != ConfidenceExact {
		t.Fatalf("confidence tier wrong: resolved=%v ambiguous=%v confidence=%q", rec.Resolved, rec.Ambiguous, rec.Confidence)
	}
	if len(rec.Candidates) != 1 {
		t.Fatalf("record has %d candidates, want 1", len(rec.Candidates))
	}
	c := rec.Candidates[0]
	if c.Vfunc != target || c.Class != "Foo" {
		t.Fatalf("candidate = %+v, want target=%#x class=Foo", c, target)
	}
	if c.Vtable != vt {
		t.Fatalf("candidate vtable = %#x, want %#x (slot_addr - offset)", c.Vtable, vt)
	}
	if rec.SlotOffset != 0x10 || rec.SlotIndex != 2 || rec.PAC != 0x1234 {
		t.Fatalf("slot fields wrong: off=%#x idx=%d pac=%#x", rec.SlotOffset, rec.SlotIndex, rec.PAC)
	}
}

func TestJoinTwoVtablesSameKeyIsAmbiguousWithBothCandidates(t *testing.T) {
	t.Parallel()

	const vtA = uint64(0xfffffe0007000000)
	const vtB = uint64(0xfffffe0007002000)
	// Both classes have an authenticated slot at offset 0x10 with pac 0x1234.
	ix := indexWith(
		cpp.MethodTable{Class: "A", VtableAddr: vtA, Methods: []cpp.VtableEntry{
			authSlot(2, vtA, 0xfffffe0000010000, 0x1234, true, "A::m()"),
		}},
		cpp.MethodTable{Class: "B", VtableAddr: vtB, Methods: []cpp.VtableEntry{
			authSlot(2, vtB, 0xfffffe0000020000, 0x1234, true, "B::m()"),
		}},
	)
	csi := csiWith(0x10, 0x1234, 0xfffffe0007111000, 0xfffffe0007110000)

	records := Join(ix, csi, nil, false)
	if len(records) != 1 {
		t.Fatalf("Join produced %d records, want 1", len(records))
	}
	rec := records[0]
	if !rec.Ambiguous || rec.Confidence != ConfidenceAmbiguous {
		t.Fatalf("want ambiguous, got ambiguous=%v confidence=%q", rec.Ambiguous, rec.Confidence)
	}
	if len(rec.Candidates) != 2 {
		t.Fatalf("ambiguous record must carry BOTH candidates, got %d: %+v", len(rec.Candidates), rec.Candidates)
	}
	classes := map[string]bool{}
	for _, c := range rec.Candidates {
		classes[c.Class] = true
	}
	if !classes["A"] || !classes["B"] {
		t.Fatalf("ambiguous record dropped a candidate: %+v", rec.Candidates)
	}
}

func TestJoinFiltersCandidatesByAuthKeyAndAddrDiv(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	const offset = uint64(0x10)
	const pac = uint16(0x1234)
	ix := indexWith(
		cpp.MethodTable{Class: "KeyA", VtableAddr: vt, Methods: []cpp.VtableEntry{
			authSlotWithKey(2, vt, 0xfffffe0000010000, pac, 0, true, "KeyA::m()"),
		}},
		cpp.MethodTable{Class: "KeyB", VtableAddr: vt + 0x1000, Methods: []cpp.VtableEntry{
			authSlotWithKey(2, vt+0x1000, 0xfffffe0000020000, pac, 1, true, "KeyB::m()"),
		}},
		cpp.MethodTable{Class: "NoAddrDiv", VtableAddr: vt + 0x2000, Methods: []cpp.VtableEntry{
			authSlotWithKey(2, vt+0x2000, 0xfffffe0000030000, pac, 0, false, "NoAddrDiv::m()"),
		}},
	)
	csi := CallSiteIndex{
		CallKey{Offset: offset, Hash: pac}: {
			{Addr: 0xfffffe0007111000, CallerFuncAddr: 0xfffffe0007110000, KeyB: false},
			{Addr: 0xfffffe0007112000, CallerFuncAddr: 0xfffffe0007110000, KeyB: true},
		},
	}

	records := Join(ix, csi, nil, false)
	if len(records) != 2 {
		t.Fatalf("Join produced %d records, want 2: %+v", len(records), records)
	}
	if got := records[0].Candidates; len(got) != 1 || got[0].Class != "KeyA" {
		t.Fatalf("BLRAA candidates = %+v, want only KeyA", got)
	}
	if got := records[1].Candidates; len(got) != 1 || got[0].Class != "KeyB" {
		t.Fatalf("BLRAB candidates = %+v, want only KeyB", got)
	}
}

func TestJoinTreatsOnlyWrongKeyOrNoAddrDivAsUnresolved(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	const offset = uint64(0x10)
	const pac = uint16(0x1234)
	ix := indexWith(
		cpp.MethodTable{Class: "WrongKey", VtableAddr: vt, Methods: []cpp.VtableEntry{
			authSlotWithKey(2, vt, 0xfffffe0000010000, pac, 1, true, "WrongKey::m()"),
		}},
		cpp.MethodTable{Class: "NoAddrDiv", VtableAddr: vt + 0x1000, Methods: []cpp.VtableEntry{
			authSlotWithKey(2, vt+0x1000, 0xfffffe0000020000, pac, 0, false, "NoAddrDiv::m()"),
		}},
	)
	csi := csiWith(offset, pac, 0xfffffe0007111000, 0xfffffe0007110000)

	if records := Join(ix, csi, nil, false); len(records) != 0 {
		t.Fatalf("wrong-key/no-addrdiv candidates must be dropped, got %+v", records)
	}
	records := Join(ix, csi, nil, true)
	if len(records) != 1 {
		t.Fatalf("includeUnresolved must retain the call site, got %d records", len(records))
	}
	rec := records[0]
	if rec.Resolved || rec.Ambiguous || rec.Confidence != ConfidenceUnresolved || len(rec.Candidates) != 0 {
		t.Fatalf("filtered candidates should leave an unresolved record: %+v", rec)
	}
}

func TestJoinSamePacDifferentOffsetNoMatch(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	// Vtable slot lives at offset 0x10 with pac 0x1234.
	ix := indexWith(cpp.MethodTable{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{
		authSlot(2, vt, 0xfffffe0000010000, 0x1234, false, "Foo::run()"),
	}})
	// Call site carries the SAME pac but a DIFFERENT offset (0x20): no match.
	csi := csiWith(0x20, 0x1234, 0xfffffe0007111000, 0xfffffe0007110000)

	if records := Join(ix, csi, nil, false); len(records) != 0 {
		t.Fatalf("pac-only collision must not match across offsets, got %d records: %+v", len(records), records)
	}
}

func TestJoinUnresolvedDroppedUnlessIncluded(t *testing.T) {
	t.Parallel()

	ix := indexWith(cpp.MethodTable{Class: "Foo", VtableAddr: 0xfffffe0007000000, Methods: []cpp.VtableEntry{
		authSlot(2, 0xfffffe0007000000, 0xfffffe0000010000, 0x1234, false, "Foo::run()"),
	}})
	// A call site whose (offset, hash) matches nothing in the index.
	csi := csiWith(0x40, 0xbeef, 0xfffffe0007111000, 0xfffffe0007110000)

	if records := Join(ix, csi, nil, false); len(records) != 0 {
		t.Fatalf("zero-candidate call site must be dropped, got %d records", len(records))
	}
	records := Join(ix, csi, nil, true)
	if len(records) != 1 {
		t.Fatalf("includeUnresolved must keep the call site, got %d records", len(records))
	}
	rec := records[0]
	if rec.Resolved || rec.Ambiguous || rec.Confidence != ConfidenceUnresolved || len(rec.Candidates) != 0 {
		t.Fatalf("unresolved record shape wrong: %+v", rec)
	}
}

func TestJoinMatchesOnOffsetAndPacTogether(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	// Two slots share pac 0x1234 at different offsets (index 2 => 0x10, index 5 => 0x28).
	ix := indexWith(cpp.MethodTable{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{
		authSlot(2, vt, 0xfffffe0000010000, 0x1234, true, "Foo::a()"),
		authSlot(5, vt, 0xfffffe0000010200, 0x1234, true, "Foo::b()"),
	}})
	csi := csiWith(0x28, 0x1234, 0xfffffe0007111000, 0xfffffe0007110000)

	records := Join(ix, csi, nil, false)
	if len(records) != 1 || len(records[0].Candidates) != 1 {
		t.Fatalf("expected exactly the offset-0x28 slot, got %+v", records)
	}
	if got := records[0].Candidates[0].Vfunc; got != 0xfffffe0000010200 {
		t.Fatalf("matched the wrong slot (pac-only collision): vfunc=%#x", got)
	}
}

func TestJoinAttributorPopulatesSiteMeta(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	ix := indexWith(cpp.MethodTable{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{
		authSlot(2, vt, 0xfffffe0000010000, 0x1234, true, "Foo::run()"),
	}})
	csi := csiWith(0x10, 0x1234, 0xfffffe0007111000, 0xfffffe0007110000)
	attr := func(site CallSite) SiteMeta {
		return SiteMeta{Image: "com.apple.driver.Foo", CallerSymbol: "Bar::dispatch()", Auth: "blrab"}
	}

	rec := Join(ix, csi, attr, false)[0]
	if rec.Image != "com.apple.driver.Foo" || rec.CallerSymbol != "Bar::dispatch()" || rec.Auth != "blrab" {
		t.Fatalf("attributor not applied: %+v", rec)
	}
}

func TestPacRecordJSONLShape(t *testing.T) {
	t.Parallel()

	rec := PacRecord{
		Callsite:     0xfffffe0007111000,
		Auth:         "blraa",
		CallerFunc:   0xfffffe0007110000,
		CallerSymbol: "Bar::dispatch()",
		Image:        "com.apple.kernel",
		SlotOffset:   0x10,
		SlotIndex:    2,
		PAC:          0x1234,
		Resolved:     true,
		Ambiguous:    false,
		Confidence:   ConfidenceExact,
		Candidates: []PacCandidate{{
			Vfunc:       0xfffffe0000010000,
			VfuncSymbol: "Foo::run()",
			Class:       "Foo",
			Vtable:      0xfffffe0007000000,
			SlotAddr:    0xfffffe0007000010,
		}},
	}

	var buf bytes.Buffer
	if err := WriteJSONL(&buf, []PacRecord{rec}); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	line := strings.TrimRight(buf.String(), "\n")

	// Valid single-line JSON object.
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("emitted line is not valid JSON: %v\n%s", err, line)
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("JSONL record must be a single line: %q", line)
	}

	for _, want := range []string{
		`"callsite":"0xfffffe0007111000"`,
		`"auth":"blraa"`,
		`"caller_func":"0xfffffe0007110000"`,
		`"image":"com.apple.kernel"`,
		`"slot_offset":16`,
		`"slot_index":2`,
		`"pac":"0x1234"`,
		`"resolved":true`,
		`"ambiguous":false`,
		`"confidence":"exact"`,
		`"vfunc":"0xfffffe0000010000"`,
		`"vfunc_symbol":"Foo::run()"`,
		`"vtable":"0xfffffe0007000000"`,
		`"slot_addr":"0xfffffe0007000010"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("emitted JSONL missing %s\n%s", want, line)
		}
	}
}

func TestFuncsFromCallSiteAndCallSitesFromFunc(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	const target = uint64(0xfffffe0000010000)
	ix := indexWith(cpp.MethodTable{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{
		authSlot(2, vt, target, 0x1234, true, "Foo::run()"),
	}})
	csi := csiWith(0x10, 0x1234, 0xfffffe0007111000, 0xfffffe0007110000)
	records := Join(ix, csi, nil, false)

	cands := FuncsFromCallSite(records, 0xfffffe0007111000)
	if len(cands) != 1 || cands[0].Vfunc != target {
		t.Fatalf("FuncsFromCallSite = %+v, want the target", cands)
	}
	if FuncsFromCallSite(records, 0xdeadbeef) != nil {
		t.Fatal("FuncsFromCallSite for an unknown call site must be nil")
	}

	sites := CallSitesFromFunc(records, target)
	if len(sites) != 1 || sites[0].Callsite != 0xfffffe0007111000 {
		t.Fatalf("CallSitesFromFunc = %+v, want the one call site", sites)
	}
	if CallSitesFromFunc(records, 0xdeadbeef) != nil {
		t.Fatal("CallSitesFromFunc for an unreferenced func must be nil")
	}
}
