package pacx

import (
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

// authSlot is a synthetic authenticated vtable slot. index*8 == Offset is the
// invariant every fixture must preserve.
func authSlot(index int, vtable, target uint64, pac uint16, addrDiv bool, sym string) cpp.VtableEntry {
	return cpp.VtableEntry{
		Index:       index,
		Offset:      uint64(index * 8),
		SlotAddress: vtable + uint64(index*8),
		Address:     target,
		Symbol:      sym,
		PAC:         pac,
		AddrDiv:     addrDiv,
		Auth:        true,
	}
}

func findForward(ix *Index, offset uint64, pac uint16) *ForwardEntry {
	for i := range ix.Forward {
		if ix.Forward[i].Offset == offset && ix.Forward[i].PAC == pac {
			return &ix.Forward[i]
		}
	}
	return nil
}

func findInverse(ix *Index, target uint64) *InverseEntry {
	for i := range ix.Inverse {
		if ix.Inverse[i].Target == target {
			return &ix.Inverse[i]
		}
	}
	return nil
}

func TestBuildIndexSlotOffsetInvariant(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	tables := []cpp.MethodTable{{
		Class:      "Foo",
		Bundle:     "com.apple.kernel",
		VtableAddr: vt,
		Methods: []cpp.VtableEntry{
			authSlot(0, vt, 0xfffffe0000010000, 0x1111, false, "Foo::a()"),
			authSlot(1, vt, 0xfffffe0000010100, 0x2222, true, "Foo::b()"),
			authSlot(2, vt, 0xfffffe0000010200, 0x3333, false, "Foo::c()"),
		},
	}}

	ix := BuildIndex(Meta{Kernelcache: "kc"}, tables)
	if len(ix.Slots) != 3 {
		t.Fatalf("indexed %d slots, want 3", len(ix.Slots))
	}
	for _, s := range ix.Slots {
		if want := uint64(s.SlotIndex * 8); s.Offset != want {
			t.Fatalf("slot %d offset = %#x, want %#x (offset must equal index*8)", s.SlotIndex, s.Offset, want)
		}
		if want := vt + s.Offset; s.SlotAddr != want {
			t.Fatalf("slot %d addr = %#x, want %#x", s.SlotIndex, s.SlotAddr, want)
		}
	}
}

func TestBuildIndexExcludesNonAuthAndUnmatchable(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	tables := []cpp.MethodTable{{
		Class:      "Foo",
		VtableAddr: vt,
		Methods: []cpp.VtableEntry{
			authSlot(0, vt, 0xfffffe0000010000, 0xaaaa, false, "keep_auth"),
			// non-auth slot: carries a diversifier field but Auth=false.
			{Index: 1, Offset: 8, SlotAddress: vt + 8, Address: 0xfffffe0000010100, PAC: 0xbbbb, Auth: false, Symbol: "drop_nonauth"},
			// auth but unmatchable: diversity 0 and no address blend.
			{Index: 2, Offset: 16, SlotAddress: vt + 16, Address: 0xfffffe0000010200, PAC: 0, AddrDiv: false, Auth: true, Symbol: "drop_zero_pac"},
			// auth, diversity 0 but address-blended -> matchable, keep.
			{Index: 3, Offset: 24, SlotAddress: vt + 24, Address: 0xfffffe0000010300, PAC: 0, AddrDiv: true, Auth: true, Symbol: "keep_addrdiv"},
			// external/bound slot -> no in-image target, drop.
			{Index: 4, Offset: 32, SlotAddress: vt + 32, Address: 0xfffffe0000010400, PAC: 0xcccc, Auth: true, ExternalReloc: true, Symbol: "drop_bind"},
		},
	}}

	ix := BuildIndex(Meta{}, tables)
	if len(ix.Slots) != 2 {
		t.Fatalf("indexed %d slots, want 2 (keep_auth + keep_addrdiv)", len(ix.Slots))
	}
	kept := map[string]bool{}
	for _, s := range ix.Slots {
		kept[s.Symbol] = true
	}
	for _, want := range []string{"keep_auth", "keep_addrdiv"} {
		if !kept[want] {
			t.Fatalf("missing kept slot %q; slots=%+v", want, ix.Slots)
		}
	}
	for _, drop := range []string{"drop_nonauth", "drop_zero_pac", "drop_bind"} {
		if kept[drop] {
			t.Fatalf("slot %q should have been excluded", drop)
		}
	}
}

func TestBuildIndexForwardCollidesOnlyOnIdenticalOffsetPac(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	// Two classes, same slot index (=> same offset). Same PAC collides into one
	// forward entry with two candidates; a different PAC at the same offset is a
	// separate key.
	tables := []cpp.MethodTable{
		{Class: "A", VtableAddr: vt, Methods: []cpp.VtableEntry{
			authSlot(0, vt, 0xfffffe0000010000, 0x1234, false, "A::m()"),
			authSlot(1, vt, 0xfffffe0000010100, 0xdead, false, "A::n()"),
		}},
		{Class: "B", VtableAddr: vt + 0x1000, Methods: []cpp.VtableEntry{
			// same offset (0) and same pac as A::m -> collides.
			authSlot(0, vt+0x1000, 0xfffffe0000010200, 0x1234, false, "B::m()"),
			// same offset (8) but different pac than A::n -> distinct key.
			authSlot(1, vt+0x1000, 0xfffffe0000010300, 0xbeef, false, "B::n()"),
		}},
	}

	ix := BuildIndex(Meta{}, tables)

	collide := findForward(ix, 0, 0x1234)
	if collide == nil || len(collide.Candidates) != 2 {
		t.Fatalf("offset=0 pac=0x1234 forward = %+v, want 2 candidates", collide)
	}

	if fe := findForward(ix, 8, 0xdead); fe == nil || len(fe.Candidates) != 1 || fe.Candidates[0].Class != "A" {
		t.Fatalf("offset=8 pac=0xdead should be A-only, got %+v", fe)
	}
	if fe := findForward(ix, 8, 0xbeef); fe == nil || len(fe.Candidates) != 1 || fe.Candidates[0].Class != "B" {
		t.Fatalf("offset=8 pac=0xbeef should be B-only, got %+v", fe)
	}
}

func TestBuildIndexInverseIsExactTransposeOfForward(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	tables := []cpp.MethodTable{
		{Class: "A", VtableAddr: vt, Methods: []cpp.VtableEntry{
			authSlot(0, vt, 0xfffffe0000010000, 0x1234, false, "A::m()"),
		}},
		{Class: "B", VtableAddr: vt + 0x1000, Methods: []cpp.VtableEntry{
			authSlot(0, vt+0x1000, 0xfffffe0000010000, 0x1234, false, "A::m()"),
		}},
	}
	ix := BuildIndex(Meta{}, tables)

	// Every forward candidate must have a matching inverse ref, and vice versa.
	fwdEdges := map[inverseRefKey]struct{}{}
	for _, f := range ix.Forward {
		for _, c := range f.Candidates {
			fwdEdges[inverseRefKey{target: c.Target, offset: f.Offset, pac: f.PAC, slotAddr: c.SlotAddr}] = struct{}{}
		}
	}
	invEdges := map[inverseRefKey]struct{}{}
	for _, inv := range ix.Inverse {
		for _, r := range inv.Refs {
			invEdges[inverseRefKey{target: inv.Target, offset: r.Offset, pac: r.PAC, slotAddr: r.SlotAddr}] = struct{}{}
		}
	}
	if len(fwdEdges) != len(invEdges) || len(fwdEdges) != 2 {
		t.Fatalf("edge counts: forward=%d inverse=%d, want 2 each", len(fwdEdges), len(invEdges))
	}
	for k := range fwdEdges {
		if _, ok := invEdges[k]; !ok {
			t.Fatalf("forward edge %+v missing from inverse", k)
		}
	}
}

// TestBuildIndexSameTargetDifferentPacNotCollapsed guards the central pitfall:
// a target-keyed index would last-write-wins collapse two references to the same
// function that differ only in diversifier. Both must survive.
func TestBuildIndexSameTargetDifferentPacNotCollapsed(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	const target = uint64(0xfffffe0000099000)
	tables := []cpp.MethodTable{
		{Class: "A", VtableAddr: vt, Methods: []cpp.VtableEntry{
			authSlot(0, vt, target, 0x1111, false, "shared()"),
		}},
		{Class: "B", VtableAddr: vt + 0x1000, Methods: []cpp.VtableEntry{
			// same target, DIFFERENT pac (and different offset).
			authSlot(3, vt+0x1000, target, 0x2222, false, "shared()"),
		}},
	}

	ix := BuildIndex(Meta{}, tables)

	inv := findInverse(ix, target)
	if inv == nil {
		t.Fatal("target missing from inverse index")
	}
	if len(inv.Refs) != 2 {
		t.Fatalf("target has %d inverse refs, want 2 (different-pac refs must NOT collapse)", len(inv.Refs))
	}
	pacs := map[uint16]bool{}
	for _, r := range inv.Refs {
		pacs[r.PAC] = true
	}
	if !pacs[0x1111] || !pacs[0x2222] {
		t.Fatalf("inverse refs lost a diversifier: %+v", inv.Refs)
	}

	// Forward side: two distinct keys, each resolving to the same target.
	if c := ix.Lookup(0, 0x1111); len(c) != 1 || c[0].Target != target {
		t.Fatalf("Lookup(0,0x1111) = %+v, want the shared target", c)
	}
	if c := ix.Lookup(24, 0x2222); len(c) != 1 || c[0].Target != target {
		t.Fatalf("Lookup(24,0x2222) = %+v, want the shared target", c)
	}
}

func TestBuildIndexDedupesRepeatedSlot(t *testing.T) {
	t.Parallel()

	const vt = uint64(0xfffffe0007000000)
	slot := authSlot(0, vt, 0xfffffe0000010000, 0x1234, false, "Foo::a()")
	// Same table listed twice -> identical slot/candidate/ref must dedupe.
	tables := []cpp.MethodTable{
		{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{slot}},
		{Class: "Foo", VtableAddr: vt, Methods: []cpp.VtableEntry{slot}},
	}
	ix := BuildIndex(Meta{}, tables)
	if len(ix.Slots) != 1 {
		t.Fatalf("dedupe failed: %d slots, want 1", len(ix.Slots))
	}
	if fe := findForward(ix, 0, 0x1234); fe == nil || len(fe.Candidates) != 1 {
		t.Fatalf("forward dedupe failed: %+v", fe)
	}
	if inv := findInverse(ix, slot.Address); inv == nil || len(inv.Refs) != 1 {
		t.Fatalf("inverse dedupe failed: %+v", inv)
	}
}
