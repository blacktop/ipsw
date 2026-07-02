// Package pacx builds a (slot-offset, 16-bit PAC) cross-reference index over the
// authenticated C++ vtable slots recovered by pkg/kernelcache/cpp.
//
// The index is the data foundation for resolving authenticated virtual calls
// (LDRAA [xN,#offset]; ... ; BLRAA) to their candidate target functions: a call
// site carries a slot offset and a 16-bit diversifier, and every vtable slot
// with a matching (offset, pac) pair is a candidate target. The forward map is
// keyed by that pair; the inverse map is keyed by the target function.
//
// Only authenticated slots are indexed. Non-authenticated slots carry no
// diversifier, and authenticated slots that are unmatchable (diversity 0 with no
// address blending) cannot be produced by a call site's MOVK, so both are
// excluded. Critically the maps are never keyed solely by target: the same
// target reached through two different diversifiers is two distinct references,
// and collapsing them would lose the exact information the index exists to carry.
package pacx

import (
	"sort"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

// Meta describes the kernelcache the index was built from.
type Meta struct {
	Kernelcache string
	UUID        string
	Arch        string
	FixupFormat string
	KernelBase  uint64
}

// Slot is a single authenticated vtable slot in the index.
type Slot struct {
	Class      string
	Bundle     string
	VtableAddr uint64
	SlotIndex  int
	Offset     uint64
	SlotAddr   uint64
	Target     uint64
	Symbol     string
	PAC        uint16
	Key        uint8
	AddrDiv    bool
	CacheLevel uint8
}

// Candidate is one vtable slot that matches a (offset, pac) key in the forward
// map: calling through that (offset, pac) may dispatch to Target.
type Candidate struct {
	Class    string
	Target   uint64
	Symbol   string
	SlotAddr uint64
	Key      uint8
	AddrDiv  bool
}

// ForwardEntry maps a (offset, pac) key to every candidate target slot.
type ForwardEntry struct {
	Offset     uint64
	PAC        uint16
	Candidates []Candidate
}

// InverseRef is one authenticated slot that references a target function.
type InverseRef struct {
	Offset   uint64
	PAC      uint16
	Class    string
	SlotAddr uint64
}

// InverseEntry lists every authenticated slot pointing at Target.
type InverseEntry struct {
	Target uint64
	Symbol string
	Refs   []InverseRef
}

// Index is the forward/inverse (offset, pac) index over authenticated slots.
type Index struct {
	Meta    Meta
	Slots   []Slot
	Forward []ForwardEntry
	Inverse []InverseEntry
}

type forwardKey struct {
	offset uint64
	pac    uint16
}

type candidateKey struct {
	forwardKey
	class    string
	target   uint64
	slotAddr uint64
}

type inverseRefKey struct {
	target   uint64
	offset   uint64
	pac      uint16
	slotAddr uint64
}

// indexBuilder accumulates the deduped forward/inverse maps before they are
// flattened into the sorted slices of an Index.
type indexBuilder struct {
	slots       []Slot
	slotSeen    map[uint64]struct{}
	forward     map[forwardKey]*ForwardEntry
	forwardSeen map[candidateKey]struct{}
	inverse     map[uint64]*InverseEntry
	inverseSeen map[inverseRefKey]struct{}
}

// BuildIndex builds the (offset, pac) index from PAC-annotated method tables.
//
// Tables are produced by cpp.Scanner.BuildNamedMethodTables (or
// BuildMethodTables). Only authenticated, matchable slots are included; see the
// package doc for the exclusion rules.
func BuildIndex(meta Meta, tables []cpp.MethodTable) *Index {
	b := &indexBuilder{
		slotSeen:    make(map[uint64]struct{}),
		forward:     make(map[forwardKey]*ForwardEntry),
		forwardSeen: make(map[candidateKey]struct{}),
		inverse:     make(map[uint64]*InverseEntry),
		inverseSeen: make(map[inverseRefKey]struct{}),
	}
	for i := range tables {
		mt := tables[i]
		for j := range mt.Methods {
			if e := mt.Methods[j]; includeSlot(e) {
				b.add(mt, e)
			}
		}
	}
	return b.finish(meta)
}

// includeSlot reports whether a vtable slot belongs in the index. Non-auth slots
// carry no diversifier; bound/external slots have no in-image target; auth slots
// with no diversity and no address blend produce a zero discriminator that no
// call-site MOVK can match.
func includeSlot(e cpp.VtableEntry) bool {
	if !e.Auth || e.ExternalReloc || e.Address == 0 {
		return false
	}
	if e.PAC == 0 && !e.AddrDiv {
		return false
	}
	return true
}

// symbolOf returns the best available name for a slot target: the real
// (demangled) symbol when present, else the resolved/synthesized method name.
func symbolOf(e cpp.VtableEntry) string {
	if e.Symbol != "" {
		return e.Symbol
	}
	return e.Method
}

func (b *indexBuilder) add(mt cpp.MethodTable, e cpp.VtableEntry) {
	sym := symbolOf(e)
	b.addSlot(mt, e, sym)
	b.addForward(mt, e, sym)
	b.addInverse(mt, e, sym)
}

func (b *indexBuilder) addSlot(mt cpp.MethodTable, e cpp.VtableEntry, sym string) {
	if _, dup := b.slotSeen[e.SlotAddress]; dup {
		return
	}
	b.slotSeen[e.SlotAddress] = struct{}{}
	b.slots = append(b.slots, Slot{
		Class:      mt.Class,
		Bundle:     mt.Bundle,
		VtableAddr: mt.VtableAddr,
		SlotIndex:  e.Index,
		Offset:     e.Offset,
		SlotAddr:   e.SlotAddress,
		Target:     e.Address,
		Symbol:     sym,
		PAC:        e.PAC,
		Key:        e.Key,
		AddrDiv:    e.AddrDiv,
		CacheLevel: e.CacheLevel,
	})
}

func (b *indexBuilder) addForward(mt cpp.MethodTable, e cpp.VtableEntry, sym string) {
	fk := forwardKey{offset: e.Offset, pac: e.PAC}
	ck := candidateKey{forwardKey: fk, class: mt.Class, target: e.Address, slotAddr: e.SlotAddress}
	if _, dup := b.forwardSeen[ck]; dup {
		return
	}
	b.forwardSeen[ck] = struct{}{}
	fe := b.forward[fk]
	if fe == nil {
		fe = &ForwardEntry{Offset: fk.offset, PAC: fk.pac}
		b.forward[fk] = fe
	}
	fe.Candidates = append(fe.Candidates, Candidate{
		Class:    mt.Class,
		Target:   e.Address,
		Symbol:   sym,
		SlotAddr: e.SlotAddress,
		Key:      e.Key,
		AddrDiv:  e.AddrDiv,
	})
}

func (b *indexBuilder) addInverse(mt cpp.MethodTable, e cpp.VtableEntry, sym string) {
	irk := inverseRefKey{target: e.Address, offset: e.Offset, pac: e.PAC, slotAddr: e.SlotAddress}
	if _, dup := b.inverseSeen[irk]; dup {
		return
	}
	b.inverseSeen[irk] = struct{}{}
	ie := b.inverse[e.Address]
	if ie == nil {
		ie = &InverseEntry{Target: e.Address}
		b.inverse[e.Address] = ie
	}
	if ie.Symbol == "" {
		ie.Symbol = sym
	}
	ie.Refs = append(ie.Refs, InverseRef{
		Offset:   e.Offset,
		PAC:      e.PAC,
		Class:    mt.Class,
		SlotAddr: e.SlotAddress,
	})
}

// finish flattens the builder's maps into an Index with deterministically sorted
// slices so emitters and tests observe a stable order.
func (b *indexBuilder) finish(meta Meta) *Index {
	ix := &Index{Meta: meta, Slots: b.slots}
	sort.Slice(ix.Slots, func(i, j int) bool { return ix.Slots[i].SlotAddr < ix.Slots[j].SlotAddr })

	ix.Forward = make([]ForwardEntry, 0, len(b.forward))
	for _, fe := range b.forward {
		sortCandidates(fe.Candidates)
		ix.Forward = append(ix.Forward, *fe)
	}
	sort.Slice(ix.Forward, func(i, j int) bool {
		if ix.Forward[i].Offset != ix.Forward[j].Offset {
			return ix.Forward[i].Offset < ix.Forward[j].Offset
		}
		return ix.Forward[i].PAC < ix.Forward[j].PAC
	})

	ix.Inverse = make([]InverseEntry, 0, len(b.inverse))
	for _, ie := range b.inverse {
		sortRefs(ie.Refs)
		ix.Inverse = append(ix.Inverse, *ie)
	}
	sort.Slice(ix.Inverse, func(i, j int) bool { return ix.Inverse[i].Target < ix.Inverse[j].Target })
	return ix
}

func sortCandidates(c []Candidate) {
	sort.Slice(c, func(i, j int) bool {
		if c[i].Class != c[j].Class {
			return c[i].Class < c[j].Class
		}
		if c[i].Target != c[j].Target {
			return c[i].Target < c[j].Target
		}
		return c[i].SlotAddr < c[j].SlotAddr
	})
}

func sortRefs(r []InverseRef) {
	sort.Slice(r, func(i, j int) bool {
		if r[i].Offset != r[j].Offset {
			return r[i].Offset < r[j].Offset
		}
		if r[i].PAC != r[j].PAC {
			return r[i].PAC < r[j].PAC
		}
		return r[i].SlotAddr < r[j].SlotAddr
	})
}

// Lookup returns the candidate targets for a (offset, pac) key, or nil.
func (ix *Index) Lookup(offset uint64, pac uint16) []Candidate {
	for i := range ix.Forward {
		if ix.Forward[i].Offset == offset && ix.Forward[i].PAC == pac {
			return ix.Forward[i].Candidates
		}
	}
	return nil
}
