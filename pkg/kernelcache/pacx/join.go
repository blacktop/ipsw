package pacx

// This file joins the two (offset, pac) indexes into resolved authenticated
// virtual-call edges. The vtable-side forward index (index.go) maps a
// (slot-offset, 16-bit pac) pair to every candidate target slot; the call-site
// index (callsite.go) maps the same (offset, hash) pair to every call site that
// dispatches through it. The join looks each call site up in the forward index
// by (offset, hash==pac) TOGETHER, filters the candidates by the call's auth key
// and address-diversity form, and emits one PacRecord per call site carrying all
// matching candidates.
//
// A call site with exactly one candidate is an exact resolution; more than one
// is inherent C++ override ambiguity and every candidate is emitted (never
// silently picked). Call sites with zero candidates are dropped unless
// includeUnresolved is set. Matching is always on (offset, pac) together: two
// slots sharing a pac at different offsets are not interchangeable, a pac-only
// match would fabricate edges the diversifier exists to prevent, and a slot
// signed with the wrong key or without address diversity cannot authenticate for
// the recovered BLRAA/BLRAB call form.

import (
	"io"
	"sort"
	"strconv"
)

// Confidence tiers for a resolved call site.
const (
	ConfidenceExact      = "exact"
	ConfidenceAmbiguous  = "ambiguous"
	ConfidenceUnresolved = "unresolved"
)

// PacCandidate is one vtable target a call site may dispatch to.
type PacCandidate struct {
	Vfunc       uint64
	VfuncSymbol string
	Class       string
	Vtable      uint64
	SlotAddr    uint64
}

// PacRecord is one resolved authenticated virtual call. Ambiguous records carry
// more than one candidate; unresolved records (only present when includeUnresolved
// is set) carry none.
type PacRecord struct {
	Callsite     uint64
	Auth         string
	CallerFunc   uint64
	CallerSymbol string
	Image        string
	SlotOffset   uint64
	SlotIndex    int
	PAC          uint16
	Resolved     bool
	Ambiguous    bool
	Confidence   string
	Candidates   []PacCandidate
}

// SiteMeta carries the per-call-site attributes the (offset, pac) indexes do not
// hold: the fileset image, the caller function's symbol, and the auth mnemonic
// (blraa/blrab).
type SiteMeta struct {
	Image        string
	CallerSymbol string
	Auth         string
}

// SiteAttributor resolves the per-call-site metadata that is not derivable from
// the two indexes. It may be nil, in which case those fields stay empty.
type SiteAttributor func(site CallSite) SiteMeta

// Join resolves every call site in csi against the vtable-side forward index and
// returns the sorted PacRecords. A call site matches only when its (offset, hash)
// equals a forward key's (offset, pac) exactly. Zero-candidate call sites are
// dropped unless includeUnresolved is set. attr may be nil.
func Join(index *Index, csi CallSiteIndex, attr SiteAttributor, includeUnresolved bool) []PacRecord {
	var records []PacRecord
	for key, sites := range csi {
		var indexed []Candidate
		if index != nil {
			indexed = index.Lookup(key.Offset, key.Hash)
		}
		for _, site := range sites {
			cands := matchingCandidates(indexed, site)
			if len(cands) == 0 && !includeUnresolved {
				continue
			}
			records = append(records, buildRecord(key, site, cands, attr))
		}
	}
	SortRecords(records)
	return records
}

func matchingCandidates(cands []Candidate, site CallSite) []Candidate {
	if len(cands) == 0 {
		return nil
	}
	key := callKey(site)
	out := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if c.AddrDiv && c.Key == key {
			out = append(out, c)
		}
	}
	return out
}

func callKey(site CallSite) uint8 {
	if site.KeyB {
		return 1
	}
	return 0
}

// buildRecord assembles a single PacRecord from a call site and its candidates.
func buildRecord(key CallKey, site CallSite, cands []Candidate, attr SiteAttributor) PacRecord {
	rec := PacRecord{
		Callsite:   site.Addr,
		CallerFunc: site.CallerFuncAddr,
		SlotOffset: key.Offset,
		SlotIndex:  int(key.Offset / 8),
		PAC:        key.Hash,
		Resolved:   len(cands) > 0,
		Ambiguous:  len(cands) > 1,
		Confidence: confidenceFor(len(cands)),
	}
	for _, c := range cands {
		rec.Candidates = append(rec.Candidates, PacCandidate{
			Vfunc:       c.Target,
			VfuncSymbol: c.Symbol,
			Class:       c.Class,
			Vtable:      c.SlotAddr - key.Offset,
			SlotAddr:    c.SlotAddr,
		})
	}
	if attr != nil {
		m := attr(site)
		rec.Image = m.Image
		rec.CallerSymbol = m.CallerSymbol
		rec.Auth = m.Auth
	}
	return rec
}

func confidenceFor(n int) string {
	switch {
	case n == 1:
		return ConfidenceExact
	case n > 1:
		return ConfidenceAmbiguous
	default:
		return ConfidenceUnresolved
	}
}

// SortRecords orders records by image, then call site, then slot offset and pac
// so emitters and tests observe a stable order.
func SortRecords(records []PacRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Image != records[j].Image {
			return records[i].Image < records[j].Image
		}
		if records[i].Callsite != records[j].Callsite {
			return records[i].Callsite < records[j].Callsite
		}
		if records[i].SlotOffset != records[j].SlotOffset {
			return records[i].SlotOffset < records[j].SlotOffset
		}
		return records[i].PAC < records[j].PAC
	})
}

// WriteJSONL writes records as newline-delimited JSON, one PacRecord per line,
// in sorted order.
func WriteJSONL(w io.Writer, records []PacRecord) error {
	SortRecords(records)
	for _, rec := range records {
		if _, err := w.Write(rec.AppendJSON(nil)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return nil
}

// AppendJSON appends the JSON encoding of the record to dst. Addresses and the
// pac are 0x-hex strings; slot_offset and slot_index are decimal.
func (r PacRecord) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"callsite":`...)
	dst = strconv.AppendQuote(dst, hexAddr(r.Callsite))
	dst = append(dst, `,"auth":`...)
	dst = strconv.AppendQuote(dst, r.Auth)
	dst = append(dst, `,"caller_func":`...)
	dst = strconv.AppendQuote(dst, hexAddr(r.CallerFunc))
	dst = append(dst, `,"caller_symbol":`...)
	dst = strconv.AppendQuote(dst, r.CallerSymbol)
	dst = append(dst, `,"image":`...)
	dst = strconv.AppendQuote(dst, r.Image)
	dst = append(dst, `,"slot_offset":`...)
	dst = strconv.AppendUint(dst, r.SlotOffset, 10)
	dst = append(dst, `,"slot_index":`...)
	dst = strconv.AppendInt(dst, int64(r.SlotIndex), 10)
	dst = append(dst, `,"pac":`...)
	dst = strconv.AppendQuote(dst, hexAddr(uint64(r.PAC)))
	dst = append(dst, `,"resolved":`...)
	dst = strconv.AppendBool(dst, r.Resolved)
	dst = append(dst, `,"ambiguous":`...)
	dst = strconv.AppendBool(dst, r.Ambiguous)
	dst = append(dst, `,"confidence":`...)
	dst = strconv.AppendQuote(dst, r.Confidence)
	dst = append(dst, `,"candidates":`...)
	dst = appendCandidates(dst, r.Candidates)
	dst = append(dst, '}')
	return dst
}

func appendCandidates(dst []byte, cands []PacCandidate) []byte {
	dst = append(dst, '[')
	for i, c := range cands {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"vfunc":`...)
		dst = strconv.AppendQuote(dst, hexAddr(c.Vfunc))
		dst = append(dst, `,"vfunc_symbol":`...)
		dst = strconv.AppendQuote(dst, c.VfuncSymbol)
		dst = append(dst, `,"class":`...)
		dst = strconv.AppendQuote(dst, c.Class)
		dst = append(dst, `,"vtable":`...)
		dst = strconv.AppendQuote(dst, hexAddr(c.Vtable))
		dst = append(dst, `,"slot_addr":`...)
		dst = strconv.AppendQuote(dst, hexAddr(c.SlotAddr))
		dst = append(dst, '}')
	}
	return append(dst, ']')
}

// FuncsFromCallSite returns the candidate targets reachable from the call site at
// addr (the PacXplorer "callsite" query). It returns nil when no record matches.
func FuncsFromCallSite(records []PacRecord, addr uint64) []PacCandidate {
	for i := range records {
		if records[i].Callsite == addr {
			return records[i].Candidates
		}
	}
	return nil
}

// CallSitesFromFunc returns every record whose candidate set includes vfunc (the
// PacXplorer "func" query).
func CallSitesFromFunc(records []PacRecord, vfunc uint64) []PacRecord {
	var out []PacRecord
	for i := range records {
		for _, c := range records[i].Candidates {
			if c.Vfunc == vfunc {
				out = append(out, records[i])
				break
			}
		}
	}
	return out
}
