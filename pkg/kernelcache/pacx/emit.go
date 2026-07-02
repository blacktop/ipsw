package pacx

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/template"
)

// hexAddr formats an address as a 0x-prefixed lowercase hex string.
func hexAddr(a uint64) string {
	return fmt.Sprintf("%#x", a)
}

// ---- JSON emission ------------------------------------------------------------

type jsonMeta struct {
	Kernelcache string `json:"kernelcache"`
	UUID        string `json:"uuid,omitempty"`
	Arch        string `json:"arch,omitempty"`
	FixupFormat string `json:"fixup_format,omitempty"`
	KernelBase  string `json:"kernel_base"`
}

type jsonSlot struct {
	Class       string `json:"class"`
	Bundle      string `json:"bundle,omitempty"`
	VtableAddr  string `json:"vtable_addr"`
	SlotIndex   int    `json:"slot_index"`
	Offset      uint64 `json:"offset"`
	SlotAddr    string `json:"slot_addr"`
	Target      string `json:"target"`
	Symbol      string `json:"symbol,omitempty"`
	PAC         uint16 `json:"pac"`
	PACHex      string `json:"pac_hex"`
	Key         uint8  `json:"key"`
	AddrDiv     bool   `json:"addr_div"`
	CacheLevel  uint8  `json:"cache_level"`
	VtableKind  string `json:"vtable_kind"`
	VtableIndex int    `json:"vtable_index"`
	BaseOffset  uint64 `json:"base_offset"`
}

type jsonCandidate struct {
	Class    string `json:"class"`
	Target   string `json:"target"`
	Symbol   string `json:"symbol,omitempty"`
	SlotAddr string `json:"slot_addr"`
	Key      uint8  `json:"key"`
	AddrDiv  bool   `json:"addr_div"`
}

type jsonForward struct {
	Offset     uint64          `json:"offset"`
	PAC        uint16          `json:"pac"`
	PACHex     string          `json:"pac_hex"`
	Candidates []jsonCandidate `json:"candidates"`
}

type jsonInverseRef struct {
	Offset   uint64 `json:"offset"`
	PAC      uint16 `json:"pac"`
	PACHex   string `json:"pac_hex"`
	Class    string `json:"class"`
	SlotAddr string `json:"slot_addr"`
}

type jsonInverse struct {
	Target string           `json:"target"`
	Symbol string           `json:"symbol,omitempty"`
	Keys   []jsonInverseRef `json:"keys"`
}

type jsonDoc struct {
	Meta    jsonMeta      `json:"meta"`
	Slots   []jsonSlot    `json:"slots,omitempty"`
	Forward []jsonForward `json:"forward"`
	Inverse []jsonInverse `json:"inverse"`
}

func (ix *Index) toJSONDoc(includeSlots bool) jsonDoc {
	doc := jsonDoc{
		Meta: jsonMeta{
			Kernelcache: ix.Meta.Kernelcache,
			UUID:        ix.Meta.UUID,
			Arch:        ix.Meta.Arch,
			FixupFormat: ix.Meta.FixupFormat,
			KernelBase:  hexAddr(ix.Meta.KernelBase),
		},
		Forward: make([]jsonForward, 0, len(ix.Forward)),
		Inverse: make([]jsonInverse, 0, len(ix.Inverse)),
	}
	if includeSlots {
		doc.Slots = make([]jsonSlot, 0, len(ix.Slots))
		for _, s := range ix.Slots {
			doc.Slots = append(doc.Slots, jsonSlot{
				Class:       s.Class,
				Bundle:      s.Bundle,
				VtableAddr:  hexAddr(s.VtableAddr),
				SlotIndex:   s.SlotIndex,
				Offset:      s.Offset,
				SlotAddr:    hexAddr(s.SlotAddr),
				Target:      hexAddr(s.Target),
				Symbol:      s.Symbol,
				PAC:         s.PAC,
				PACHex:      hexAddr(uint64(s.PAC)),
				Key:         s.Key,
				AddrDiv:     s.AddrDiv,
				CacheLevel:  s.CacheLevel,
				VtableKind:  "primary",
				VtableIndex: 0,
				BaseOffset:  0,
			})
		}
	}
	for _, f := range ix.Forward {
		cands := make([]jsonCandidate, 0, len(f.Candidates))
		for _, c := range f.Candidates {
			cands = append(cands, jsonCandidate{
				Class:    c.Class,
				Target:   hexAddr(c.Target),
				Symbol:   c.Symbol,
				SlotAddr: hexAddr(c.SlotAddr),
				Key:      c.Key,
				AddrDiv:  c.AddrDiv,
			})
		}
		doc.Forward = append(doc.Forward, jsonForward{
			Offset:     f.Offset,
			PAC:        f.PAC,
			PACHex:     hexAddr(uint64(f.PAC)),
			Candidates: cands,
		})
	}
	for _, inv := range ix.Inverse {
		keys := make([]jsonInverseRef, 0, len(inv.Refs))
		for _, r := range inv.Refs {
			keys = append(keys, jsonInverseRef{
				Offset:   r.Offset,
				PAC:      r.PAC,
				PACHex:   hexAddr(uint64(r.PAC)),
				Class:    r.Class,
				SlotAddr: hexAddr(r.SlotAddr),
			})
		}
		doc.Inverse = append(doc.Inverse, jsonInverse{
			Target: hexAddr(inv.Target),
			Symbol: inv.Symbol,
			Keys:   keys,
		})
	}
	return doc
}

// WriteJSON writes the index as pacx.json. Addresses are 0x-hex strings, offsets
// are decimal, and PAC values carry both a decimal and a pac_hex form. The full
// per-slot slots[] array is emitted only when includeSlots is set; forward and
// inverse (the primary xref material) are always written.
func (ix *Index) WriteJSON(w io.Writer, includeSlots bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ix.toJSONDoc(includeSlots)); err != nil {
		return fmt.Errorf("encode pacx json: %w", err)
	}
	return nil
}

// ---- IDAPython emission -------------------------------------------------------

// pyCandidate/pyForward/pyInverse mirror the forward/inverse shape but keep
// addresses as integers so the embedded Python can do rebase arithmetic.
type pyCandidate struct {
	Class    string `json:"class"`
	Target   uint64 `json:"target"`
	Symbol   string `json:"symbol"`
	SlotAddr uint64 `json:"slot_addr"`
	Key      uint8  `json:"key"`
	AddrDiv  bool   `json:"addr_div"`
}

type pyForward struct {
	Offset     uint64        `json:"offset"`
	PAC        uint16        `json:"pac"`
	Candidates []pyCandidate `json:"candidates"`
}

type pyInverseRef struct {
	Offset   uint64 `json:"offset"`
	PAC      uint16 `json:"pac"`
	Class    string `json:"class"`
	SlotAddr uint64 `json:"slot_addr"`
}

type pyInverse struct {
	Target uint64         `json:"target"`
	Symbol string         `json:"symbol"`
	Keys   []pyInverseRef `json:"keys"`
}

func (ix *Index) toPyForward() []pyForward {
	out := make([]pyForward, 0, len(ix.Forward))
	for _, f := range ix.Forward {
		cands := make([]pyCandidate, 0, len(f.Candidates))
		for _, c := range f.Candidates {
			cands = append(cands, pyCandidate{
				Class: c.Class, Target: c.Target, Symbol: c.Symbol,
				SlotAddr: c.SlotAddr, Key: c.Key, AddrDiv: c.AddrDiv,
			})
		}
		out = append(out, pyForward{Offset: f.Offset, PAC: f.PAC, Candidates: cands})
	}
	return out
}

func (ix *Index) toPyInverse() []pyInverse {
	out := make([]pyInverse, 0, len(ix.Inverse))
	for _, inv := range ix.Inverse {
		keys := make([]pyInverseRef, 0, len(inv.Refs))
		for _, r := range inv.Refs {
			keys = append(keys, pyInverseRef{Offset: r.Offset, PAC: r.PAC, Class: r.Class, SlotAddr: r.SlotAddr})
		}
		out = append(out, pyInverse{Target: inv.Target, Symbol: inv.Symbol, Keys: keys})
	}
	return out
}

type idaTemplateData struct {
	Kernelcache string
	KernelBase  string
	Forward     string
	Inverse     string
}

var idaTemplate = template.Must(template.New("pacx.py").Parse(idaScript))

// WriteIDAPython writes pacx.py: the embedded FORWARD/INVERSE index plus the
// pacx_candidates/pacx_xrefs/pacx_annotate helpers. The script does no call-site
// scan; pacx_annotate only comments the known vtable slots.
func (ix *Index) WriteIDAPython(w io.Writer) error {
	fwd, err := json.Marshal(ix.toPyForward())
	if err != nil {
		return fmt.Errorf("encode pacx forward: %w", err)
	}
	inv, err := json.Marshal(ix.toPyInverse())
	if err != nil {
		return fmt.Errorf("encode pacx inverse: %w", err)
	}
	data := idaTemplateData{
		Kernelcache: ix.Meta.Kernelcache,
		KernelBase:  hexAddr(ix.Meta.KernelBase),
		Forward:     string(fwd),
		Inverse:     string(inv),
	}
	if err := idaTemplate.Execute(w, data); err != nil {
		return fmt.Errorf("render pacx.py: %w", err)
	}
	return nil
}

// ---- radare2 emission ---------------------------------------------------------

type r2Comment struct {
	Addr string
	Text string
}

type r2Flag struct {
	Name string
	Addr string
}

type r2TemplateData struct {
	Kernelcache string
	Comments    []r2Comment
	Flags       []r2Flag
}

var r2Template = template.Must(template.New("pacx.r2").Parse(r2Script))

// sanitizeFlag rewrites a symbol into a radare2-safe flag component. Empty names
// fall back to the target address so every flag is still unique.
func sanitizeFlag(sym string, target uint64) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, sym)
	name = strings.Trim(name, "_")
	if name == "" {
		return fmt.Sprintf("fn_%x", target)
	}
	return name
}

// WriteR2 writes pacx.r2: a CCu comment on each authenticated slot and an f flag
// on each target function.
func (ix *Index) WriteR2(w io.Writer) error {
	data := r2TemplateData{Kernelcache: ix.Meta.Kernelcache}
	for _, f := range ix.Forward {
		for _, c := range f.Candidates {
			data.Comments = append(data.Comments, r2Comment{
				Addr: hexAddr(c.SlotAddr),
				Text: fmt.Sprintf("pacx off=%#x pac=%#x %s -> %s",
					f.Offset, f.PAC, c.Class, candidateLabel(c)),
			})
		}
	}
	for _, inv := range ix.Inverse {
		data.Flags = append(data.Flags, r2Flag{
			Name: "pacx." + sanitizeFlag(inv.Symbol, inv.Target),
			Addr: hexAddr(inv.Target),
		})
	}
	if err := r2Template.Execute(w, data); err != nil {
		return fmt.Errorf("render pacx.r2: %w", err)
	}
	return nil
}

func candidateLabel(c Candidate) string {
	if c.Symbol != "" {
		return c.Symbol
	}
	return hexAddr(c.Target)
}
