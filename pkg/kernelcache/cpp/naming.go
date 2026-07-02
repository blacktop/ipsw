package cpp

import (
	"fmt"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/demangle"
)

// BuildNamedMethodTables builds PAC-annotated method tables for classes and
// resolves per-slot names and classification across the class hierarchy:
// override detection, symbol demangling, inheritance of parent names, structor
// name re-synthesis, fn_0x fallback, and back-propagation of authoritative
// names down chains of guessed ancestors. The result is index-aligned with
// classes.
func (s *Scanner) BuildNamedMethodTables(classes []Class) []MethodTable {
	tables := s.BuildMethodTables(classes)
	for i := range tables {
		for j := range tables[i].Methods {
			e := &tables[i].Methods[j]
			if mangled := s.rawSymbolName(e.Address); mangled != "" {
				e.Mangled = mangled
			} else if e.ExternalReloc && e.Symbol != "" {
				e.Mangled = e.Symbol
			}
		}
	}
	nameMethodTables(classes, tables)
	return tables
}

// rawSymbolName returns the raw (still-mangled) symtab/export symbol at addr, or
// empty when the address is stripped. Unlike SymbolName it does not demangle.
func (s *Scanner) rawSymbolName(addr uint64) string {
	if addr == 0 {
		return ""
	}
	owner := s.fileForVMAddr(addr)
	for _, file := range []*macho.File{owner, s.root} {
		if file == nil {
			continue
		}
		syms, err := file.FindAddressSymbols(addr)
		if err != nil {
			continue
		}
		for _, sym := range syms {
			name := strings.TrimSpace(sym.Name)
			if name == "" || name == "<redacted>" {
				continue
			}
			return name
		}
	}
	return ""
}

const (
	stUnvisited int8 = iota
	stVisiting
	stDone
)

// nameState carries the cross-class bookkeeping for the naming pass. tables is
// index-aligned with classes. chain[t][slot] links same-slot entries whose
// names were guessed (inherited non-authoritatively) so a later authoritative
// resolution can back-propagate down the chain; -1 terminates a link.
type nameState struct {
	classes []Class
	tables  []MethodTable
	metaIdx map[uint64]int
	chain   [][]int
	state   []int8
}

// nameMethodTables resolves per-slot names and classification for tables in
// parents-first order. classes and tables must be index-aligned.
func nameMethodTables(classes []Class, tables []MethodTable) {
	if len(classes) != len(tables) {
		return
	}
	ns := newNameState(classes, tables)
	for i := range tables {
		ns.process(i)
	}
}

func newNameState(classes []Class, tables []MethodTable) *nameState {
	ns := &nameState{
		classes: classes,
		tables:  tables,
		metaIdx: make(map[uint64]int, len(classes)),
		chain:   make([][]int, len(tables)),
		state:   make([]int8, len(tables)),
	}
	for i := range classes {
		if mp := classes[i].MetaPtr; mp != 0 {
			if _, exists := ns.metaIdx[mp]; !exists {
				ns.metaIdx[mp] = i
			}
		}
	}
	for i := range tables {
		links := make([]int, len(tables[i].Methods))
		for j := range links {
			links[j] = -1
		}
		ns.chain[i] = links
	}
	return ns
}

// process names table i after its effective parent, guarding against cycles.
func (ns *nameState) process(i int) {
	if ns.state[i] != stUnvisited {
		return
	}
	ns.state[i] = stVisiting
	p := ns.effectiveParent(i)
	if p >= 0 {
		ns.process(p)
	}
	for idx := range ns.tables[i].Methods {
		ns.nameSlot(i, p, idx)
	}
	ns.state[i] = stDone
}

// rawParent returns the table index of i's direct super-metaclass, or -1.
func (ns *nameState) rawParent(i int) int {
	sm := ns.classes[i].SuperMeta
	if sm == 0 {
		return -1
	}
	if j, ok := ns.metaIdx[sm]; ok && j != i {
		return j
	}
	return -1
}

// effectiveParent returns the nearest ancestor of i that has a vtable, skipping
// abstract (empty) intermediates, or -1.
func (ns *nameState) effectiveParent(i int) int {
	p := ns.rawParent(i)
	for steps := 0; p >= 0 && len(ns.tables[p].Methods) == 0 && steps < len(ns.tables); steps++ {
		p = ns.rawParent(p)
	}
	if p >= 0 && len(ns.tables[p].Methods) == 0 {
		return -1
	}
	return p
}

// nameSlot resolves the name and classification for slot idx of table i, given
// its effective parent table p (-1 when none).
func (ns *nameState) nameSlot(i, p, idx int) {
	e := &ns.tables[i].Methods[idx]
	var pent *VtableEntry
	if p >= 0 && idx < len(ns.tables[p].Methods) {
		pent = &ns.tables[p].Methods[idx]
		e.ParentAddress = pent.Address
	}
	if !e.ExternalReloc {
		e.Overrides = pent == nil || e.Address != pent.Address
	}
	if !e.PureVirtual {
		resolveOwnName(e)
	}
	if e.Method == "" && pent != nil {
		ns.inherit(i, p, idx, e, pent)
	}
	if e.Method == "" {
		e.Method = fmt.Sprintf("fn_0x%x()", idx*8)
	}
	if e.Class == "" {
		e.Class = ns.classes[i].Name
	}
	if e.Authoritative && !e.Structor && pent != nil && !pent.Authoritative {
		ns.backPropagate(i, idx, e.Method)
	}
}

// resolveOwnName populates Class/Method/Structor from the slot's own mangled
// symbol when it demangles to a class-qualified C++ name.
func resolveOwnName(e *VtableEntry) {
	if e.Mangled == "" {
		return
	}
	demangled := demangle.Do(e.Mangled, false, false)
	if demangled == e.Mangled {
		return
	}
	class, method, ok := splitClassMethod(stripThunkPrefix(demangled))
	if !ok {
		return
	}
	e.Class = class
	e.Method = method
	e.Structor = isStructor(class, method)
	e.Authoritative = true
}

// inherit resolves a slot with no own name from its parent slot pent, either
// re-synthesizing a structor name or inheriting the parent method name and
// linking a guessed name into the back-propagation chain.
func (ns *nameState) inherit(i, p, idx int, e, pent *VtableEntry) {
	e.Method = pent.Method
	if pent.Structor {
		ns.resynthStructor(i, e, pent)
		return
	}
	if e.Overrides {
		e.Class = ns.classes[i].Name
	} else {
		e.Class = pent.Class
	}
	e.Authoritative = pent.Authoritative
	if !e.Authoritative {
		old := ns.chain[p][idx]
		ns.chain[p][idx] = i
		ns.chain[i][idx] = old
	}
}

// resynthStructor rebuilds a constructor/destructor name for this class from the
// parent structor entry. A parent name that does not begin with the parent's
// class basename is treated as a bad structor and the method is cleared.
func (ns *nameState) resynthStructor(i int, e, pent *VtableEntry) {
	method := pent.Method
	dest := strings.HasPrefix(method, "~")
	mth := method
	if dest {
		mth = mth[1:]
	}
	base := classBasename(pent.Class)
	if base == "" || !strings.HasPrefix(mth, base) {
		e.Method = ""
		return
	}
	suffix := mth[len(base):]
	own := classBasename(ns.classes[i].Name)
	if dest {
		e.Method = "~" + own + suffix
	} else {
		e.Method = own + suffix
	}
	e.Class = ns.classes[i].Name
	e.Structor = true
	e.Authoritative = false
}

// backPropagate rewrites the guessed name of every ancestor in slot idx's chain,
// from the topmost class that owns the slot down to i's parent, with the
// authoritative method name that i just resolved.
func (ns *nameState) backPropagate(i, idx int, method string) {
	cls := i
	for c := ns.rawParent(cls); c >= 0; c = ns.rawParent(c) {
		methods := ns.tables[c].Methods
		if len(methods) == 0 {
			continue
		}
		if idx >= len(methods) {
			break
		}
		cls = c
	}
	if idx >= len(ns.tables[cls].Methods) || ns.tables[cls].Methods[idx].Authoritative {
		return
	}
	for next := cls; next >= 0; {
		m := &ns.tables[next].Methods[idx]
		m.Method = method
		m.Authoritative = true
		cur := next
		next = ns.chain[cur][idx]
		ns.chain[cur][idx] = -1
	}
}

// splitClassMethod splits a demangled C++ name like "Foo::Bar::baz(int)" into
// class ("Foo::Bar") and method ("baz(int)"), ignoring "::" nested inside
// template arguments. ok is false when no top-level "::" separator exists.
func splitClassMethod(demangled string) (string, string, bool) {
	demangled = stripThunkPrefix(demangled)
	argStart := len(demangled)
	depth := 0
	for i := 0; i < len(demangled); i++ {
		switch demangled[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case '(':
			if depth == 0 {
				argStart = i
				i = len(demangled)
			}
		}
	}
	depth = 0
	for i := argStart - 1; i >= 1; i-- {
		switch demangled[i] {
		case '>':
			depth++
		case '<':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 && demangled[i-1] == ':' {
				return demangled[:i-1], demangled[i+1:], true
			}
		}
	}
	return "", "", false
}

func stripThunkPrefix(demangled string) string {
	for {
		demangled = strings.TrimSpace(demangled)
		switch {
		case strings.HasPrefix(demangled, "non-virtual thunk to "):
			demangled = strings.TrimPrefix(demangled, "non-virtual thunk to ")
		case strings.HasPrefix(demangled, "virtual thunk to "):
			demangled = strings.TrimPrefix(demangled, "virtual thunk to ")
		default:
			return demangled
		}
	}
}

// classBasename returns the last "::"-separated component of a class name,
// dropping any trailing template argument list ("Foo::Bar<Baz>" -> "Bar").
func classBasename(class string) string {
	end := len(class)
	if end > 0 && class[end-1] == '>' {
		depth := 0
		j := end
		for j > 0 {
			c := class[j-1]
			j--
			if c == '>' {
				depth++
			} else if c == '<' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		end = j
	}
	for i := end; i >= 2; i-- {
		if class[i-1] == ':' && class[i-2] == ':' {
			return class[i:end]
		}
	}
	return class[:end]
}

// isStructor reports whether method is a constructor or destructor of class.
func isStructor(class, method string) bool {
	if strings.HasPrefix(method, "~") {
		return true
	}
	name := method
	if idx := strings.IndexAny(name, "(<"); idx >= 0 {
		name = name[:idx]
	}
	return name != "" && name == classBasename(class)
}
