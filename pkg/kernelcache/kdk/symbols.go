package kdk

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
)

// A fully stripped kernel collection has no symbol names at all, not even the
// undefined symbols of its KEXTs. kmutil can only link a KEXT's imports by
// name, so the extracted images need *some* names. synthesizeLinkSymbols
// invents them: every cross-image reference target gets a name that the
// defining image exports and every referencing image imports. kmutil strips
// symbols when building a stripped collection, so the names never reach the
// output; they only have to be consistent.
//
// KEXT targets get synthetic names derived from their position in their
// section, so identical images get identical names in different collections:
//
//	_kc.<bundle-id>.<segment>.<section>.f<function index>[_<offset>]  (code)
//	_kc.<bundle-id>.<segment>.<section>.d<hex offset>                 (data)
//
// Kernel targets are restricted by the kernel's __LINKINFO,__symbolsets: a
// KEXT only sees kernel symbols listed for the com.apple.kpi.* libraries it
// depends on, and the symbol sets are copied into the collection unchanged.
// KEXTs depending on com.apple.kpi.private can use synthetic names below one of
// its exported prefixes. Others get placeholder names taken from their KPI sets;
// such a placeholder labels an arbitrary address and does not identify the
// original function.
type linkSymbols struct {
	imports map[string][]macho.Symbol // entry -> undefined symbols (Value = target)
	exports map[string][]macho.Symbol // entry -> defined symbols
}

type symbolSets struct {
	WeakRefFallbackSymbol struct {
		SymbolName string `plist:"SymbolName"`
	} `plist:"WeakRefFallbackSymbol"`
	SymbolsSets []struct {
		CFBundleIdentifier string `plist:"CFBundleIdentifier"`
		Symbols            []struct {
			SymbolName   string `plist:"SymbolName"`
			SymbolPrefix string `plist:"SymbolPrefix"`
			AliasTarget  string `plist:"AliasTarget"`
		} `plist:"Symbols"`
	} `plist:"SymbolsSets"`
}

// isStrippedCollection reports whether the kernel has no symbols to link with.
func isStrippedCollection(entries map[string]*macho.File) bool {
	kernel := entries[kernelID]
	return kernel != nil && (kernel.Symtab == nil || len(kernel.Symtab.Syms) == 0)
}

type sectionRange struct {
	entry   string
	index   uint8 // 1-based section ordinal within the entry
	section *types.Section
}

func synthesizeLinkSymbols(entries map[string]*macho.File, refs map[string][]*types.SplitInfoEntry, infos []bundleInfo, known map[uint64][]string) (*linkSymbols, error) {
	kernel := entries[kernelID]

	// Locate the image and section of every target.
	var ranges []sectionRange
	for id, f := range entries {
		for i, s := range f.Sections {
			if s.Size > 0 {
				ranges = append(ranges, sectionRange{entry: id, index: uint8(i + 1), section: s})
			}
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].section.Addr < ranges[j].section.Addr })
	lookup := func(addr uint64) (sectionRange, bool) {
		i := sort.Search(len(ranges), func(i int) bool { return ranges[i].section.Addr > addr }) - 1
		if i >= 0 && addr < ranges[i].section.Addr+ranges[i].section.Size {
			return ranges[i], true
		}
		return sectionRange{}, false
	}

	// Collect cross-image targets per referencing image. Pointers become
	// binds; branches reach the same targets through their GOT slots.
	type need struct {
		entry  string
		target uint64
	}
	var needs []need
	for id, entryRefs := range refs {
		seen := make(map[uint64]struct{})
		for _, ref := range entryRefs {
			if ref.Kind != types.DYLD_CACHE_ADJ_V2_POINTER_64 && ref.Kind != types.DYLD_CACHE_ADJ_V2_ARM64_BR26 {
				continue
			}
			owner, ok := lookup(ref.TargetVmAddr)
			if !ok || owner.entry == id {
				continue
			}
			if _, dup := seen[ref.TargetVmAddr]; dup {
				continue
			}
			seen[ref.TargetVmAddr] = struct{}{}
			needs = append(needs, need{id, ref.TargetVmAddr})
		}
	}
	sort.Slice(needs, func(i, j int) bool {
		if needs[i].entry != needs[j].entry {
			return needs[i].entry < needs[j].entry
		}
		return needs[i].target < needs[j].target
	})

	// Synthetic, position-derived names.
	functionStarts := make(map[string][]uint64)
	for id, f := range entries {
		var starts []uint64
		for _, fn := range f.GetFunctions() {
			starts = append(starts, fn.StartAddr)
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		functionStarts[id] = starts
	}
	positionName := func(owner sectionRange, target uint64) string {
		// Section names repeat across segments (__TEXT.__const,
		// __DATA_CONST.__const, ...), so qualify them.
		section := strings.TrimLeft(owner.section.Seg, "_") + "." + strings.TrimLeft(owner.section.Name, "_")
		if owner.section.Flags.IsPureInstructions() || owner.section.Flags.IsSomeInstructions() {
			starts := functionStarts[owner.entry]
			i := sort.Search(len(starts), func(i int) bool { return starts[i] > target }) - 1
			if i >= 0 && starts[i] >= owner.section.Addr {
				if starts[i] == target {
					return fmt.Sprintf("%s.f%d", section, i)
				}
				return fmt.Sprintf("%s.f%d_%x", section, i, target-starts[i])
			}
		}
		// Offsets, unlike reference counts, do not depend on which images
		// the collection contains.
		return fmt.Sprintf("%s.d%x", section, target-owner.section.Addr)
	}

	// Kernel symbol sets.
	var sets symbolSets
	if sec := kernel.Section("__LINKINFO", "__symbolsets"); sec != nil {
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read kernel symbol sets: %w", err)
		}
		if _, err := plist.Unmarshal(data, &sets); err != nil {
			return nil, fmt.Errorf("failed to parse kernel symbol sets: %w", err)
		}
	}
	setNames := make(map[string][]string) // KPI -> exported plain names
	privatePrefix := ""
	var privatePrefixes []string
	reserved := make(map[string]struct{}) // alias names and targets
	for _, set := range sets.SymbolsSets {
		for _, sym := range set.Symbols {
			switch {
			case sym.SymbolPrefix != "":
				if set.CFBundleIdentifier == "com.apple.kpi.private" {
					if privatePrefix == "" {
						privatePrefix = sym.SymbolPrefix
					}
					privatePrefixes = append(privatePrefixes, sym.SymbolPrefix)
				}
			case sym.AliasTarget != "":
				reserved[sym.SymbolName] = struct{}{}
				reserved[sym.AliasTarget] = struct{}{}
			case sym.SymbolName != "":
				setNames[set.CFBundleIdentifier] = append(setNames[set.CFBundleIdentifier], sym.SymbolName)
			}
		}
	}
	if sets.WeakRefFallbackSymbol.SymbolName != "" {
		reserved[sets.WeakRefFallbackSymbol.SymbolName] = struct{}{}
	}

	deps := make(map[string][]string)
	for _, info := range infos {
		id, _ := info["CFBundleIdentifier"].(string)
		if libs, ok := info["OSBundleLibraries"].(map[string]any); ok {
			for lib := range libs {
				deps[id] = append(deps[id], lib)
			}
			sort.Strings(deps[id])
		}
	}
	// kmutil resolves a KEXT's symbols through all of its dependencies,
	// direct or not.
	closure := make(map[string][]string, len(deps))
	for id := range deps {
		seen := map[string]bool{id: true}
		queue := append([]string(nil), deps[id]...)
		for len(queue) > 0 {
			dep := queue[0]
			queue = queue[1:]
			if seen[dep] {
				continue
			}
			seen[dep] = true
			closure[id] = append(closure[id], dep)
			queue = append(queue, deps[dep]...)
		}
		sort.Strings(closure[id])
	}
	deps = closure

	result := &linkSymbols{imports: make(map[string][]macho.Symbol), exports: make(map[string][]macho.Symbol)}
	defined := make(map[string]uint64) // name -> target
	namesAt := make(map[uint64][]string)
	define := func(owner sectionRange, name string, target uint64) {
		if existing, ok := defined[name]; ok {
			if existing != target {
				log.Warnf("synthesized name %s used for %#x and %#x", name, existing, target)
			}
			return
		}
		defined[name] = target
		namesAt[target] = append(namesAt[target], name)
		result.exports[owner.entry] = append(result.exports[owner.entry], macho.Symbol{
			Name: name, Type: types.N_SECT | types.N_EXT, Sect: owner.index, Value: target,
		})
	}
	// Known names (e.g. from `ipsw kernel symbolicate`) become symbols of the
	// image defining their address. Kernel names are exported (kmutil only
	// exposes those listed in the KPI symbol sets). KEXT names are exported
	// unless another image defines the same name: such duplicates are
	// usually file-local helpers that would otherwise satisfy other images'
	// imports, so they stay local.
	knownOwners := make(map[string]map[string]bool)
	knownAddrs := make([]uint64, 0, len(known))
	knownNames := 0
	for addr, names := range known {
		owner, ok := lookup(addr)
		if !ok {
			continue
		}
		for _, name := range names {
			if knownOwners[name] == nil {
				knownOwners[name] = make(map[string]bool)
			}
			knownOwners[name][owner.entry] = true
		}
		knownAddrs = append(knownAddrs, addr)
	}
	sort.Slice(knownAddrs, func(i, j int) bool { return knownAddrs[i] < knownAddrs[j] })
	knownLocal := 0
	// The kernel's first text address is where extractions put symbol-set
	// alias targets without a known address. A symbol map made from such an
	// extraction (BinDiff against an extracted KDK) carries these
	// placeholders along; they must not hide the real targets.
	var textStart uint64
	if text := kernel.Section("__TEXT_EXEC", "__text"); text != nil {
		textStart = text.Addr
	}
	for _, addr := range knownAddrs {
		owner, _ := lookup(addr)
		for _, name := range known[addr] {
			if name == "" || name == "_kmod_info" {
				continue
			}
			if _, isReserved := reserved[name]; isReserved && addr == textStart {
				continue
			}
			knownNames++
			if owner.entry != kernelID && len(knownOwners[name]) > 1 {
				result.exports[owner.entry] = append(result.exports[owner.entry], macho.Symbol{
					Name: name, Type: types.N_SECT, Sect: owner.index, Value: addr,
				})
				knownLocal++
				continue
			}
			define(owner, name, addr)
		}
	}
	if len(known) > 0 {
		log.Infof("Using %d known symbol names (%d kept local as duplicates)", knownNames, knownLocal)
	}
	// knownImportName returns the known name of target if importer can bind it.
	knownImportName := func(importer string, owner sectionRange, target uint64) string {
		for _, name := range known[target] {
			if addr, ok := defined[name]; !ok || addr != target {
				continue
			}
			if owner.entry != kernelID {
				return name
			}
			for _, dep := range deps[importer] {
				if slices.Contains(setNames[dep], name) {
					return name
				}
				if dep == "com.apple.kpi.private" {
					for _, prefix := range privatePrefixes {
						if strings.HasPrefix(name, prefix) {
							return name
						}
					}
				}
			}
		}
		return ""
	}
	knownImports, synthesizedImports := 0, 0

	// Placeholder names of an earlier extraction (carried over by
	// symbolicating with an extracted KDK) are kept: they identify the
	// functions other extractions import by them. A position-derived name
	// clashing with one of them gets a suffix instead.
	uniqueName := func(name string, target uint64) string {
		candidate := name
		for i := 1; ; i++ {
			if addr, ok := defined[candidate]; !ok || addr == target {
				return candidate
			}
			candidate = fmt.Sprintf("%s.%d", name, i)
		}
	}
	nextName := make(map[string]int) // KPI -> next unused index
	unresolved := 0
	for _, n := range needs {
		owner, _ := lookup(n.target)
		name := knownImportName(n.entry, owner, n.target)
		if name != "" {
			knownImports++
		} else if owner.entry != kernelID {
			name = uniqueName("_kc."+owner.entry+"."+positionName(owner, n.target), n.target)
			if !slices.Contains(deps[n.entry], owner.entry) {
				log.Debugf("%s references %s but does not depend on it", n.entry, owner.entry)
			}
		} else {
			visible := make(map[string]bool)
			for _, dep := range deps[n.entry] {
				visible[dep] = true
			}
			if visible["com.apple.kpi.private"] && privatePrefix != "" {
				name = uniqueName(privatePrefix+"_kc."+positionName(owner, n.target), n.target)
			} else {
				// Reuse a placeholder already standing for this address if
				// this KEXT can see it, otherwise take an unused one.
				for _, candidate := range namesAt[n.target] {
					for _, dep := range deps[n.entry] {
						if slices.Contains(setNames[dep], candidate) {
							name = candidate
						}
					}
				}
				for _, dep := range deps[n.entry] {
					for name == "" && nextName[dep] < len(setNames[dep]) {
						candidate := setNames[dep][nextName[dep]]
						nextName[dep]++
						if _, used := defined[candidate]; used {
							continue
						}
						if _, isReserved := reserved[candidate]; isReserved {
							continue
						}
						if vtablePatchingName(candidate) {
							continue
						}
						name = candidate
					}
				}
			}
		}
		if name != "" && !slices.Contains(known[n.target], name) {
			synthesizedImports++
		}
		if name == "" {
			unresolved++
			log.Warnf("no exportable kernel symbol name left for %s -> %#x", n.entry, n.target)
			continue
		}
		if addr, ok := defined[name]; ok && addr != n.target {
			return nil, fmt.Errorf("import %s of %s would bind %#x instead of %#x", name, n.entry, addr, n.target)
		}
		define(owner, name, n.target)
		result.imports[n.entry] = append(result.imports[n.entry], macho.Symbol{
			Name: name, Type: types.N_UNDF | types.N_EXT, Value: n.target,
		})
	}

	// Symbol-set aliases must resolve to kernel globals. kmutil binds an
	// alias name (e.g. _IOLockLock) to its target (_lck_mtx_lock), so a
	// target without a known address takes the address of a known alias
	// name. Only targets nobody can reach get an arbitrary address.
	if text := kernel.Section("__TEXT_EXEC", "__text"); text != nil {
		owner, _ := lookup(text.Addr)
		for _, name := range slices.Sorted(maps.Keys(reserved)) {
			isAliasTarget := false
			var aliasAddr uint64
			for _, set := range sets.SymbolsSets {
				for _, sym := range set.Symbols {
					if sym.AliasTarget != name {
						continue
					}
					isAliasTarget = true
					if addr, ok := defined[sym.SymbolName]; ok && aliasAddr == 0 {
						if o, _ := lookup(addr); o.entry == kernelID {
							aliasAddr = addr
						}
					}
				}
			}
			if addr, ok := defined[name]; ok {
				if o, _ := lookup(addr); o.entry == kernelID {
					continue // defined by the kernel from the symbol map
				}
			}
			if aliasAddr != 0 {
				o, _ := lookup(aliasAddr)
				if _, elsewhere := defined[name]; elsewhere {
					result.exports[kernelID] = append(result.exports[kernelID], macho.Symbol{
						Name: name, Type: types.N_SECT | types.N_EXT, Sect: o.index, Value: aliasAddr,
					})
				} else {
					define(o, name, aliasAddr)
				}
				continue
			}
			if isAliasTarget || name == sets.WeakRefFallbackSymbol.SymbolName {
				if _, elsewhere := defined[name]; elsewhere {
					// A KEXT defines the name too; the kernel still needs it.
					result.exports[kernelID] = append(result.exports[kernelID], macho.Symbol{
						Name: name, Type: types.N_SECT | types.N_EXT, Sect: owner.index, Value: text.Addr,
					})
					continue
				}
				define(owner, name, text.Addr)
			}
		}
	}
	// Every KEXT exports its own _kmod_info; kmutil refuses KEXTs without it.
	for _, info := range infos {
		id, _ := info["CFBundleIdentifier"].(string)
		var addr uint64
		switch v := info["_PrelinkKmodInfo"].(type) {
		case uint64:
			addr = v
		case int64: // kernel addresses are serialized as negative integers
			addr = uint64(v)
		default:
			continue
		}
		if entries[id] == nil {
			continue
		}
		if owner, ok := lookup(addr); ok && owner.entry == id {
			result.exports[id] = append(result.exports[id], macho.Symbol{
				Name: "_kmod_info", Type: types.N_SECT | types.N_EXT, Sect: owner.index, Value: addr,
			})
		}
	}
	// Order by name, not address: the extracted images must not depend on
	// where the collection placed their dependencies.
	for id := range result.exports {
		sort.Slice(result.exports[id], func(i, j int) bool { return result.exports[id][i].Name < result.exports[id][j].Name })
	}
	for id := range result.imports {
		sort.Slice(result.imports[id], func(i, j int) bool { return result.imports[id][i].Name < result.imports[id][j].Name })
	}
	log.Infof("Named %d cross-image references: %d with known names, %d synthesized, %d unresolved", len(needs), knownImports, synthesizedImports, unresolved)
	return result, nil
}

// vtablePatchingName reports names kmutil's C++ vtable patcher interprets
// (vtables and metaclass symbols). A placeholder must not use them, or kmutil
// would patch vtables against an unrelated address.
func vtablePatchingName(name string) bool {
	return strings.HasPrefix(name, "__ZTV") ||
		strings.Contains(name, "10gMetaClassE") ||
		strings.Contains(name, "10superClassE") ||
		strings.Contains(name, "9MetaClassE")
}

// LoadSymbolMap reads an `ipsw kernel symbolicate --json` map (address ->
// name). An address may also map to a list of names, e.g. when KEXTs bind the
// same kernel address under different names.
func LoadSymbolMap(path string) (map[uint64][]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read symbols %s: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse symbols %s: %w", path, err)
	}
	symbols := make(map[uint64][]string, len(raw))
	for key, value := range raw {
		addr, err := strconv.ParseUint(key, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q in %s", key, path)
		}
		var names []string
		if err := json.Unmarshal(value, &names); err != nil {
			var name string
			if err := json.Unmarshal(value, &name); err != nil {
				return nil, fmt.Errorf("invalid name for %s in %s: %s", key, path, value)
			}
			names = []string{name}
		}
		symbols[addr] = names
	}
	return symbols, nil
}
