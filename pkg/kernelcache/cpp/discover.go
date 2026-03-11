package cpp

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

var osMetaClassCtorNames = []string{
	"__ZN11OSMetaClassC2EPKcPKS_j",
	"__ZN11OSMetaClassC1EPKcPKS_j",
	"__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t",
	"__ZN11OSMetaClassC1EPKcPKS_jPP4zoneS1_19zone_create_flags_t",
}

var cxaPureVirtualNames = []string{
	"__cxa_pure_virtual",
	"___cxa_pure_virtual",
}

var osMetaClassSeedNames = []string{
	"IORegistryEntry",
	"IOService",
	"IOUserClient",
}

const (
	errorLogMessage     = "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error)."
	cxaPureVirtualPanic = "__cxa_pure_virtual"
)

func (s *Scanner) resolveAnchors() error {
	files := s.anchorFiles()
	preferredFiles := s.preferredAnchorFiles()

	for _, file := range files {
		s.addCtorVariantsFromFile(file)
		if s.cxaPureVirtual == 0 {
			s.setPureVirtualFromSymbols(file)
		}
		if s.cxaPureVirtual == 0 {
			s.setPureVirtualFromExports(file)
		}
	}

	if s.cxaPureVirtual == 0 {
		s.setPureVirtualFromExports(s.root)
	}
	if len(s.osMetaClassVariants) == 0 {
		if err := s.findAnchorsViaIntersection(preferredFiles); err == nil && len(s.osMetaClassVariants) > 0 {
			s.stats.setAnchorMode(anchorModePreferredFileStringFallback)
		} else if err := s.findAnchorsViaIntersection(files); err == nil && len(s.osMetaClassVariants) > 0 {
			s.stats.setAnchorMode(anchorModeGlobalStringFallback)
		}
	}
	if s.cxaPureVirtual == 0 {
		_ = s.findPureVirtualViaStrings(preferredFiles)
	}
	if s.cxaPureVirtual == 0 {
		_ = s.findPureVirtualViaStrings(files)
	}
	if len(s.osMetaClassVariants) > 0 && s.cxaPureVirtual != 0 {
		if s.stats.anchorMode == anchorModeUnknown {
			s.stats.setAnchorMode(anchorModeSymbolExportSymtab)
		}
		return nil
	}

	if len(s.osMetaClassVariants) == 0 || s.cxaPureVirtual == 0 {
		if err := s.findAnchorsViaLegacyStrings(preferredFiles); err == nil && len(s.osMetaClassVariants) > 0 && s.cxaPureVirtual != 0 {
			s.stats.setAnchorMode(anchorModePreferredFileStringFallback)
		}
	}
	if len(s.osMetaClassVariants) == 0 || s.cxaPureVirtual == 0 {
		if err := s.findAnchorsViaLegacyStrings(files); err == nil && len(s.osMetaClassVariants) > 0 && s.cxaPureVirtual != 0 {
			s.stats.setAnchorMode(anchorModeGlobalStringFallback)
		}
	}
	if len(s.osMetaClassVariants) == 0 {
		return fmt.Errorf("failed to resolve OSMetaClass constructor variants")
	}
	if s.cxaPureVirtual == 0 {
		return fmt.Errorf("failed to resolve __cxa_pure_virtual")
	}
	if s.stats.anchorMode == anchorModeUnknown {
		s.stats.setAnchorMode(anchorModeSymbolExportSymtab)
	}
	return nil
}

func (s *Scanner) addCtorVariantsFromFile(file *macho.File) {
	for _, name := range osMetaClassCtorNames {
		if addr, err := file.FindSymbolAddress(name); err == nil {
			s.osMetaClassVariants[addr] = struct{}{}
		}
		if addr, err := file.FindSymbolAddress(name + ".stub"); err == nil {
			s.osMetaClassVariants[addr] = struct{}{}
		}
	}
	if exports, err := file.DyldExports(); err == nil {
		for _, export := range exports {
			if isOSMetaClassCtorName(export.Name) {
				s.osMetaClassVariants[export.Address] = struct{}{}
			}
		}
	}
	if file.Symtab != nil {
		for _, sym := range file.Symtab.Syms {
			if isOSMetaClassCtorName(sym.Name) {
				s.osMetaClassVariants[sym.Value] = struct{}{}
			}
		}
	}
}

func (s *Scanner) setPureVirtualFromSymbols(file *macho.File) {
	for _, name := range cxaPureVirtualNames {
		if addr, err := file.FindSymbolAddress(name); err == nil {
			s.cxaPureVirtual = addr
			return
		}
	}
}

func (s *Scanner) setPureVirtualFromExports(file *macho.File) {
	if file == nil {
		return
	}
	if exports, err := file.DyldExports(); err == nil {
		for _, export := range exports {
			if strings.Contains(export.Name, "cxa_pure_virtual") {
				s.cxaPureVirtual = export.Address
				return
			}
		}
	}
}

func (s *Scanner) preferredAnchorFiles() []*macho.File {
	files := make([]*macho.File, 0, 2)
	seen := make(map[*macho.File]bool, 2)
	if s.root != nil {
		seen[s.root] = true
		files = append(files, s.root)
	}
	if s.root != nil && s.root.FileHeader.Type == types.MH_FILESET {
		for _, fs := range s.root.FileSets() {
			if normalizeEntryID(fs.EntryID) != kernelBundleName {
				continue
			}
			kernelFile, err := s.root.GetFileSetFileByName(fs.EntryID)
			if err != nil || seen[kernelFile] {
				break
			}
			seen[kernelFile] = true
			files = append(files, kernelFile)
			break
		}
	}
	return files
}

func (s *Scanner) anchorFiles() []*macho.File {
	files := make([]*macho.File, 0, len(s.targets)+1)
	seen := make(map[*macho.File]bool, len(s.targets)+1)
	if s.root.FileHeader.Type == types.MH_FILESET {
		for _, fs := range s.root.FileSets() {
			if normalizeEntryID(fs.EntryID) != kernelBundleName {
				continue
			}
			kernelFile, err := s.root.GetFileSetFileByName(fs.EntryID)
			if err != nil {
				break
			}
			seen[kernelFile] = true
			files = append(files, kernelFile)
			break
		}
	}
	if !seen[s.root] {
		seen[s.root] = true
		files = append(files, s.root)
	}
	for _, target := range s.targets {
		if seen[target.file] {
			continue
		}
		seen[target.file] = true
		files = append(files, target.file)
	}
	return files
}

func (s *Scanner) findAnchorsViaLegacyStrings(files []*macho.File) error {
	var lastErr error
	for _, file := range files {
		if err := s.findAnchorsInFileViaStrings(file); err != nil {
			lastErr = err
			continue
		}
		if len(s.osMetaClassVariants) > 0 && s.cxaPureVirtual != 0 {
			return nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("string-xref anchor fallback did not resolve required anchors")
	}
	return lastErr
}

func (s *Scanner) findAnchorsInFileViaStrings(file *macho.File) error {
	strs, err := file.GetCStrings()
	if err != nil {
		return err
	}

	var errorStrAddr uint64
	var panicStrAddr uint64
	for _, str2addr := range strs {
		for str, addr := range str2addr {
			switch str {
			case errorLogMessage:
				errorStrAddr = addr
			case cxaPureVirtualPanic:
				panicStrAddr = addr
			}
		}
		if errorStrAddr != 0 && panicStrAddr != 0 {
			break
		}
	}
	if errorStrAddr == 0 && panicStrAddr == 0 {
		return fmt.Errorf("required anchor strings not present in file")
	}

	funcs, err := s.functionsForFile(file)
	if err != nil {
		return err
	}
	foundVariant := false
	foundPure := s.cxaPureVirtual != 0
	for _, fn := range funcs {
		if errorStrAddr != 0 {
			if referenced, err := s.functionReferencesAddressNoResolve(file, fn, errorStrAddr); err == nil && referenced {
				s.osMetaClassVariants[fn.StartAddr] = struct{}{}
				foundVariant = true
			}
		}
		if panicStrAddr != 0 && s.cxaPureVirtual == 0 {
			if referenced, err := s.functionReferencesAddressNoResolve(file, fn, panicStrAddr); err == nil && referenced {
				s.cxaPureVirtual = fn.StartAddr
				foundPure = true
			}
		}
	}
	if foundVariant || foundPure {
		return nil
	}
	return fmt.Errorf("no anchor xrefs found in file")
}

func (s *Scanner) findPureVirtualViaStrings(files []*macho.File) error {
	for _, file := range files {
		strs, err := file.GetCStrings()
		if err != nil {
			continue
		}
		var panicStrAddr uint64
		for _, str2addr := range strs {
			for str, addr := range str2addr {
				if str == cxaPureVirtualPanic {
					panicStrAddr = addr
					break
				}
			}
			if panicStrAddr != 0 {
				break
			}
		}
		if panicStrAddr == 0 {
			continue
		}
		funcs, err := s.functionsForFile(file)
		if err != nil {
			continue
		}
		for _, fn := range funcs {
			if referenced, err := s.functionReferencesAddressNoResolve(file, fn, panicStrAddr); err == nil && referenced {
				s.cxaPureVirtual = fn.StartAddr
				return nil
			}
		}
	}
	return fmt.Errorf("no pure virtual anchor xrefs found")
}

func collectSeedStringRefs(files []*macho.File) map[string]uint64Set {
	refs := make(map[string]uint64Set, len(osMetaClassSeedNames))
	for _, name := range osMetaClassSeedNames {
		refs[name] = make(uint64Set)
	}
	for _, file := range files {
		strs, err := file.GetCStrings()
		if err != nil {
			continue
		}
		for _, str2addr := range strs {
			for str, addr := range str2addr {
				if set, ok := refs[str]; ok {
					set[addr] = struct{}{}
				}
			}
		}
	}
	return refs
}

func (s *Scanner) findAnchorsViaIntersection(files []*macho.File) error {
	refsByName := collectSeedStringRefs(files)
	var candidates uint64Set
	for _, name := range osMetaClassSeedNames {
		refs := refsByName[name]
		if len(refs) == 0 {
			return fmt.Errorf("failed to find string: %s", name)
		}
		current := make(uint64Set)
		for _, file := range files {
			s.collectConstructorTargetsForStringRefs(file, refs, candidates, current)
		}
		if len(current) == 0 {
			return fmt.Errorf("no constructor candidates found for %s", name)
		}
		candidates = current
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no common constructor candidates found")
	}
	for addr := range candidates {
		s.osMetaClassVariants[addr] = struct{}{}
	}
	return nil
}

func (s *Scanner) collectConstructorTargetsForStringRefs(file *macho.File, refs uint64Set, prev uint64Set, out uint64Set) {
	for _, sec := range file.Sections {
		if sec == nil || sec.Size < 8 {
			continue
		}
		if sec.Seg != "__TEXT_EXEC" && sec.Seg != "__TEXT" {
			continue
		}
		data, err := s.readSectionData(file, sec)
		if err != nil {
			continue
		}
		targets := collectConstructorTargetsForStringRefs(sec.Addr, data, refs, prev)
		for target := range targets {
			out[target] = struct{}{}
		}
	}
}

func (s *Scanner) discoverAltConstructors(files []*macho.File) error {
	if len(s.osMetaClassVariants) == 0 {
		return nil
	}
	known := func() uint64Set {
		out := make(uint64Set, len(s.osMetaClassVariants))
		for addr := range s.osMetaClassVariants {
			out[addr] = struct{}{}
		}
		return out
	}

	const maxRounds = 8
	changed := true
	for round := 0; changed && round < maxRounds; round++ {
		changed = false
		current := known()
		for _, file := range files {
			funcs, err := s.functionsForFile(file)
			if err != nil {
				continue
			}
			for _, fn := range funcs {
				if s.isOSMetaClassVariant(fn.StartAddr) {
					continue
				}
				data, err := s.functionDataFor(file, fn)
				if err != nil || len(data) == 0 {
					continue
				}
				if !functionCallsAnyAnchor(fn.StartAddr, data, func(addr uint64) bool { return hasUint64Set(current, addr) }) {
					continue
				}
				if _, ok := findPassThroughConstructorTarget(fn.StartAddr, data, current); ok {
					s.osMetaClassVariants[fn.StartAddr] = struct{}{}
					changed = true
				}
			}
		}
	}
	return nil
}

func (s *Scanner) expandBoundedOSMetaClassAliases(files []*macho.File) error {
	if len(s.osMetaClassVariants) == 0 {
		return nil
	}
	refs := make(uint64Set)
	for _, file := range files {
		index := s.buildPointerIndex(file)
		for target := range s.osMetaClassVariants {
			for _, slot := range index[target] {
				refs[slot] = struct{}{}
			}
		}
	}
	if len(refs) == 0 {
		return nil
	}
	for _, file := range files {
		for _, sec := range file.Sections {
			if sec == nil || sec.Size < 12 {
				continue
			}
			if sec.Seg != "__TEXT_EXEC" && sec.Seg != "__TEXT" {
				continue
			}
			data, err := s.readSectionData(file, sec)
			if err != nil {
				continue
			}
			for off := 0; off+12 <= len(data); off += 4 {
				alias := sec.Addr + uint64(off)
				if s.isOSMetaClassVariant(alias) {
					continue
				}
				if _, ok := importStubReferenceTarget(alias, data[off:], refs); ok {
					s.osMetaClassVariants[alias] = struct{}{}
				}
			}
		}
	}
	return nil
}

func (s *Scanner) functionReferencesAddressNoResolve(m *macho.File, fn types.Function, target uint64) (bool, error) {
	data, err := s.functionDataFor(m, fn)
	if err != nil {
		return false, err
	}
	return rawWordReferencesAddress(fn.StartAddr, data, target, nil), nil
}

type rawRefRegState struct {
	adrpBase uint64
	computed uint64
	loadAddr uint64
}

// rawWordReferencesAddress checks whether raw instruction bytes contain
// an address reference to target using stateful ADRP/ADD/LDR tracking.
func rawWordReferencesAddress(start uint64, data []byte, target uint64, resolve func(uint64) (uint64, bool)) bool {
	var regs [31]rawRefRegState
	for offset := 0; offset+4 <= len(data); offset += 4 {
		pc := start + uint64(offset)
		raw := readUint32At(data, offset)
		switch {
		case (raw & 0x9f000000) == 0x90000000: // ADRP Xd, #page
			rd := int(raw & 0x1f)
			if rd < 31 {
				if addr, ok := decodeADRPImmediate(pc, raw); ok {
					regs[rd] = rawRefRegState{adrpBase: addr}
				} else {
					regs[rd] = rawRefRegState{}
				}
			}
		case (raw & 0x9f000000) == 0x10000000: // ADR Xd, #imm
			rd := int(raw & 0x1f)
			if rd < 31 {
				immhi := int64((raw >> 5) & 0x7ffff)
				immlo := int64((raw >> 29) & 0x3)
				imm := (immhi << 2) | immlo
				if imm&(1<<20) != 0 {
					imm |= ^int64((1 << 21) - 1)
				}
				addr := uint64(int64(pc) + imm)
				regs[rd] = rawRefRegState{computed: addr}
				if addr == target {
					return true
				}
			}
		case (raw & 0xff800000) == 0x91000000: // ADD Xd, Xn, #imm12
			rd := int(raw & 0x1f)
			rn := int((raw >> 5) & 0x1f)
			if rn < 31 {
				imm12 := uint64((raw >> 10) & 0xfff)
				if (raw>>22)&1 == 1 {
					imm12 <<= 12
				}
				base := regs[rn].computed
				if base == 0 {
					base = regs[rn].adrpBase
				}
				if rd < 31 {
					regs[rd] = rawRefRegState{}
				}
				if base != 0 {
					addr := base + imm12
					if rd < 31 {
						regs[rd] = rawRefRegState{computed: addr}
					}
					if addr == target {
						return true
					}
				}
			}
		case (raw & 0xffc00000) == 0xf9400000: // LDR Xt, [Xn, #uimm]
			rt := int(raw & 0x1f)
			rn := int((raw >> 5) & 0x1f)
			if rn < 31 {
				imm12 := uint64((raw>>10)&0xfff) * 8
				base := regs[rn].computed
				if base == 0 {
					base = regs[rn].adrpBase
				}
				if rt < 31 {
					regs[rt] = rawRefRegState{}
				}
				if base != 0 {
					loadAddr := base + imm12
					if rt < 31 {
						regs[rt] = rawRefRegState{loadAddr: loadAddr}
					}
					if resolve != nil {
						if ptr, ok := resolve(loadAddr); ok && ptr == target {
							return true
						}
					}
				}
			}
		case (raw & 0xff000000) == 0x58000000,
			(raw & 0xff000000) == 0x18000000: // literal LDR
			rt := int(raw & 0x1f)
			imm19 := int64((raw >> 5) & 0x7ffff)
			if imm19&(1<<18) != 0 {
				imm19 |= ^int64((1 << 19) - 1)
			}
			loadAddr := uint64(int64(pc) + (imm19 << 2))
			if rt < 31 {
				regs[rt] = rawRefRegState{loadAddr: loadAddr}
			}
			if resolve != nil {
				if ptr, ok := resolve(loadAddr); ok && ptr == target {
					return true
				}
			}
		case (raw >> 26) == 0b100101: // BL
			if dest, ok := decodeBLTarget(pc, raw); ok && dest == target {
				return true
			}
		case (raw >> 26) == 0b000101: // B
			if dest, ok := decodeBTarget(pc, raw); ok && dest == target {
				return true
			}
		case (raw & 0xffe0ffe0) == 0xaa0003e0: // MOV Xd, Xm
			rd := int(raw & 0x1f)
			rm := int((raw >> 16) & 0x1f)
			if rd < 31 {
				if rm < 31 {
					regs[rd] = regs[rm]
				} else {
					regs[rd] = rawRefRegState{}
				}
			}
		case (raw & 0xff800000) == 0xd2800000: // MOVZ
			rd := int(raw & 0x1f)
			if rd < 31 {
				regs[rd] = rawRefRegState{}
			}
		}
	}
	return false
}

func isOSMetaClassCtorName(name string) bool {
	name = strings.TrimPrefix(name, "_")
	return strings.Contains(name, "OSMetaClassC1") || strings.Contains(name, "OSMetaClassC2") || strings.Contains(name, "OSMetaClass::OSMetaClass")
}

func (s *Scanner) isOSMetaClassVariant(addr uint64) bool {
	_, ok := s.osMetaClassVariants[addr]
	return ok
}

func (s *Scanner) collectCtorCandidates(target scanTarget) ([]ctorPath, error) {
	modInit, err := s.collectModInitCtors(target)
	if err != nil {
		return nil, err
	}

	// In MH_FILESET the kernel entry's function list includes
	// infrastructure code (OSMetaClass impl, thunks) that calls
	// OSMetaClass::OSMetaClass for non-kernel classes. Skip the
	// direct-caller scan for the kernel entry; __mod_init_func
	// is authoritative.
	var direct []ctorPath
	if !(target.entryID == kernelBundleName && s.root.FileHeader.Type == types.MH_FILESET) {
		direct, err = s.collectDirectCallers(target)
		if err != nil {
			return nil, err
		}
	}

	out := make([]ctorPath, 0, len(modInit)+len(direct))
	seen := make(map[fileAddrKey]bool, len(modInit)+len(direct))
	for _, path := range modInit {
		key := fileAddrKey{file: path.owner, addr: path.fn.StartAddr}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, path)
	}
	for _, path := range direct {
		key := fileAddrKey{file: path.owner, addr: path.fn.StartAddr}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, path)
	}
	return out, nil
}

func (s *Scanner) collectDirectCallers(target scanTarget) ([]ctorPath, error) {
	funcs, err := s.functionsForFile(target.file)
	if err != nil {
		return nil, nil
	}

	out := make([]ctorPath, 0, len(funcs)/8)
	for _, fn := range funcs {
		data, err := s.functionDataFor(target.file, fn)
		if err != nil || len(data) < 4 {
			continue
		}
		if functionCallsAnyAnchor(fn.StartAddr, data, s.isOSMetaClassVariant) {
			out = append(out, ctorPath{fn: fn, owner: target.file, entryID: target.entryID})
		}
	}
	return out, nil
}

func functionCallsAnyAnchor(start uint64, data []byte, isAnchor func(uint64) bool) bool {
	for offset := 0; offset+4 <= len(data); offset += 4 {
		pc := start + uint64(offset)
		raw := readUint32At(data, offset)
		if target, ok := decodeBLTarget(pc, raw); ok && isAnchor(target) {
			return true
		}
		if target, ok := decodeBTarget(pc, raw); ok && isAnchor(target) {
			return true
		}
	}
	return false
}

func (s *Scanner) collectModInitCtors(target scanTarget) ([]ctorPath, error) {
	ptrs, err := s.modInitPointers(target.file)
	if err != nil {
		return nil, nil
	}

	out := make([]ctorPath, 0, len(ptrs))
	seen := make(map[fileAddrKey]bool, len(ptrs))
	for _, ptr := range ptrs {
		path, ok, err := s.resolveWrapperChain(target.file, target.entryID, ptr)
		if err != nil || !ok {
			continue
		}
		if startFn, _, err := s.functionForAddrInAnyFile(target.file, ptr); err == nil && startFn.StartAddr != path.fn.StartAddr {
			if ctx, ok := s.simulateWrapperContext(target.file, ptr, path.fn.StartAddr); ok {
				path.preload = ctx
			}
			if wrapperContextEmpty(path.preload) {
				if ctx, ok := s.recoverStaticWrapperContext(target.file, ptr, path.fn.StartAddr); ok && !wrapperContextEmpty(ctx) {
					path.preload = ctx
				}
			}
		}
		key := fileAddrKey{file: path.owner, addr: path.fn.StartAddr}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, path)
	}
	return out, nil
}

func (s *Scanner) modInitPointers(m *macho.File) ([]uint64, error) {
	var sec *types.Section
	if sec = m.Section("__DATA_CONST", "__mod_init_func"); sec == nil {
		sec = m.Section("__DATA", "__mod_init_func")
	}
	if sec == nil {
		return nil, fmt.Errorf("no __mod_init_func section")
	}

	data, err := s.readSectionData(m, sec)
	if err != nil {
		return nil, err
	}

	ptrs := make([]uint64, 0, len(data)/8)
	for offset := 0; offset+8 <= len(data); offset += 8 {
		addr := sec.Addr + uint64(offset)
		ptr, ok := s.fallbackPointerAt(m, addr)
		if !ok || ptr == 0 {
			continue
		}
		ptrs = append(ptrs, ptr)
	}
	return ptrs, nil
}

type wrapperInspection struct {
	direct      bool
	nextTargets []uint64
}

func (s *Scanner) resolveWrapperChain(startFile *macho.File, startEntry string, addr uint64) (ctorPath, bool, error) {
	type queueItem struct {
		file  *macho.File
		entry string
		addr  uint64
		depth int
	}
	queue := []queueItem{{file: startFile, entry: startEntry, addr: addr, depth: 0}}
	visited := make(map[fileAddrKey]bool, s.cfg.MaxWrapperDepth+1)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		fn, owner, err := s.functionForAddrInAnyFile(current.file, current.addr)
		if err != nil {
			continue
		}
		key := fileAddrKey{file: owner, addr: fn.StartAddr}
		if visited[key] {
			continue
		}
		visited[key] = true

		inspection, err := s.inspectFunction(owner, fn)
		if err != nil {
			continue
		}
		entryID := s.entryForFile(owner)
		if entryID == "" {
			entryID = normalizeEntryID(current.entry)
		}
		if inspection.direct {
			return ctorPath{fn: fn, owner: owner, entryID: entryID}, true, nil
		}

		if current.depth >= s.cfg.MaxWrapperDepth {
			continue
		}
		for _, next := range inspection.nextTargets {
			queue = append(queue, queueItem{file: owner, entry: entryID, addr: next, depth: current.depth + 1})
		}
	}

	return ctorPath{}, false, nil
}

func (s *Scanner) inspectFunction(m *macho.File, fn types.Function) (wrapperInspection, error) {
	data, err := s.functionDataFor(m, fn)
	if err != nil {
		return wrapperInspection{}, err
	}
	return inspectFunctionData(fn.StartAddr, data, s.isOSMetaClassVariant), nil
}

func inspectFunctionData(start uint64, data []byte, isAnchor func(uint64) bool) wrapperInspection {
	nextTargets := make([]uint64, 0, 4)
	lastNonNOP := uint64(0)
	lastTarget := uint64(0)
	for offset := 0; offset+4 <= len(data); offset += 4 {
		pc := start + uint64(offset)
		raw := readUint32At(data, offset)

		if target, ok := decodeBLTarget(pc, raw); ok {
			if isAnchor(target) {
				return wrapperInspection{direct: true}
			}
			if target != 0 && target != start {
				nextTargets = append(nextTargets, target)
				lastTarget = target
			}
		}
		if target, ok := decodeBTarget(pc, raw); ok && target != 0 && target != start {
			nextTargets = append(nextTargets, target)
			lastTarget = target
		}
		if !isArm64Nop(raw) {
			lastNonNOP = pc
		}
	}

	if len(nextTargets) == 0 && lastNonNOP != 0 && lastTarget != 0 {
		nextTargets = append(nextTargets, lastTarget)
	}

	slices.Sort(nextTargets)
	nextTargets = slices.Compact(nextTargets)
	return wrapperInspection{nextTargets: nextTargets}
}
