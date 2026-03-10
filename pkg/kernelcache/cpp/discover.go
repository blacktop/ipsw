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

const (
	errorLogMessage     = "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error)."
	cxaPureVirtualPanic = "__cxa_pure_virtual"
)

func (s *Scanner) resolveAnchors() error {
	files := s.anchorFiles()

	for _, file := range files {
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
		if s.cxaPureVirtual == 0 {
			for _, name := range cxaPureVirtualNames {
				if addr, err := file.FindSymbolAddress(name); err == nil {
					s.cxaPureVirtual = addr
					break
				}
			}
		}
		if s.cxaPureVirtual == 0 {
			if exports, err := file.DyldExports(); err == nil {
				for _, export := range exports {
					if strings.Contains(export.Name, "cxa_pure_virtual") {
						s.cxaPureVirtual = export.Address
						break
					}
				}
			}
		}
	}

	if s.cxaPureVirtual == 0 {
		if exports, err := s.root.DyldExports(); err == nil {
			for _, export := range exports {
				if strings.Contains(export.Name, "cxa_pure_virtual") {
					s.cxaPureVirtual = export.Address
					break
				}
			}
		}
	}
	if len(s.osMetaClassVariants) == 0 || s.cxaPureVirtual == 0 {
		if err := s.findAnchorsViaPreferredFiles(); err != nil {
			if len(s.osMetaClassVariants) == 0 || s.cxaPureVirtual == 0 {
				err = s.findAnchorsViaStrings()
			}
			if len(s.osMetaClassVariants) == 0 {
				return err
			}
		}
	}

	if len(s.osMetaClassVariants) == 0 {
		return fmt.Errorf("failed to resolve OSMetaClass constructor variants")
	}
	return nil
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

func (s *Scanner) findAnchorsViaPreferredFiles() error {
	for _, file := range s.anchorFiles() {
		if err := s.findAnchorsInFileViaStrings(file); err == nil && len(s.osMetaClassVariants) > 0 && s.cxaPureVirtual != 0 {
			if expandErr := s.expandOSMetaClassWrappers([]*macho.File{file}); expandErr == nil {
				return nil
			}
			return nil
		}
	}
	return fmt.Errorf("preferred stripped-cache anchor scan did not resolve required anchors")
}

func (s *Scanner) findAnchorsViaStrings() error {
	files := s.anchorFiles()
	for _, file := range files {
		if err := s.findAnchorsInFileViaStrings(file); err != nil {
			continue
		}
		if len(s.osMetaClassVariants) > 0 && s.cxaPureVirtual != 0 {
			_ = s.expandOSMetaClassWrappers(files)
			return nil
		}
	}
	return fmt.Errorf("string-xref anchor fallback did not resolve required anchors")
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
			if referenced, err := s.functionReferencesAddress(file, fn, errorStrAddr); err == nil && referenced {
				s.osMetaClassVariants[fn.StartAddr] = struct{}{}
				foundVariant = true
			}
		}
		if panicStrAddr != 0 && s.cxaPureVirtual == 0 {
			if referenced, err := s.functionReferencesAddress(file, fn, panicStrAddr); err == nil && referenced {
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

func (s *Scanner) expandOSMetaClassWrappers(files []*macho.File) error {
	if len(s.osMetaClassVariants) == 0 {
		return nil
	}
	changed := true
	for changed {
		changed = false
		for _, file := range files {
			funcs, err := s.functionsForFile(file)
			if err != nil {
				return err
			}
			for _, fn := range funcs {
				if s.isOSMetaClassVariant(fn.StartAddr) {
					continue
				}
				data, err := s.functionDataFor(file, fn)
				if err != nil {
					continue
				}
				inspection := inspectFunctionData(fn.StartAddr, data, s.isOSMetaClassVariant)
				if inspection.direct {
					s.osMetaClassVariants[fn.StartAddr] = struct{}{}
					changed = true
					continue
				}
				if len(inspection.nextTargets) == 1 && s.isOSMetaClassVariant(inspection.nextTargets[0]) {
					s.osMetaClassVariants[fn.StartAddr] = struct{}{}
					changed = true
				}
			}
		}
	}
	return nil
}

func (s *Scanner) functionReferencesAddress(m *macho.File, fn types.Function, target uint64) (bool, error) {
	data, err := s.functionDataFor(m, fn)
	if err != nil {
		return false, err
	}
	return rawWordReferencesAddress(fn.StartAddr, data, target, func(addr uint64) (uint64, bool) {
		return s.resolvePointerAt(m, addr)
	}), nil
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
	direct, err := s.collectDirectCallers(target)
	if err != nil {
		return nil, err
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
		var ptr uint64
		if s.root.FileHeader.Type == types.MH_FILESET {
			ptr, err = s.root.GetPointerAtAddress(addr)
		} else {
			ptr, err = m.GetPointerAtAddress(addr)
		}
		if err != nil || ptr == 0 {
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
