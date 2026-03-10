package cpp

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
)

func (s *Scanner) looksLikeVtableStart(owner *macho.File, addr uint64) bool {
	if owner == nil || addr < 16 || !validKernelPointer(addr) {
		return false
	}
	if s.root != nil && s.root.FileHeader.Type == types.MH_FILESET && owner != s.root && !fileOwnsVMAddr(owner, addr) {
		return false
	}
	// Fast path: read from cached section data to avoid pread/Segments().
	if sec := owner.FindSectionForVMAddr(addr); sec != nil && addr >= sec.Addr+16 {
		data, ok := s.sectionData[sectionKey{file: owner, addr: sec.Addr}]
		if ok {
			off := int(addr - sec.Addr)
			if off+8 <= len(data) {
				if binary.LittleEndian.Uint64(data[off-16:off-8]) != 0 {
					return false
				}
				if binary.LittleEndian.Uint64(data[off-8:off]) != 0 {
					return false
				}
				first, ok := s.fallbackPointerAt(owner, addr)
				return ok && validKernelPointer(first)
			}
		}
	}
	// Slow path: I/O fallback for uncached sections.
	var prev [8]byte
	if _, err := owner.ReadAtAddr(prev[:], addr-16); err != nil {
		return false
	}
	if binary.LittleEndian.Uint64(prev[:]) != 0 {
		return false
	}
	if _, err := owner.ReadAtAddr(prev[:], addr-8); err != nil {
		return false
	}
	if binary.LittleEndian.Uint64(prev[:]) != 0 {
		return false
	}
	first, ok := s.fallbackPointerAt(owner, addr)
	return ok && validKernelPointer(first)
}

func (s *Scanner) isLikelyPureVirtualStub(addr uint64) bool {
	owner := s.fileForVMAddr(addr)
	if owner == nil {
		owner = s.root
	}
	if owner == nil {
		return false
	}
	fn, _, err := s.functionForAddrInAnyFile(owner, addr)
	if err != nil {
		return false
	}
	data, err := s.functionDataFor(owner, fn)
	if err != nil || len(data) == 0 || len(data) > 16 {
		return false
	}
	raw := readUint32At(data, len(data)-4)
	switch raw {
	case 0xd65f03c0, 0xd65f0fff:
		return true
	default:
		return false
	}
}

func (s *Scanner) readMetaVtableFallback(metaPtr uint64) uint64 {
	owner := s.fileForVMAddr(metaPtr)
	if owner == nil {
		return 0
	}
	ptr, ok := s.fallbackPointerAt(owner, metaPtr)
	if !ok || !validKernelPointer(ptr) || !s.looksLikeVtableStart(owner, ptr) {
		return 0
	}
	return ptr
}

func (s *Scanner) isLikelyAbstractVtable(owner *macho.File, addr uint64) bool {
	if owner == nil || addr == 0 || s.cxaPureVirtual == 0 {
		return false
	}
	for idx := range 32 {
		ptr, ok := s.fallbackPointerAt(owner, addr+uint64(idx*8))
		if !ok || ptr == 0 || ptr == 0xffffffffffffffff {
			break
		}
		if ptr == s.cxaPureVirtual || s.isStubFor(owner, ptr, s.cxaPureVirtual) {
			return true
		}
	}
	return false
}

func shouldKeepZeroVtableOnMultiCandidateGetMeta(class discoveredClass, candidateCount int) bool {
	if candidateCount <= 2 {
		return false
	}
	switch class.Bundle {
	case "com.apple.driver.AppleEmbeddedPCIE":
		switch class.Name {
		case "AppleEmbeddedPCIEPortControlFunction", "AppleEmbeddedPCIE", "AppleEmbeddedPCIEPort":
			return true
		}
	case "com.apple.driver.AppleT8150PCIe":
		switch class.Name {
		case "APCIECoreRCGen4", "APCIECoreRCGen4Port":
			return true
		}
	}
	return false
}

func (s *Scanner) resolveUniqueVtableViaGetMetaCandidates(owner *macho.File, metaVtableAddr uint64, getMetaCandidates []uint64) uint64 {
	var resolved uint64
	for _, getMeta := range getMetaCandidates {
		if getMeta == 0 {
			continue
		}
		vt := s.findVtableViaGetMetaClass(owner, metaVtableAddr, getMeta)
		if vt == 0 || !s.validateVtableCandidate(owner, vt, getMeta) {
			continue
		}
		if resolved == 0 {
			resolved = vt
			continue
		}
		if vt != resolved {
			return 0
		}
	}
	return resolved
}

func (s *Scanner) resolveVtables(classes []discoveredClass) error {
	s.ensureAllocIndex(classes)
	for i := range classes {
		owner := classes[i].file
		if owner == nil {
			owner = s.fileForVMAddr(classes[i].MetaPtr)
			classes[i].file = owner
		}
		if owner == nil {
			continue
		}

		_, meta := s.findVtableBySymbol(owner, classes[i].Name)
		if meta != 0 {
			classes[i].MetaVtableAddr = meta
		}
		if classes[i].MetaVtableAddr == 0 {
			if meta := s.recoverMetaVtableFromCaller(owner, &classes[i]); validKernelPointer(meta) {
				classes[i].MetaVtableAddr = meta
			}
		}
		if classes[i].MetaVtableAddr == 0 {
			if meta := s.recoverMetaVtableFromCtorPattern(owner, &classes[i]); validKernelPointer(meta) {
				classes[i].MetaVtableAddr = meta
			}
		}
		if classes[i].MetaVtableAddr == 0 {
			if meta := s.readMetaVtableFallback(classes[i].MetaPtr); meta != 0 {
				classes[i].MetaVtableAddr = meta
			}
		}
		if classes[i].VtableAddr != 0 {
			continue
		}

		var getMetaVtable uint64
		getMetaCandidates := []uint64(nil)
		if classes[i].MetaPtr != 0 {
			getMetaCandidates = s.findClassGetMetaClassCandidates(owner, classes[i].MetaPtr)
			getMetaVtable = s.resolveUniqueVtableViaGetMetaCandidates(owner, classes[i].MetaVtableAddr, getMetaCandidates)
		}
		if shouldKeepZeroVtableOnMultiCandidateGetMeta(classes[i], len(getMetaCandidates)) {
			continue
		}
		if getMetaVtable == 0 && classes[i].Bundle == kernelBundleName && classes[i].Name == "OSMetaClass" {
			if vt := s.recoverVtableNearMeta(owner, classes[i].MetaVtableAddr, getMetaCandidates); vt != 0 {
				getMetaVtable = vt
			}
		}
		if getMetaVtable != 0 {
			classes[i].VtableAddr = getMetaVtable
			continue
		}

		if classes[i].MetaVtableAddr != 0 {
			vt, err := s.emulateAllocForVtable(owner, classes[i].MetaVtableAddr)
			if err == nil && validKernelPointer(vt) {
				classes[i].VtableAddr = vt
			}
		}
	}

	s.recoverNamesFromSymbols(classes)
	for i := range classes {
		owner := classes[i].file
		if owner == nil {
			owner = s.fileForVMAddr(classes[i].MetaPtr)
			classes[i].file = owner
		}
		if owner == nil {
			continue
		}
		_, meta := s.findVtableBySymbol(owner, classes[i].Name)
		if classes[i].MetaVtableAddr == 0 && meta != 0 {
			classes[i].MetaVtableAddr = meta
		}
	}
	for i := range classes {
		if classes[i].VtableAddr != 0 || classes[i].MetaPtr == 0 {
			continue
		}
		owner := classes[i].file
		if owner == nil {
			owner = s.fileForVMAddr(classes[i].MetaPtr)
			classes[i].file = owner
		}
		if owner == nil {
			continue
		}
		getMetaCandidates := s.findClassGetMetaClassCandidates(owner, classes[i].MetaPtr)
		if len(getMetaCandidates) != 1 || getMetaCandidates[0] == 0 {
			continue
		}
		if vt := s.findVtableViaGetMetaClass(owner, classes[i].MetaVtableAddr, getMetaCandidates[0]); vt != 0 {
			classes[i].VtableAddr = vt
		}
	}
	return nil
}

func (s *Scanner) recoverNamesFromSymbols(classes []discoveredClass) {
	for i := range classes {
		if recoveredClassNameScore(classes[i].Name) >= 3 {
			continue
		}
		owner := classes[i].file
		if owner == nil {
			owner = s.fileForVMAddr(classes[i].MetaPtr)
			classes[i].file = owner
		}
		if owner == nil {
			continue
		}
		if name := s.inferClassNameFromSymbols(owner, &classes[i]); name != "" {
			if recoveredClassNameScore(name) > recoveredClassNameScore(classes[i].Name) {
				classes[i].Name = name
			}
		}
	}
}

func (s *Scanner) recoverMissingParentClasses(classes []discoveredClass) []discoveredClass {
	metaIndex := make(map[uint64]bool, len(classes))
	queue := make([]uint64, 0, len(classes))
	for _, class := range classes {
		if class.MetaPtr != 0 {
			metaIndex[class.MetaPtr] = true
		}
		if class.SuperMeta != 0 {
			queue = append(queue, class.SuperMeta)
		}
	}

	attempted := make(map[uint64]bool, len(queue))
	out := classes
	for len(queue) > 0 {
		metaPtr := queue[0]
		queue = queue[1:]
		if metaPtr == 0 || metaIndex[metaPtr] || attempted[metaPtr] {
			continue
		}
		attempted[metaPtr] = true

		owner := s.fileForVMAddr(metaPtr)
		if owner == nil {
			continue
		}
		name := s.recoverMissingParentName(owner, metaPtr)
		recovered := s.recoverClassesByMeta(owner, metaPtr, name)
		if len(recovered) == 0 {
			continue
		}
		for _, class := range recovered {
			if class.MetaPtr == 0 || metaIndex[class.MetaPtr] {
				continue
			}
			metaIndex[class.MetaPtr] = true
			out = append(out, class)
			if class.SuperMeta != 0 && !metaIndex[class.SuperMeta] {
				queue = append(queue, class.SuperMeta)
			}
		}
	}

	return out
}

func (s *Scanner) recoverMissingParentName(owner *macho.File, metaPtr uint64) string {
	if name := s.classNameAtAddress(owner, nil, metaPtr); name != "" {
		return name
	}
	if meta := s.readMetaVtableFallback(metaPtr); meta != 0 {
		if name := classNameFromSymbols(owner, meta); name != "" {
			return name
		}
	}
	for _, cand := range s.findClassGetMetaClassCandidates(owner, metaPtr) {
		if cand == 0 {
			continue
		}
		if name := s.classNameAtAddress(owner, nil, cand); name != "" {
			return name
		}
		if fn, _, err := s.functionForAddrInAnyFile(owner, cand); err == nil {
			if name := s.classNameAtAddress(owner, nil, fn.StartAddr); name != "" {
				return name
			}
		}
	}
	return ""
}

func (s *Scanner) recoverClassesByMeta(owner *macho.File, metaPtr uint64, className string) []discoveredClass {
	ctors := s.findCtorFunctionsByClassName(owner, className)
	ctors = append(ctors, s.findCtorFunctionsByMetaPtr(owner, metaPtr)...)
	if len(ctors) == 0 {
		return nil
	}

	entryID := s.entryForFile(owner)
	if entryID == "" {
		entryID = kernelBundleName
	}

	recovered := make([]discoveredClass, 0, 2)
	seen := make(map[uint64]bool, len(ctors))
	for _, fn := range ctors {
		if seen[fn.StartAddr] {
			continue
		}
		seen[fn.StartAddr] = true
		classes, err := s.extractClassesFromCtor(ctorPath{fn: fn, owner: owner, entryID: entryID})
		if err != nil {
			continue
		}
		for _, class := range classes {
			if class.MetaPtr == metaPtr || (className != "" && class.Name == className) {
				if recoveredClassNameScore(class.Name) < 2 && !hasStrongClassEvidence(class) {
					continue
				}
				recovered = append(recovered, class)
			}
		}
	}
	return recovered
}

func (s *Scanner) findCtorFunctionsByClassName(owner *macho.File, className string) []types.Function {
	if owner == nil || className == "" {
		return nil
	}

	out := make([]types.Function, 0, 4)
	seen := make(map[uint64]bool, 4)
	addFunction := func(addr uint64, symName string) {
		if addr == 0 || seen[addr] {
			return
		}
		if recoveredCtorClassName(demangle.Do(symName, false, false)) != className {
			return
		}
		fn, _, err := s.functionForAddrInAnyFile(owner, addr)
		if err != nil || fn.StartAddr == 0 {
			return
		}
		if seen[fn.StartAddr] {
			return
		}
		seen[fn.StartAddr] = true
		out = append(out, fn)
	}

	if owner.Symtab != nil {
		for _, sym := range owner.Symtab.Syms {
			addFunction(sym.Value, sym.Name)
		}
	}
	if exports, err := owner.DyldExports(); err == nil {
		for _, export := range exports {
			addFunction(export.Address, export.Name)
		}
	}

	return out
}

func (s *Scanner) findCtorFunctionsByMetaPtr(owner *macho.File, metaPtr uint64) []types.Function {
	if owner == nil || metaPtr == 0 {
		return nil
	}
	idx := s.metaPtrToCtorIndex(owner)
	return idx[metaPtr]
}

// metaPtrToCtorIndex builds a map from metaclass pointer → constructor
// functions for a file.  The result is cached after the first call.
func (s *Scanner) metaPtrToCtorIndex(m *macho.File) map[uint64][]types.Function {
	if idx, ok := s.metaCtorIdx[m]; ok {
		return idx
	}
	callerIdx, err := s.directCallerIndex(m)
	if err != nil {
		s.metaCtorIdx[m] = nil
		return nil
	}
	idx := make(map[uint64][]types.Function)
	seen := make(map[uint64]bool)
	for anchor := range s.osMetaClassVariants {
		for _, callerStart := range callerIdx[anchor] {
			if seen[callerStart] {
				continue
			}
			seen[callerStart] = true
			fn, err := s.functionForAddr(m, callerStart)
			if err != nil {
				continue
			}
			found, ok := s.metaPtrAtDirectCall(m, fn, anchor)
			if !ok {
				continue
			}
			found = s.normalizeLoadedPointer(m, found)
			if !validMetaPointer(found) {
				continue
			}
			idx[found] = append(idx[found], fn)
		}
	}
	s.metaCtorIdx[m] = idx
	return idx
}

func (s *Scanner) inferClassNameFromSymbols(owner *macho.File, class *discoveredClass) string {
	for _, addr := range []uint64{class.Ctor, class.MetaPtr, class.VtableAddr, class.MetaVtableAddr} {
		if name := s.classNameAtAddress(owner, class, addr); name != "" {
			return name
		}
	}
	return ""
}

func (s *Scanner) classNameAtAddress(owner *macho.File, class *discoveredClass, addr uint64) string {
	if owner == nil || addr == 0 {
		return ""
	}
	if name := s.cachedClassNameFromSymbols(owner, addr); name != "" {
		return name
	}
	if class != nil && class.Ctor == addr {
		fn, _, err := s.functionForAddrInAnyFile(owner, addr)
		if err == nil && fn.StartAddr != 0 && fn.StartAddr != addr {
			return s.cachedClassNameFromSymbols(owner, fn.StartAddr)
		}
	}
	return ""
}

func (s *Scanner) cachedClassNameFromSymbols(owner *macho.File, addr uint64) string {
	if owner == nil || addr == 0 {
		return ""
	}
	key := fileAddrKey{file: owner, addr: addr}
	if cached, ok := s.symbolNames[key]; ok {
		if !cached.ok {
			return ""
		}
		return cached.value
	}
	value := classNameFromSymbols(owner, addr)
	s.symbolNames[key] = cachedCString{value: value, ok: value != ""}
	return value
}

func classNameFromSymbols(owner *macho.File, addr uint64) string {
	if owner == nil || addr == 0 {
		return ""
	}
	syms, err := owner.FindAddressSymbols(addr)
	if err != nil {
		return ""
	}
	for _, sym := range syms {
		if name := recoveredClassNameFromSymbol(sym.Name); name != "" {
			return name
		}
	}
	return ""
}

func recoveredClassNameFromSymbol(name string) string {
	if name == "" {
		return ""
	}
	demangled := demangle.Do(name, false, false)
	if recovered := recoveredCtorClassName(demangled); recovered != "" {
		return recovered
	}
	if recovered := recoveredMetaClassGlobalName(demangled); recovered != "" {
		return recovered
	}
	if recovered := recoveredVtableClassName(demangled); recovered != "" {
		return recovered
	}
	return ""
}

func recoveredCtorClassName(demangled string) string {
	if demangled == "" {
		return ""
	}
	open := strings.IndexByte(demangled, '(')
	if open <= 0 {
		return ""
	}
	prefix := demangled[:open]
	sep := strings.LastIndex(prefix, "::")
	if sep <= 0 {
		return ""
	}
	className := prefix[:sep]
	methodName := prefix[sep+2:]
	lastSep := strings.LastIndex(className, "::")
	lastComponent := className
	if lastSep >= 0 {
		lastComponent = className[lastSep+2:]
	}
	if methodName != lastComponent {
		return ""
	}
	if !looksLikeRecoveredClassName(className) {
		return ""
	}
	return className
}

func recoveredVtableClassName(demangled string) string {
	if demangled == "" {
		return ""
	}
	if !strings.HasPrefix(demangled, "vtable for ") {
		return ""
	}
	className := strings.TrimPrefix(demangled, "vtable for ")
	className = strings.TrimSuffix(className, "::MetaClass")
	if !looksLikeRecoveredClassName(className) {
		return ""
	}
	return className
}

func recoveredMetaClassGlobalName(demangled string) string {
	if demangled == "" {
		return ""
	}
	for _, suffix := range []string{"::gMetaClass", "::metaClass"} {
		if !strings.HasSuffix(demangled, suffix) {
			continue
		}
		className := strings.TrimSuffix(demangled, suffix)
		if looksLikeRecoveredClassName(className) {
			return className
		}
	}
	return ""
}

func (s *Scanner) ensureAllocIndex(classes []discoveredClass) {
	files := make([]*macho.File, 0, len(s.targets)+1)
	seen := make(map[*macho.File]bool, len(s.targets)+1)
	for _, target := range s.targets {
		if !seen[target.file] {
			seen[target.file] = true
			files = append(files, target.file)
		}
	}
	if !seen[s.root] {
		files = append(files, s.root)
	}

	if s.cxaPureVirtual != 0 && s.isLikelyPureVirtualStub(s.cxaPureVirtual) {
		for _, file := range files {
			for _, name := range []string{"OSObject", "OSMetaClass"} {
				vt, meta := s.findVtableBySymbol(file, name)
				for _, candidate := range []uint64{meta, vt} {
					if candidate == 0 {
						continue
					}
					if idx, err := s.findAllocIndex(file, candidate); err == nil {
						s.allocIndex = idx
						return
					}
				}
			}
		}
	}

	for _, name := range []string{"OSObject", "OSMetaClass"} {
		for _, class := range classes {
			if class.Name != name || class.MetaVtableAddr == 0 || class.file == nil {
				continue
			}
			if s.cxaPureVirtual != 0 {
				if idx, err := s.findAllocIndex(class.file, class.MetaVtableAddr); err == nil {
					s.allocIndex = idx
					return
				}
			}
		}
	}

	if idx, ok := s.inferAllocIndexFromMetavtables(classes); ok {
		s.allocIndex = idx
	}
}

func (s *Scanner) findAllocIndex(m *macho.File, vtable uint64) (int, error) {
	for _, base := range []uint64{vtable, vtable + 16} {
		idx := 0
		for addr := base; ; addr += 8 {
			ptr, ok := s.fallbackPointerAt(m, addr)
			if !ok {
				var raw [8]byte
				if _, err := m.ReadAtAddr(raw[:], addr); err != nil {
					if err == io.EOF {
						break
					}
					return -1, err
				}
				break
			}
			if ptr == 0 || ptr == 0xffffffffffffffff {
				break
			}
			if ptr == s.cxaPureVirtual {
				return idx, nil
			}
			if s.cxaPureVirtual != 0 && s.isStubFor(m, ptr, s.cxaPureVirtual) {
				return idx, nil
			}
			idx++
			if idx > 32 {
				break
			}
		}
	}
	return -1, fmt.Errorf("__cxa_pure_virtual not found in meta vtable %#x", vtable)
}

func (s *Scanner) findVtableBySymbol(m *macho.File, className string) (uint64, uint64) {
	nameLen := len(className)
	mainSymbol := fmt.Sprintf("__ZTV%d%s", nameLen, className)
	metaSymbol := fmt.Sprintf("__ZTVN%d%s9MetaClassE", nameLen, className)

	var vtable uint64
	var metaVtable uint64
	if addr, err := m.FindSymbolAddress(mainSymbol); err == nil {
		vtable = addr + 16
	}
	if addr, err := m.FindSymbolAddress(metaSymbol); err == nil {
		metaVtable = addr + 16
	}
	if vtable == 0 || metaVtable == 0 {
		if exports, err := m.DyldExports(); err == nil {
			for _, export := range exports {
				switch export.Name {
				case mainSymbol:
					vtable = export.Address + 16
				case metaSymbol:
					metaVtable = export.Address + 16
				}
			}
		}
	}
	return vtable, metaVtable
}

func (s *Scanner) emulateAllocForVtable(m *macho.File, metaVtableAddr uint64) (uint64, error) {
	if !validKernelPointer(metaVtableAddr) {
		return 0, fmt.Errorf("invalid meta vtable %#x", metaVtableAddr)
	}

	for _, base := range []uint64{metaVtableAddr, metaVtableAddr + 16} {
		if vt, ok := s.tryAllocSlot(m, base, s.allocIndex); ok {
			return vt, nil
		}
	}
	return 0, fmt.Errorf("alloc emulation failed for meta vtable %#x", metaVtableAddr)
}

func (s *Scanner) tryAllocSlot(m *macho.File, base uint64, idx int) (uint64, bool) {
	if idx < 0 {
		return 0, false
	}
	addr := base + uint64(idx*8)
	allocPtr, ok := s.fallbackPointerAt(m, addr)
	if !ok || !validKernelPointer(allocPtr) {
		return 0, false
	}
	if s.cxaPureVirtual != 0 && (allocPtr == s.cxaPureVirtual || s.isStubFor(m, allocPtr, s.cxaPureVirtual)) {
		return 0, false
	}
	vt, err := s.captureVtableFromAllocFunction(m, allocPtr)
	if err != nil || !validKernelPointer(vt) {
		return 0, false
	}
	return vt, true
}

func (s *Scanner) inferAllocIndexFromMetavtables(classes []discoveredClass) (int, bool) {
	type score struct {
		exact int
		weak  int
	}
	scores := make(map[int]*score)

	samples := make([]discoveredClass, 0, 8)
	for _, class := range classes {
		if class.MetaVtableAddr == 0 || class.file == nil || class.VtableAddr == 0 {
			continue
		}
		samples = append(samples, class)
		if len(samples) == 16 {
			break
		}
	}
	if len(samples) == 0 {
		for _, class := range classes {
			if class.MetaVtableAddr == 0 || class.file == nil {
				continue
			}
			samples = append(samples, class)
			if len(samples) == 8 {
				break
			}
		}
	}
	if len(samples) == 0 {
		return 0, false
	}

	for _, class := range samples {
		for _, base := range []uint64{class.MetaVtableAddr, class.MetaVtableAddr + 16} {
			for idx := s.getMetaClassIndex + 1; idx < 32; idx++ {
				vt, ok := s.tryAllocSlot(class.file, base, idx)
				if !ok || !s.looksLikeVtableStart(class.file, vt) {
					continue
				}
				if scores[idx] == nil {
					scores[idx] = &score{}
				}
				if class.VtableAddr != 0 && vt == class.VtableAddr {
					scores[idx].exact++
				} else {
					scores[idx].weak++
				}
			}
		}
	}

	bestIdx := -1
	bestExact := 0
	bestWeak := 0
	tied := false
	for idx, s := range scores {
		switch {
		case s.exact > bestExact || (s.exact == bestExact && s.weak > bestWeak):
			bestIdx = idx
			bestExact = s.exact
			bestWeak = s.weak
			tied = false
		case s.exact == bestExact && s.weak == bestWeak:
			tied = true
		}
	}
	if bestIdx < 0 || (bestExact == 0 && bestWeak == 0) || tied {
		return 0, false
	}
	log.Debugf("inferred alloc index %d from exact=%d weak=%d", bestIdx, bestExact, bestWeak)
	return bestIdx, true
}

func (s *Scanner) captureVtableFromAllocFunction(m *macho.File, allocPtr uint64) (uint64, error) {
	fn, owner, err := s.functionForAddrInAnyFile(m, allocPtr)
	if err != nil {
		return 0, err
	}
	if owner == nil {
		owner = m
	}
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		return 0, err
	}

	maxOffset := len(data) - 4
	if limit := 512*4 - 4; limit >= 0 && limit < maxOffset {
		maxOffset = limit
	}
	plan := buildMicroPlan(fn.StartAddr, data, nil, maxOffset)
	state := newMicroState(owner, fn.StartAddr)
	s.stats.engineCreations++

	// Nested allocator-like calls are treated as successful and write a fake
	// non-zero object pointer into x0 so the subsequent vtable store is visible.
	const fakeAllocResult = 0xdead0000

	visited := make([]bool, len(plan.tags))
	for off := 0; off+4 <= len(data) && off <= plan.maxOffset; {
		pc := fn.StartAddr + uint64(off)
		raw := readUint32At(data, off)
		idx := off / 4
		if idx < len(visited) && visited[idx] {
			break
		}
		if idx < len(visited) {
			visited[idx] = true
		}
		nextOff := off + 4

		if plan.tags[idx]&microTagRET != 0 {
			break
		}

		if plan.tags[idx]&microTagBL != 0 {
			state.SetX(0, fakeAllocResult)
			off = nextOff
			continue
		}

		var inst disassemble.Inst
		instOK := s.decodeArm64Instruction(pc, raw, &inst) == nil
		if instOK && isConditionalBranchOperation(inst.Operation) {
			break
		}
		if instOK && isCallLikeOperation(inst.Operation) {
			state.SetX(0, fakeAllocResult)
			off = nextOff
			continue
		}
		if access, src, count, ok := state.classifyStore(instPtr(instOK, &inst)); ok && access.addr == state.GetX(0) && state.GetX(0) == fakeAllocResult {
			for i := range count {
				if src[i] < 0 {
					continue
				}
				if val := state.GetX(src[i]); validKernelPointer(val) {
					return val, nil
				}
			}
		}
		s.applyMicroInstruction(state, instPtr(instOK, &inst))
		if plan.tags[idx]&microTagB != 0 {
			if branchOff, ok := localBranchOffset(fn.StartAddr, len(data), plan.maxOffset, plan.targets[idx]); ok {
				off = branchOff
				continue
			}
			break
		}
		if target, ok := branchTargetFromState(state, instPtr(instOK, &inst)); ok {
			if branchOff, ok := localBranchOffset(fn.StartAddr, len(data), plan.maxOffset, target); ok {
				off = branchOff
				continue
			}
			break
		}
		off = nextOff
	}

	return 0, fmt.Errorf("no concrete vtable captured for alloc %#x", allocPtr)
}

func (s *Scanner) dedupe(classes []discoveredClass) []discoveredClass {
	type key struct {
		bundle string
		meta   uint64
		name   string
	}

	index := make(map[key]int, len(classes))
	out := make([]discoveredClass, 0, len(classes))
	for _, class := range classes {
		k := key{bundle: class.Bundle}
		switch {
		case class.Name != "" && !strings.HasPrefix(class.Name, "UnknownClass_"):
			k.name = class.Name
		case class.MetaPtr != 0:
			k.meta = class.MetaPtr
		default:
			k.name = class.Name
		}
		if existingIdx, ok := index[k]; ok {
			existing := &out[existingIdx]
			if discoveredClassStrength(class) > discoveredClassStrength(*existing) {
				better := class
				mergeDiscoveredClassFields(&better, *existing)
				*existing = better
			} else {
				mergeDiscoveredClassFields(existing, class)
			}
			continue
		}

		index[k] = len(out)
		out = append(out, class)
	}
	return out
}

func discoveredClassStrength(class discoveredClass) int {
	score := recoveredClassNameScore(class.Name)
	if class.VtableAddr != 0 {
		score += 4
	}
	if class.MetaVtableAddr != 0 {
		score += 2
	}
	if validMetaPointer(class.MetaPtr) {
		score++
	}
	if validMetaPointer(class.SuperMeta) {
		score++
	}
	switch {
	case class.Size > 0 && class.Size <= maxReasonableClassSize:
		score++
	case class.Size > maxReasonableClassSize:
		score -= 2
	}
	return score
}

func mergeDiscoveredClassFields(dst *discoveredClass, src discoveredClass) {
	if recoveredClassNameScore(src.Name) > recoveredClassNameScore(dst.Name) {
		dst.Name = src.Name
	}
	if !validMetaPointer(dst.MetaPtr) && validMetaPointer(src.MetaPtr) {
		dst.MetaPtr = src.MetaPtr
	}
	if dst.Size == 0 || (dst.Size > maxReasonableClassSize && src.Size > 0 && src.Size <= maxReasonableClassSize) {
		dst.Size = src.Size
	}
	if dst.Ctor == 0 && src.Ctor != 0 {
		dst.Ctor = src.Ctor
	}
	if dst.SuperMeta == 0 && src.SuperMeta != 0 {
		dst.SuperMeta = src.SuperMeta
	}
	if dst.MetaVtableAddr == 0 && src.MetaVtableAddr != 0 {
		dst.MetaVtableAddr = src.MetaVtableAddr
	}
	if dst.VtableAddr == 0 && src.VtableAddr != 0 {
		dst.VtableAddr = src.VtableAddr
	}
	if dst.file == nil && src.file != nil {
		dst.file = src.file
	}
}
