package dyld

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/xref"
)

// ImportedSymbolNamesForImage returns imported symbol names for a cache image.
// It prefers Mach-O bind metadata and falls back to resolving stub pointer
// targets, which covers chained-cache images that no longer carry LC_DYLD_INFO.
func ImportedSymbolNamesForImage(image *CacheImage) ([]string, error) {
	if image == nil {
		return nil, fmt.Errorf("nil cache image")
	}
	var bindErr error
	if m, err := image.GetPartialMacho(); err == nil {
		if imports, err := m.ImportedSymbolNames(); err == nil {
			return imports, nil
		} else {
			bindErr = err
		}
	} else {
		bindErr = err
	}
	imports, err := importedSymbolNamesFromResolvedStubs(image)
	if err != nil {
		if bindErr != nil {
			return nil, bindErr
		}
		return nil, err
	}
	if len(imports) == 0 && bindErr != nil {
		return nil, bindErr
	}
	return imports, nil
}

func importedSymbolNamesFromResolvedStubs(image *CacheImage) ([]string, error) {
	if image == nil || image.cache == nil {
		return nil, nil
	}
	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}
	stubSlots := softLinkStubPointerSlots(m)
	resolvedImages := make(map[*CacheImage]struct{})
	seen := make(map[string]struct{})
	for _, slot := range stubSlots {
		ptr, err := image.cache.ReadPointerAtAddress(slot)
		if err != nil || ptr == 0 {
			continue
		}
		target := image.cache.SlideInfo.SlidePointer(ptr)
		name := fallbackImportedSymbolName(softLinkResolvedTargetName(image.cache, target, resolvedImages))
		if name == "" {
			continue
		}
		seen[name] = struct{}{}
	}
	imports := make([]string, 0, len(seen))
	for name := range seen {
		imports = append(imports, name)
	}
	sort.Strings(imports)
	return imports, nil
}

func fallbackImportedSymbolName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "j_")
	return name
}

// SoftLinkConfig controls soft-link global extraction from a DSC image.
type SoftLinkConfig struct {
	Image  string
	Filter string
}

// SoftLinkRecord describes one SOFT_LINK-style global and the nearby helper
// symbols that can be recovered from the image symbol tables.
type SoftLinkRecord struct {
	Image            string `json:"image"`
	Symbol           string `json:"symbol"`
	GlobalAddr       uint64 `json:"global_addr,omitempty"`
	InitFuncAddr     uint64 `json:"init_fn_addr,omitempty"`
	OnceAddr         uint64 `json:"once_addr,omitempty"`
	FrameworkLibAddr uint64 `json:"framework_lib_addr,omitempty"`
	GlobalName       string `json:"global_name,omitempty"`
	InitFuncName     string `json:"init_fn_name,omitempty"`
	OnceName         string `json:"once_name,omitempty"`
	FrameworkLibName string `json:"framework_lib_name,omitempty"`
}

type softLinkSymbol struct {
	Name    string
	Address uint64
}

// SoftLinks returns softLink* globals for an image, with best-effort recovery
// of matching init, once, and framework-library helper symbols when names are
// present in the cache.
func SoftLinks(f *File, config SoftLinkConfig) ([]SoftLinkRecord, error) {
	if f == nil {
		return nil, fmt.Errorf("nil dyld cache")
	}
	if strings.TrimSpace(config.Image) == "" {
		return nil, fmt.Errorf("--image is required")
	}
	filter, err := compileSoftLinkFilter(config.Filter)
	if err != nil {
		return nil, err
	}

	image, err := cacheImageByName(f, config.Image)
	if err != nil {
		return nil, fmt.Errorf("image not in DSC: %w", err)
	}
	symbols := softLinkSymbols(image)
	records := softLinkRecordsFromSymbols(image.Name, symbols)
	if len(records) == 0 || filter != nil {
		if disasmRecords, err := softLinkRecordsFromDisassembly(image); err == nil {
			records = mergeSoftLinkRecords(records, disasmRecords)
		}
	}
	if filter != nil {
		records = filterSoftLinkRecords(records, filter)
	}
	return records, nil
}

func compileSoftLinkFilter(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil
	}
	filter, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid --filter regex %q: %w", pattern, err)
	}
	return filter, nil
}

func softLinkSymbols(image *CacheImage) []softLinkSymbol {
	if image == nil {
		return nil
	}
	_ = image.ParseLocalSymbols(false)
	_ = image.ParsePublicSymbols(false)

	symbols := make([]softLinkSymbol, 0, len(image.LocalSymbols)+len(image.PublicSymbols))
	seen := make(map[string]struct{})
	add := func(name string, addr uint64) {
		display := softLinkDisplayName(name)
		if display == "" {
			return
		}
		key := fmt.Sprintf("%016x:%s", addr, display)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		symbols = append(symbols, softLinkSymbol{Name: display, Address: addr})
	}
	for _, sym := range image.LocalSymbols {
		add(sym.Name, sym.Value)
	}
	for _, sym := range image.PublicSymbols {
		add(sym.Name, sym.Address)
	}
	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].Name == symbols[j].Name {
			return symbols[i].Address < symbols[j].Address
		}
		return symbols[i].Name < symbols[j].Name
	})
	return symbols
}

func softLinkDisplayName(name string) string {
	name = strings.TrimSpace(demangle.Do(name, false, false))
	name = strings.TrimPrefix(name, "_")
	return name
}

func softLinkRecordsFromSymbols(imageName string, symbols []softLinkSymbol) []SoftLinkRecord {
	recordsBySuffix := make(map[string]*SoftLinkRecord)
	var helpers []softLinkSymbol

	for _, sym := range symbols {
		suffix, ok := softLinkGlobalSuffix(sym.Name)
		if !ok {
			helpers = append(helpers, sym)
			continue
		}
		rec := recordsBySuffix[suffix]
		if rec == nil {
			rec = &SoftLinkRecord{
				Image:      imageName,
				Symbol:     suffix,
				GlobalAddr: sym.Address,
				GlobalName: sym.Name,
			}
			recordsBySuffix[suffix] = rec
			continue
		}
		if rec.GlobalAddr == 0 || (sym.Address != 0 && sym.Address < rec.GlobalAddr) {
			rec.GlobalAddr = sym.Address
			rec.GlobalName = sym.Name
		}
	}

	for suffix, rec := range recordsBySuffix {
		for _, helper := range helpers {
			applySoftLinkHelper(rec, helper, suffix)
		}
	}

	records := make([]SoftLinkRecord, 0, len(recordsBySuffix))
	for _, rec := range recordsBySuffix {
		records = append(records, *rec)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Symbol == records[j].Symbol {
			return records[i].GlobalAddr < records[j].GlobalAddr
		}
		return records[i].Symbol < records[j].Symbol
	})
	return records
}

func applySoftLinkHelper(record *SoftLinkRecord, helper softLinkSymbol, suffix string) {
	switch classifySoftLinkHelper(helper.Name, suffix) {
	case "init":
		if shouldReplaceSoftLinkHelper(record.InitFuncAddr, helper.Address) {
			record.InitFuncAddr = helper.Address
			record.InitFuncName = helper.Name
		}
	case "once":
		if shouldReplaceSoftLinkHelper(record.OnceAddr, helper.Address) {
			record.OnceAddr = helper.Address
			record.OnceName = helper.Name
		}
	case "library":
		if shouldReplaceSoftLinkHelper(record.FrameworkLibAddr, helper.Address) {
			record.FrameworkLibAddr = helper.Address
			record.FrameworkLibName = helper.Name
		}
	}
}

func softLinkGlobalSuffix(name string) (string, bool) {
	short := softLinkShortName(name)
	for _, prefix := range []string{"softLink", "softlink"} {
		if strings.HasPrefix(short, prefix) && len(short) > len(prefix) {
			suffix := strings.Trim(short[len(prefix):], "_")
			if suffix != "" && !strings.EqualFold(suffix, "Library") && !strings.HasSuffix(suffix, "Library") {
				return suffix, true
			}
		}
	}
	return "", false
}

func softLinkShortName(name string) string {
	if idx := strings.LastIndex(name, "::"); idx >= 0 {
		name = name[idx+len("::"):]
	}
	name = strings.TrimSuffix(name, "()")
	return strings.TrimSpace(name)
}

func classifySoftLinkHelper(name, suffix string) string {
	short := softLinkShortName(name)
	lowerShort := strings.ToLower(short)
	lowerName := strings.ToLower(name)
	lowerSuffix := strings.ToLower(suffix)
	switch {
	case strings.Contains(lowerShort, "once") && strings.Contains(lowerName, lowerSuffix):
		return "once"
	case strings.HasPrefix(short, "init") && strings.Contains(lowerShort, lowerSuffix):
		return "init"
	case strings.Contains(lowerShort, "library") && softLinkFrameworkMatches(short, suffix):
		return "library"
	default:
		return ""
	}
}

func softLinkFrameworkMatches(helper, suffix string) bool {
	framework := softLinkFrameworkPrefix(suffix)
	if framework == "" {
		return false
	}
	return strings.Contains(strings.ToLower(helper), strings.ToLower(framework))
}

func softLinkFrameworkPrefix(suffix string) string {
	for idx := 1; idx < len(suffix); idx++ {
		if suffix[idx] >= 'A' && suffix[idx] <= 'Z' && suffix[idx-1] >= 'a' && suffix[idx-1] <= 'z' {
			return suffix[:idx]
		}
	}
	return suffix
}

func shouldReplaceSoftLinkHelper(existing, candidate uint64) bool {
	if existing == 0 {
		return candidate != 0
	}
	if candidate == 0 {
		return false
	}
	return candidate < existing
}

func filterSoftLinkRecords(records []SoftLinkRecord, filter *regexp.Regexp) []SoftLinkRecord {
	if filter == nil {
		return records
	}
	out := records[:0]
	for _, record := range records {
		if filter.MatchString(record.Symbol) ||
			filter.MatchString(record.GlobalName) ||
			filter.MatchString(record.InitFuncName) ||
			filter.MatchString(record.OnceName) ||
			filter.MatchString(record.FrameworkLibName) {
			out = append(out, record)
		}
	}
	return out
}

type softLinkCallTargets struct {
	dlsym        xref.TargetSet
	dispatchOnce xref.TargetSet
}

type softLinkFunction struct {
	start  uint64
	end    uint64
	instrs []xref.Instruction
}

type softLinkRegValue struct {
	known    bool
	addr     uint64
	loadAddr uint64
}

func softLinkRecordsFromDisassembly(image *CacheImage) ([]SoftLinkRecord, error) {
	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}
	targets, err := softLinkImportedCallTargets(image, m)
	if err != nil || len(targets.dlsym) == 0 {
		return nil, err
	}
	funcs, err := softLinkInstructionFunctions(m)
	if err != nil {
		return nil, err
	}
	return softLinkRecordsFromInstructionFunctions(
		image.Name,
		funcs,
		targets,
		image.cache.GetCString,
		image.cache.ReadPointerAtAddress,
	), nil
}

func softLinkImportedCallTargets(image *CacheImage, m *macho.File) (softLinkCallTargets, error) {
	targets := softLinkCallTargets{
		dlsym:        xref.NewTargetSet(),
		dispatchOnce: xref.NewTargetSet(),
	}
	stubSlots := softLinkStubPointerSlots(m)
	var bindErr error
	if binds, err := m.GetBindInfo(); err == nil {
		bindSlots := make(map[uint64]string)
		for _, bind := range binds {
			name := strings.TrimPrefix(bind.Name, "_")
			switch name {
			case "dlsym", "dispatch_once":
				bindSlots[bind.Start+bind.SegOffset] = name
			}
		}
		softLinkAddTargetsFromBindSlots(targets, stubSlots, bindSlots)
	} else {
		bindErr = err
	}
	softLinkAddTargetsFromResolvedStubs(image, targets, stubSlots)
	if len(targets.dlsym) == 0 && len(targets.dispatchOnce) == 0 && bindErr != nil {
		return targets, bindErr
	}
	return targets, nil
}

func softLinkStubPointerSlots(m *macho.File) map[uint64]uint64 {
	stubSlots := make(map[uint64]uint64)
	for _, sec := range m.Sections {
		if sec == nil || sec.Size == 0 || !sec.Flags.IsSymbolStubs() {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		maps.Copy(stubSlots, xref.StubPointerSlotsFromInstructions(xref.Decode(data, sec.Addr)))
	}
	return stubSlots
}

func softLinkAddTargetsFromBindSlots(targets softLinkCallTargets, stubSlots map[uint64]uint64, bindSlots map[uint64]string) {
	for stub, slot := range stubSlots {
		softLinkAddCallTarget(targets, bindSlots[slot], stub)
	}
}

func softLinkAddTargetsFromResolvedStubs(image *CacheImage, targets softLinkCallTargets, stubSlots map[uint64]uint64) {
	if image == nil || image.cache == nil {
		return
	}
	resolvedImages := make(map[*CacheImage]struct{})
	for stub, slot := range stubSlots {
		ptr, err := image.cache.ReadPointerAtAddress(slot)
		if err != nil || ptr == 0 {
			continue
		}
		target := image.cache.SlideInfo.SlidePointer(ptr)
		name := softLinkResolvedTargetName(image.cache, target, resolvedImages)
		softLinkAddCallTarget(targets, softLinkImportedTargetName(name), stub)
	}
}

func softLinkAddCallTarget(targets softLinkCallTargets, name string, stub uint64) {
	switch name {
	case "dlsym":
		targets.dlsym.Add(stub)
	case "dispatch_once":
		targets.dispatchOnce.Add(stub)
	}
}

func softLinkResolvedTargetName(f *File, target uint64, resolvedImages map[*CacheImage]struct{}) string {
	if name, ok := f.AddressToSymbol.Get(target); ok {
		return name
	}
	img, err := f.GetImageContainingTextAddr(target)
	if err != nil || img == nil {
		return ""
	}
	if _, ok := resolvedImages[img]; !ok {
		_ = img.ParsePublicSymbols(false)
		resolvedImages[img] = struct{}{}
	}
	if name, ok := f.AddressToSymbol.Get(target); ok {
		return name
	}
	return ""
}

func softLinkImportedTargetName(name string) string {
	short := softLinkShortName(softLinkDisplayName(name))
	short = strings.TrimPrefix(short, "j_")
	short = strings.TrimPrefix(short, "_")
	switch short {
	case "dlsym", "dispatch_once":
		return short
	default:
		return ""
	}
}

func softLinkInstructionFunctions(m *macho.File) ([]softLinkFunction, error) {
	sections := softLinkExecutableSections(m)
	if len(sections) == 0 {
		return nil, nil
	}
	funcs := m.GetFunctions()
	if len(funcs) == 0 {
		generated, err := m.GenerateFunctionStarts()
		if err != nil {
			return nil, err
		}
		funcs = generated
	}
	if len(funcs) == 0 {
		return nil, nil
	}
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].StartAddr < funcs[j].StartAddr
	})
	out := make([]softLinkFunction, 0, len(funcs))
	for _, sec := range sections {
		data, err := sec.Data()
		if err != nil {
			continue
		}
		sectionInstrs := xref.Decode(data, sec.Addr)
		for idx, fn := range funcs {
			if fn.StartAddr < sec.Addr || fn.StartAddr >= sec.Addr+sec.Size {
				continue
			}
			end := softLinkFunctionEnd(fn, funcs, idx, sec)
			if end <= fn.StartAddr {
				continue
			}
			startIdx := int((fn.StartAddr - sec.Addr) / 4)
			endIdx := int((end - sec.Addr) / 4)
			if startIdx < 0 || startIdx >= len(sectionInstrs) || endIdx <= startIdx {
				continue
			}
			if endIdx > len(sectionInstrs) {
				endIdx = len(sectionInstrs)
			}
			out = append(out, softLinkFunction{
				start:  fn.StartAddr,
				end:    end,
				instrs: sectionInstrs[startIdx:endIdx],
			})
		}
	}
	return out, nil
}

func softLinkExecutableSections(m *macho.File) []*mtypes.Section {
	sections := make([]*mtypes.Section, 0, len(m.Sections))
	for _, sec := range m.Sections {
		if sec == nil || sec.Size == 0 {
			continue
		}
		if sec.Flags.IsPureInstructions() || sec.Flags.IsSomeInstructions() || sec.Name == "__text" {
			sections = append(sections, sec)
		}
	}
	return sections
}

func softLinkFunctionEnd(fn mtypes.Function, funcs []mtypes.Function, idx int, sec *mtypes.Section) uint64 {
	sectionEnd := sec.Addr + sec.Size
	end := fn.EndAddr
	if end == 0 || end > sectionEnd {
		end = sectionEnd
		for next := idx + 1; next < len(funcs); next++ {
			if funcs[next].StartAddr > fn.StartAddr && funcs[next].StartAddr <= sectionEnd {
				end = funcs[next].StartAddr
				break
			}
		}
	}
	return end
}

func softLinkRecordsFromInstructionFunctions(
	imageName string,
	funcs []softLinkFunction,
	targets softLinkCallTargets,
	readCString func(uint64) (string, error),
	readPointer func(uint64) (uint64, error),
) []SoftLinkRecord {
	recordsByKey := make(map[string]*SoftLinkRecord)
	recordsByInit := make(map[uint64][]*SoftLinkRecord)
	for _, fn := range funcs {
		for idx := range fn.instrs {
			target, ok := softLinkDirectCallTarget(&fn.instrs[idx].Inst)
			if !ok || !targets.dlsym.Has(target) {
				continue
			}
			record, ok := softLinkRecordFromDlsymCall(imageName, fn, idx, targets, readCString, readPointer)
			if !ok {
				continue
			}
			key := softLinkDisasmRecordKey(record)
			merged := mergeSoftLinkRecord(recordsByKey[key], record)
			recordsByKey[key] = merged
			recordsByInit[merged.InitFuncAddr] = appendSoftLinkRecordPointer(recordsByInit[merged.InitFuncAddr], merged)
		}
	}
	if len(recordsByKey) == 0 {
		return nil
	}
	for _, fn := range funcs {
		for idx := range fn.instrs {
			target, ok := softLinkDirectCallTarget(&fn.instrs[idx].Inst)
			if !ok || !targets.dispatchOnce.Has(target) {
				continue
			}
			state := softLinkStateBefore(fn.instrs, idx, readPointer, 32)
			initAddr := state[1].addr
			if initAddr == 0 {
				continue
			}
			for _, record := range recordsByInit[initAddr] {
				if record.OnceAddr == 0 {
					record.OnceAddr = state[0].addr
				}
			}
		}
	}
	records := make([]SoftLinkRecord, 0, len(recordsByKey))
	for _, record := range recordsByKey {
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Symbol == records[j].Symbol {
			return records[i].InitFuncAddr < records[j].InitFuncAddr
		}
		return records[i].Symbol < records[j].Symbol
	})
	return records
}

func softLinkDisasmRecordKey(record SoftLinkRecord) string {
	if record.GlobalAddr != 0 {
		return fmt.Sprintf("global:%#x", record.GlobalAddr)
	}
	return fmt.Sprintf("%s:%#x", record.Symbol, record.InitFuncAddr)
}

func appendSoftLinkRecordPointer(records []*SoftLinkRecord, record *SoftLinkRecord) []*SoftLinkRecord {
	if slices.Contains(records, record) {
		return records
	}
	return append(records, record)
}

func softLinkRecordFromDlsymCall(
	imageName string,
	fn softLinkFunction,
	callIdx int,
	targets softLinkCallTargets,
	readCString func(uint64) (string, error),
	readPointer func(uint64) (uint64, error),
) (SoftLinkRecord, bool) {
	state := softLinkStateBefore(fn.instrs, callIdx, readPointer, 64)
	symbolAddr := state[1].addr
	if symbolAddr == 0 {
		return SoftLinkRecord{}, false
	}
	symbol, err := readCString(symbolAddr)
	if err != nil || !validSoftLinkDlsymSymbol(symbol) {
		return SoftLinkRecord{}, false
	}
	record := SoftLinkRecord{
		Image:        imageName,
		Symbol:       strings.TrimPrefix(symbol, "_"),
		InitFuncAddr: fn.start,
	}
	if globalAddr, ok := softLinkStoreAfterCall(fn.instrs, callIdx, readPointer); ok {
		record.GlobalAddr = globalAddr
	}
	if state[0].loadAddr != 0 {
		record.FrameworkLibAddr = state[0].loadAddr
	} else if helperAddr := softLinkLastInternalCall(fn.instrs, callIdx, targets); helperAddr != 0 {
		record.FrameworkLibAddr = helperAddr
	}
	return record, true
}

func validSoftLinkDlsymSymbol(symbol string) bool {
	symbol = strings.TrimSpace(symbol)
	if symbol == "" || len(symbol) > 256 {
		return false
	}
	if strings.ContainsAny(symbol, "/ \t\r\n") {
		return false
	}
	return true
}

func softLinkStoreAfterCall(instrs []xref.Instruction, callIdx int, readPointer func(uint64) (uint64, error)) (uint64, bool) {
	var state [31]softLinkRegValue
	var returnRegs [31]bool
	returnRegs[0] = true
	limit := min(callIdx+16, len(instrs)-1)
	for idx := callIdx + 1; idx <= limit; idx++ {
		inst := &instrs[idx].Inst
		if addr, ok := softLinkReturnStoreAddress(inst, state); ok {
			src, srcOK := xref.OperandRegIndex(inst, 0)
			if srcOK && returnRegs[src] {
				return addr, true
			}
		}
		softLinkApplyReturnMove(inst, &returnRegs)
		softLinkApplyInstruction(inst, &state, readPointer)
		if softLinkStopsStoreScan(inst) {
			break
		}
	}
	return 0, false
}

func softLinkReturnStoreAddress(inst *disassemble.Inst, state [31]softLinkRegValue) (uint64, bool) {
	switch inst.Operation {
	case disassemble.ARM64_STR, disassemble.ARM64_STUR:
	default:
		return 0, false
	}
	return softLinkMemoryAddress(inst, 1, state)
}

func softLinkApplyReturnMove(inst *disassemble.Inst, returnRegs *[31]bool) {
	dst, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return
	}
	switch inst.Operation {
	case disassemble.ARM64_MOV:
		src, ok := xref.OperandRegIndex(inst, 1)
		returnRegs[dst] = ok && returnRegs[src]
	case disassemble.ARM64_ORR:
		left, leftOK := xref.OperandReg(inst, 1)
		right, rightOK := xref.OperandRegIndex(inst, 2)
		returnRegs[dst] = leftOK && rightOK && softLinkIsZeroReg(left) && returnRegs[right]
	default:
		if softLinkShouldClearDest(inst) {
			returnRegs[dst] = false
		}
	}
}

func softLinkStopsStoreScan(inst *disassemble.Inst) bool {
	if inst == nil {
		return false
	}
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_BLR,
		disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ,
		disassemble.ARM64_B, disassemble.ARM64_BR,
		disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ,
		disassemble.ARM64_RET, disassemble.ARM64_RETAA, disassemble.ARM64_RETAB:
		return true
	default:
		return false
	}
}

func softLinkLastInternalCall(instrs []xref.Instruction, callIdx int, targets softLinkCallTargets) uint64 {
	for idx := callIdx - 1; idx >= 0 && idx >= callIdx-32; idx-- {
		target, ok := softLinkDirectCallTarget(&instrs[idx].Inst)
		if !ok || target == 0 || targets.dlsym.Has(target) || targets.dispatchOnce.Has(target) {
			continue
		}
		return target
	}
	return 0
}

func softLinkStateBefore(
	instrs []xref.Instruction,
	callIdx int,
	readPointer func(uint64) (uint64, error),
	maxInstructions int,
) [31]softLinkRegValue {
	var state [31]softLinkRegValue
	window := maxInstructions
	if window <= 0 {
		window = 32
	}
	start := max(callIdx-window, 0)
	for idx := start; idx < callIdx; idx++ {
		softLinkApplyInstruction(&instrs[idx].Inst, &state, readPointer)
	}
	return state
}

func softLinkApplyInstruction(
	inst *disassemble.Inst,
	state *[31]softLinkRegValue,
	readPointer func(uint64) (uint64, error),
) {
	switch inst.Operation {
	case disassemble.ARM64_ADR, disassemble.ARM64_ADRP:
		if rd, ok := xref.OperandRegIndex(inst, 0); ok {
			if imm, ok := xref.OperandImm(inst, 1); ok {
				state[rd] = softLinkRegValue{known: true, addr: imm}
			}
		}
	case disassemble.ARM64_ADD:
		softLinkApplyAdd(inst, state)
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		softLinkApplyLoad(inst, state, readPointer)
	case disassemble.ARM64_MOV:
		softLinkApplyMove(inst, state)
	case disassemble.ARM64_MOVZ:
		if rd, ok := xref.OperandRegIndex(inst, 0); ok {
			if imm, ok := xref.OperandImm(inst, 1); ok {
				state[rd] = softLinkRegValue{known: true, addr: imm}
			}
		}
	case disassemble.ARM64_MOVK:
		softLinkApplyMoveKeep(inst, state)
	case disassemble.ARM64_ORR:
		if !softLinkApplyORRMove(inst, state) {
			softLinkClearDest(inst, state)
		}
	default:
		if softLinkIsCall(inst.Operation) {
			for idx := 0; idx <= 17; idx++ {
				state[idx] = softLinkRegValue{}
			}
			return
		}
		if softLinkShouldClearDest(inst) {
			softLinkClearDest(inst, state)
		}
	}
}

func softLinkApplyAdd(inst *disassemble.Inst, state *[31]softLinkRegValue) {
	rd, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return
	}
	rn, ok := xref.OperandRegIndex(inst, 1)
	if !ok || !state[rn].known {
		state[rd] = softLinkRegValue{}
		return
	}
	imm, ok := xref.OperandImm(inst, 2)
	if !ok {
		state[rd] = softLinkRegValue{}
		return
	}
	state[rd] = softLinkRegValue{known: true, addr: state[rn].addr + imm}
}

func softLinkApplyLoad(
	inst *disassemble.Inst,
	state *[31]softLinkRegValue,
	readPointer func(uint64) (uint64, error),
) {
	rd, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return
	}
	addr, ok := softLinkMemoryAddress(inst, 1, *state)
	if !ok {
		state[rd] = softLinkRegValue{}
		return
	}
	value := softLinkRegValue{loadAddr: addr}
	if readPointer != nil {
		if ptr, err := readPointer(addr); err == nil && ptr != 0 {
			value.known = true
			value.addr = ptr
		}
	}
	state[rd] = value
}

func softLinkApplyMove(inst *disassemble.Inst, state *[31]softLinkRegValue) {
	rd, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return
	}
	if rn, ok := xref.OperandRegIndex(inst, 1); ok {
		state[rd] = state[rn]
		return
	}
	if imm, ok := xref.OperandImm(inst, 1); ok {
		state[rd] = softLinkRegValue{known: true, addr: imm}
		return
	}
	state[rd] = softLinkRegValue{}
}

func softLinkApplyMoveKeep(inst *disassemble.Inst, state *[31]softLinkRegValue) {
	rd, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return
	}
	imm, ok := xref.OperandImm(inst, 1)
	if !ok || !state[rd].known {
		state[rd] = softLinkRegValue{}
		return
	}
	shift := uint64(0)
	if inst.NumOps > 1 && inst.Operands[1].ShiftValueUsed {
		shift = uint64(inst.Operands[1].ShiftValue)
	}
	mask := uint64(0xffff) << shift
	state[rd].addr = (state[rd].addr &^ mask) | ((imm << shift) & mask)
}

func softLinkApplyORRMove(inst *disassemble.Inst, state *[31]softLinkRegValue) bool {
	rd, ok := xref.OperandRegIndex(inst, 0)
	if !ok {
		return false
	}
	left, leftOK := xref.OperandReg(inst, 1)
	right, rightOK := xref.OperandRegIndex(inst, 2)
	if leftOK && rightOK && softLinkIsZeroReg(left) {
		state[rd] = state[right]
		return true
	}
	return false
}

func softLinkMemoryAddress(inst *disassemble.Inst, operand int, state [31]softLinkRegValue) (uint64, bool) {
	if target, ok := xref.LabelTarget(inst); ok {
		return target, true
	}
	baseReg, ok := xref.OperandRegIndex(inst, operand)
	if !ok || !state[baseReg].known {
		return 0, false
	}
	offset, ok := xref.MemoryOffset(inst, operand)
	if !ok {
		return 0, false
	}
	return state[baseReg].addr + offset, true
}

func softLinkClearDest(inst *disassemble.Inst, state *[31]softLinkRegValue) {
	if rd, ok := xref.OperandRegIndex(inst, 0); ok {
		state[rd] = softLinkRegValue{}
	}
}

func softLinkDirectCallTarget(inst *disassemble.Inst) (uint64, bool) {
	switch inst.Operation {
	case disassemble.ARM64_BL, disassemble.ARM64_B:
		return xref.LabelTarget(inst)
	default:
		return 0, false
	}
}

func softLinkIsCall(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_BL, disassemble.ARM64_BLR,
		disassemble.ARM64_BLRAA, disassemble.ARM64_BLRAAZ,
		disassemble.ARM64_BLRAB, disassemble.ARM64_BLRABZ:
		return true
	default:
		return false
	}
}

func softLinkShouldClearDest(inst *disassemble.Inst) bool {
	if inst == nil || inst.NumOps == 0 {
		return false
	}
	if _, ok := xref.OperandRegIndex(inst, 0); !ok {
		return false
	}
	op := strings.ToLower(inst.Operation.String())
	if strings.HasPrefix(op, "st") || strings.HasPrefix(op, "b.") || op == "b" || op == "br" || op == "ret" {
		return false
	}
	return true
}

func softLinkIsZeroReg(reg disassemble.Register) bool {
	return reg == disassemble.REG_XZR || reg == disassemble.REG_WZR
}

func mergeSoftLinkRecords(existing, extra []SoftLinkRecord) []SoftLinkRecord {
	bySymbol := make(map[string]*SoftLinkRecord)
	byGlobal := make(map[uint64]*SoftLinkRecord)
	for _, record := range existing {
		copy := record
		bySymbol[copy.Symbol] = &copy
		if copy.GlobalAddr != 0 {
			byGlobal[copy.GlobalAddr] = &copy
		}
	}
	for _, record := range extra {
		if record.GlobalAddr != 0 {
			if existing := byGlobal[record.GlobalAddr]; existing != nil {
				mergeSoftLinkRecord(existing, record)
				continue
			}
		}
		merged := mergeSoftLinkRecord(bySymbol[record.Symbol], record)
		bySymbol[merged.Symbol] = merged
		if merged.GlobalAddr != 0 {
			byGlobal[merged.GlobalAddr] = merged
		}
	}
	records := make([]SoftLinkRecord, 0, len(bySymbol))
	for _, record := range bySymbol {
		records = append(records, *record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Symbol == records[j].Symbol {
			return records[i].GlobalAddr < records[j].GlobalAddr
		}
		return records[i].Symbol < records[j].Symbol
	})
	return records
}

func mergeSoftLinkRecord(existing *SoftLinkRecord, extra SoftLinkRecord) *SoftLinkRecord {
	if existing == nil {
		copy := extra
		return &copy
	}
	if existing.Image == "" {
		existing.Image = extra.Image
	}
	if existing.GlobalAddr == 0 {
		existing.GlobalAddr = extra.GlobalAddr
	}
	if existing.InitFuncAddr == 0 {
		existing.InitFuncAddr = extra.InitFuncAddr
	}
	if existing.OnceAddr == 0 {
		existing.OnceAddr = extra.OnceAddr
	}
	if existing.FrameworkLibAddr == 0 {
		existing.FrameworkLibAddr = extra.FrameworkLibAddr
	}
	if existing.GlobalName == "" {
		existing.GlobalName = extra.GlobalName
	}
	if existing.InitFuncName == "" {
		existing.InitFuncName = extra.InitFuncName
	}
	if existing.OnceName == "" {
		existing.OnceName = extra.OnceName
	}
	if existing.FrameworkLibName == "" {
		existing.FrameworkLibName = extra.FrameworkLibName
	}
	return existing
}
