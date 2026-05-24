package iokit

import (
	"fmt"
	"sort"
)

type dispatchEntry struct {
	object               uint64
	function             uint64
	adjustor             uint64
	scalarInputCount     uint32
	structInputSize      uint32
	scalarOutputCount    uint32
	structOutputSize     uint32
	flags                int64
	checkEntitlementAddr uint64
	checkEntitlement     string
	count0               uint64
	count1               uint64
}

func (a *analyzer) dispatchRecords(info *classInfo, analysis methodAnalysis) ([]Record, error) {
	if analysis.kind == DispatchExternalMethod2022 && analysis.stride != dispatchSize2022 {
		return nil, fmt.Errorf("IOExternalMethodDispatch2022 layout mismatch: stride=%d assumed=%d class=%s", analysis.stride, dispatchSize2022, info.Name)
	}
	if len(analysis.selectedEntries) > 0 {
		return a.selectedDispatchRecords(info, analysis), nil
	}
	if analysis.note == "bounds_unknown" || analysis.count <= 0 {
		return []Record{a.unresolvedMethodRecord(info, analysis, -1, "bounds_unknown")}, nil
	}
	bases := dispatchTableBases(analysis)
	records := make([]Record, 0, len(bases)*analysis.count)
	for tableIndex, tableBase := range bases {
		tableAnalysis := analysis
		tableAnalysis.arrayBase = tableBase
		if analysis.note == "conditional_array" {
			tableAnalysis.note = ""
		}
		for selector := 0; selector < analysis.count; selector++ {
			rec := a.dispatchRecord(info, tableAnalysis, selector)
			if analysis.note == "conditional_array" {
				addConditionalTableExtra(rec.Extra, tableIndex, tableBase)
			}
			records = append(records, rec)
		}
	}
	return records, nil
}

func (a *analyzer) selectedDispatchRecords(info *classInfo, analysis methodAnalysis) []Record {
	selectors := make([]int, 0, len(analysis.selectedEntries))
	for selector := range analysis.selectedEntries {
		selectors = append(selectors, selector)
	}
	sort.Ints(selectors)
	records := make([]Record, 0, len(selectors))
	for _, selector := range selectors {
		entryAnalysis := analysis
		entryAnalysis.arrayBase = analysis.selectedEntries[selector]
		rec := a.dispatchRecord(info, entryAnalysis, 0)
		rec.Selector = selector
		rec.Extra["slice_notes"] = appendNote(rec.Extra["slice_notes"], "selected_entry")
		records = append(records, rec)
	}
	return records
}

func dispatchTableBases(analysis methodAnalysis) []uint64 {
	if analysis.note == "conditional_array" && len(analysis.arrayBases) > 0 {
		return analysis.arrayBases
	}
	return []uint64{analysis.arrayBase}
}

func addConditionalTableExtra(extra map[string]string, tableIndex int, tableBase uint64) {
	if extra == nil {
		return
	}
	extra["table"] = fmt.Sprintf("table_%d", tableIndex)
	extra["table_base"] = hexAddr(tableBase)
	extra["slice_notes"] = appendNote(extra["slice_notes"], "conditional_array")
}

func (a *analyzer) dispatchRecord(info *classInfo, analysis methodAnalysis, selector int) Record {
	entry, note := a.readDispatchEntry(analysis, selector)
	rec := Record{
		Kind:              KindMethod,
		Class:             info.Name,
		Bundle:            info.Bundle,
		Selector:          selector,
		MethodAddr:        hexAddr(entry.function),
		MethodSymbol:      a.symbolName(entry.function),
		DispatchKind:      analysis.kind,
		ScalarInputCount:  int64(entry.scalarInputCount),
		ScalarOutputCount: int64(entry.scalarOutputCount),
		StructInputSize:   int64(entry.structInputSize),
		StructOutputSize:  int64(entry.structOutputSize),
		Flags:             entry.flags,
		Resolved:          entry.function != 0 && note == "",
		Extra:             map[string]string{},
	}
	if note != "" {
		rec.ScalarInputCount = -1
		rec.ScalarOutputCount = -1
		rec.StructInputSize = -1
		rec.StructOutputSize = -1
		rec.Flags = -1
		rec.Extra["slice_notes"] = note
	}
	if entry.checkEntitlement != "" {
		rec.Extra["check_entitlement"] = entry.checkEntitlement
	} else if entry.checkEntitlementAddr != 0 {
		rec.Extra["check_entitlement_addr"] = hexAddr(entry.checkEntitlementAddr)
	}
	return rec
}

func (a *analyzer) legacyDispatchRecords(info *classInfo, analysis methodAnalysis) ([]Record, error) {
	if analysis.stride != dispatchSizeLegacy {
		return nil, fmt.Errorf("IOExternalMethod layout mismatch: stride=%d assumed=%d class=%s", analysis.stride, dispatchSizeLegacy, info.Name)
	}
	if analysis.note == "bounds_unknown" || analysis.count <= 0 {
		return []Record{a.unresolvedMethodRecord(info, analysis, -1, "bounds_unknown")}, nil
	}
	records := make([]Record, 0, analysis.count)
	for selector := 0; selector < analysis.count; selector++ {
		records = append(records, a.legacyDispatchRecord(info, analysis, selector))
	}
	return records, nil
}

func (a *analyzer) legacyDispatchRecord(info *classInfo, analysis methodAnalysis, selector int) Record {
	entry, note := a.readLegacyDispatchEntry(analysis, selector)
	scalarIn, scalarOut, structIn, structOut, countNote := legacyCountsForFlags(entry.flags, entry.count0, entry.count1)
	note = appendNote(note, countNote)
	rec := Record{
		Kind:              KindMethod,
		Class:             info.Name,
		Bundle:            info.Bundle,
		Selector:          selector,
		MethodAddr:        hexAddr(entry.function),
		MethodSymbol:      a.symbolName(entry.function),
		DispatchKind:      DispatchExternalMethodLegacy,
		ScalarInputCount:  scalarIn,
		ScalarOutputCount: scalarOut,
		StructInputSize:   structIn,
		StructOutputSize:  structOut,
		Flags:             entry.flags,
		Resolved:          entry.function != 0 && note == "",
		Extra:             map[string]string{},
	}
	if entry.object != 0 {
		rec.Extra["target_addr"] = hexAddr(entry.object)
	}
	if entry.adjustor != 0 {
		rec.Extra["method_adjustor"] = hexAddr(entry.adjustor)
	}
	if note != "" {
		rec.ScalarInputCount = -1
		rec.ScalarOutputCount = -1
		rec.StructInputSize = -1
		rec.StructOutputSize = -1
		rec.Flags = -1
		rec.Extra["slice_notes"] = note
	}
	return rec
}

func (a *analyzer) readLegacyDispatchEntry(analysis methodAnalysis, selector int) (dispatchEntry, string) {
	addr := analysis.arrayBase + uint64(selector)*analysis.stride
	entry := dispatchEntry{}
	if object, ok := a.scanner.ReadPointerAt(analysis.owner, addr); ok {
		entry.object = object
	}
	function, ok := a.scanner.ReadPointerAt(analysis.owner, addr+8)
	if !ok {
		if raw, err := a.scanner.ReadUint64At(analysis.owner, addr+8); err == nil {
			function = raw
		}
	}
	if function == 0 {
		return entry, "indirect"
	}
	entry.function = function
	if adjustor, err := a.scanner.ReadUint64At(analysis.owner, addr+16); err == nil {
		entry.adjustor = adjustor
	}
	flags, err := a.scanner.ReadUint32At(analysis.owner, addr+24)
	if err != nil {
		return entry, "indirect"
	}
	entry.flags = int64(flags)
	count0, err := a.scanner.ReadUint64At(analysis.owner, addr+32)
	if err != nil {
		return entry, "indirect"
	}
	entry.count0 = count0
	count1, err := a.scanner.ReadUint64At(analysis.owner, addr+40)
	if err != nil {
		return entry, "indirect"
	}
	entry.count1 = count1
	return entry, ""
}

func legacyCountsForFlags(flags int64, count0, count1 uint64) (int64, int64, int64, int64, string) {
	var scalarIn, scalarOut, structIn, structOut int64
	switch uint32(flags) & 0xf {
	case 0:
		scalarIn = legacyCountToInt64(count0)
		scalarOut = legacyCountToInt64(count1)
	case 2:
		scalarIn = legacyCountToInt64(count0)
		structOut = legacyCountToInt64(count1)
	case 3:
		structIn = legacyCountToInt64(count0)
		structOut = legacyCountToInt64(count1)
	case 4:
		scalarIn = legacyCountToInt64(count0)
		structIn = legacyCountToInt64(count1)
	default:
		return -1, -1, -1, -1, "legacy_flags_unknown"
	}
	if scalarIn < 0 || scalarOut < 0 || structIn < 0 || structOut < 0 {
		return -1, -1, -1, -1, "legacy_count_overflow"
	}
	return scalarIn, scalarOut, structIn, structOut, ""
}

func legacyCountToInt64(count uint64) int64 {
	const maxInt64Uint64 = uint64(1<<63 - 1)
	if count > maxInt64Uint64 {
		return -1
	}
	return int64(count)
}

func (a *analyzer) readDispatchEntry(analysis methodAnalysis, selector int) (dispatchEntry, string) {
	addr := analysis.arrayBase + uint64(selector)*analysis.stride
	function, ok := a.scanner.ReadPointerAt(analysis.owner, addr)
	if !ok || function == 0 {
		return dispatchEntry{}, "indirect"
	}
	scalarIn, err := a.scanner.ReadUint32At(analysis.owner, addr+8)
	if err != nil {
		return dispatchEntry{function: function}, "indirect"
	}
	structIn, err := a.scanner.ReadUint32At(analysis.owner, addr+12)
	if err != nil {
		return dispatchEntry{function: function}, "indirect"
	}
	scalarOut, err := a.scanner.ReadUint32At(analysis.owner, addr+16)
	if err != nil {
		return dispatchEntry{function: function}, "indirect"
	}
	structOut, err := a.scanner.ReadUint32At(analysis.owner, addr+20)
	if err != nil {
		return dispatchEntry{function: function}, "indirect"
	}
	entry := dispatchEntry{
		function:          function,
		scalarInputCount:  scalarIn,
		structInputSize:   structIn,
		scalarOutputCount: scalarOut,
		structOutputSize:  structOut,
		flags:             0,
	}
	if analysis.kind == DispatchExternalMethod2022 {
		flags, err := a.scanner.ReadUint32At(analysis.owner, addr+24)
		if err != nil {
			return entry, "indirect"
		}
		entry.flags = int64(flags & 0xff)
		if entitlement, ok := a.scanner.ReadPointerAt(analysis.owner, addr+32); ok {
			entry.checkEntitlementAddr = entitlement
			if str, err := a.scanner.ReadCStringAt(analysis.owner, entitlement); err == nil && validLiteralString(str) {
				entry.checkEntitlement = str
			}
		}
	}
	return entry, ""
}

func (a *analyzer) unresolvedMethodRecord(info *classInfo, analysis methodAnalysis, selector int, note string) Record {
	return Record{
		Kind:              KindMethod,
		Class:             info.Name,
		Bundle:            info.Bundle,
		Selector:          selector,
		MethodAddr:        "0x0",
		MethodSymbol:      "",
		DispatchKind:      analysis.kind,
		ScalarInputCount:  -1,
		ScalarOutputCount: -1,
		StructInputSize:   -1,
		StructOutputSize:  -1,
		Flags:             -1,
		Resolved:          false,
		Extra:             map[string]string{"slice_notes": note},
	}
}

func (a *analyzer) switchRecords(info *classInfo, analysis methodAnalysis) []Record {
	count := analysis.count
	if count <= 0 || count > maxSelectorCount {
		return []Record{a.unresolvedMethodRecord(info, analysis, -1, "bounds_unknown")}
	}
	records := make([]Record, 0, count)
	for selector := range count {
		extra := map[string]string{"slice_notes": "switch"}
		var methodAddr uint64
		if caseInfo, ok := analysis.switchCases[selector]; ok {
			methodAddr = caseInfo.methodAddr
			if caseInfo.readsStructureInput {
				extra["reads_structure_input"] = "true"
			}
			if caseInfo.readsStructureInputSize {
				extra["reads_structure_input_size"] = "true"
			}
		}
		records = append(records, Record{
			Kind:              KindMethod,
			Class:             info.Name,
			Bundle:            info.Bundle,
			Selector:          selector,
			MethodAddr:        hexAddr(methodAddr),
			MethodSymbol:      a.symbolName(methodAddr),
			DispatchKind:      DispatchSwitch,
			ScalarInputCount:  -1,
			ScalarOutputCount: -1,
			StructInputSize:   -1,
			StructOutputSize:  -1,
			Flags:             -1,
			Resolved:          methodAddr != 0,
			Extra:             extra,
		})
	}
	return records
}
