package iokit

import "fmt"

type dispatchEntry struct {
	function             uint64
	scalarInputCount     uint32
	structInputSize      uint32
	scalarOutputCount    uint32
	structOutputSize     uint32
	flags                int64
	checkEntitlementAddr uint64
	checkEntitlement     string
}

func (a *analyzer) dispatchRecords(info *classInfo, analysis methodAnalysis) ([]Record, error) {
	if analysis.kind == DispatchExternalMethod2022 && analysis.stride != dispatchSize2022 {
		return nil, fmt.Errorf("IOExternalMethodDispatch2022 layout mismatch: stride=%d assumed=%d class=%s", analysis.stride, dispatchSize2022, info.Name)
	}
	if analysis.note == "bounds_unknown" || analysis.count <= 0 {
		return []Record{a.unresolvedMethodRecord(info, analysis, -1, "bounds_unknown")}, nil
	}
	if analysis.note == "conditional_array" {
		records := make([]Record, 0, analysis.count)
		for selector := 0; selector < analysis.count; selector++ {
			records = append(records, a.unresolvedMethodRecord(info, analysis, selector, "conditional_array"))
		}
		return records, nil
	}
	records := make([]Record, 0, analysis.count)
	for selector := 0; selector < analysis.count; selector++ {
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
		records = append(records, rec)
	}
	return records, nil
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
		records = append(records, Record{
			Kind:              KindMethod,
			Class:             info.Name,
			Bundle:            info.Bundle,
			Selector:          selector,
			MethodAddr:        "0x0",
			MethodSymbol:      "",
			DispatchKind:      DispatchSwitch,
			ScalarInputCount:  -1,
			ScalarOutputCount: -1,
			StructInputSize:   -1,
			StructOutputSize:  -1,
			Flags:             -1,
			Resolved:          false,
			Extra:             map[string]string{"slice_notes": "switch"},
		})
	}
	return records
}
