package xrefs

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/blacktop/ipsw/pkg/xref"
)

const (
	kernelCStringThreshold = 20
	kernelMaxVtableSlots   = 240
)

type kernelScanImage struct {
	name string
	m    *macho.File
}

type kernelDiscovery struct {
	direct         map[uint64][]targetSpec
	virtual        map[int][]targetSpec
	virtualCallers xref.TargetSet
}

type cstringConvergence struct {
	direct       map[uint64][]targetSpec
	virtualSlots map[string]int
}

type convergenceCandidate struct {
	addr  uint64
	slot  int
	count int
}

func kernelFilesetScanImages(root *macho.File, entries []*macho.FilesetEntry, stderr io.Writer) []kernelScanImage {
	images := make([]kernelScanImage, 0, len(entries))
	for _, entry := range entries {
		m, err := root.GetFileSetFileByName(entry.EntryID)
		if err != nil {
			progress(stderr, "kernelcache: failed to parse fileset entry %s: %v\n", entry.EntryID, err)
			continue
		}
		images = append(images, kernelScanImage{name: entry.EntryID, m: m})
	}
	sort.SliceStable(images, func(i, j int) bool {
		return images[i].name < images[j].name
	})
	return images
}

func discoverKernelTargets(root *macho.File, images []kernelScanImage, stderr io.Writer) (map[uint64][]targetSpec, map[int][]targetSpec, xref.TargetSet) {
	out := kernelDiscovery{
		direct:         make(map[uint64][]targetSpec),
		virtual:        make(map[int][]targetSpec),
		virtualCallers: xref.NewTargetSet(),
	}
	scanner, classes := scanKernelCPP(root, stderr)
	if scanner != nil {
		out.virtualCallers = ioUserClientMethodStarts(scanner, classes)
		addNamedVtableTarget(scanner, classes, &out, "IOUserClient::copyClientEntitlement", "copyClientEntitlement", stderr)
		addNamedVtableTarget(scanner, classes, &out, "IOUserClient::clientHasPrivilege", "clientHasPrivilege", stderr)
	}

	cstrings := collectCStringConvergence(images, stderr)
	mergeTargets(out.direct, cstrings.direct)
	if scanner != nil && !virtualHasCanonical(out.virtual, "IOUserClient::copyClientEntitlement") {
		addVtableTargetByCallee(scanner, classes, &out, "IOUserClient::copyClientEntitlement", []string{"IOTaskHasEntitlement", "IOCurrentTaskHasEntitlement"}, stderr)
	}
	for canonical, slot := range cstrings.virtualSlots {
		if virtualHasCanonical(out.virtual, canonical) {
			continue
		}
		if scanner != nil {
			addVtableSlotTarget(scanner, classes, &out, canonical, slot, stderr)
			continue
		}
		if target, ok := kernelTargetByCanonical(canonical, "vtable_slot"); ok {
			target = virtualMethodTargetSpec(target)
			target.VirtualSlot = slot
			addVirtualTarget(out.virtual, slot, target)
			progress(stderr, "kernelcache: vtable-slot convergence found %s slot=%d\n", canonical, slot)
		}
	}

	return out.direct, out.virtual, out.virtualCallers
}

func scanKernelCPP(root *macho.File, stderr io.Writer) (*cpp.Scanner, []cpp.Class) {
	if root == nil {
		return nil, nil
	}
	scanner := cpp.NewScanner(root, cpp.Config{})
	classes, err := scanner.Scan()
	if err != nil {
		progress(stderr, "kernelcache: cpp scan failed during entitlement target discovery: %v\n", err)
		return nil, nil
	}
	return scanner, classes
}

func addNamedVtableTarget(scanner *cpp.Scanner, classes []cpp.Class, out *kernelDiscovery, canonical string, method string, stderr io.Writer) {
	if virtualHasCanonical(out.virtual, canonical) {
		return
	}
	counts := make(map[int]int)
	for idx := range classes {
		if !reachesCPPClass(classes, idx, "IOUserClient") && !reachesCPPClass(classes, idx, "IOUserClient2022") {
			continue
		}
		for _, entry := range scanner.VtableEntries(classes[idx], kernelMaxVtableSlots) {
			if isNamedCPPMethod(entry.Symbol, method) {
				counts[entry.Index]++
			}
		}
	}
	slot, ok := chooseVtableSlot(canonical, counts, "symbol", stderr)
	if !ok {
		return
	}
	addVtableSlotTarget(scanner, classes, out, canonical, slot, stderr)
}

func addVtableSlotTarget(scanner *cpp.Scanner, classes []cpp.Class, out *kernelDiscovery, canonical string, slot int, stderr io.Writer) {
	target, ok := kernelTargetByCanonical(canonical, "vtable_slot")
	if !ok {
		return
	}
	target = virtualMethodTargetSpec(target)
	target.VirtualSlot = slot
	addVirtualTarget(out.virtual, slot, target)

	for _, className := range []string{"IOUserClient", "IOUserClient2022"} {
		idx := findCPPClass(classes, className)
		if idx < 0 {
			continue
		}
		entry, ok := scanner.VtableEntry(classes[idx], slot)
		if !ok || entry.Address == 0 {
			continue
		}
		addTarget(out.direct, entry.Address, target)
		progress(stderr, "kernelcache: vtable slot discovered %s class=%s slot=%d slot_addr=%#x target=%#x\n", canonical, className, slot, entry.SlotAddress, entry.Address)
		return
	}
	progress(stderr, "kernelcache: vtable slot discovered %s slot=%d\n", canonical, slot)
}

func addVtableTargetByCallee(scanner *cpp.Scanner, classes []cpp.Class, out *kernelDiscovery, canonical string, calleeCanonicals []string, stderr io.Writer) {
	callees := xref.NewTargetSet()
	for addr, specs := range out.direct {
		for _, spec := range specs {
			for _, callee := range calleeCanonicals {
				if spec.Canonical == callee {
					callees.Add(addr)
				}
			}
		}
	}
	if len(callees) == 0 {
		return
	}
	callCache := make(map[uint64]bool)
	counts := make(map[int]int)
	for idx := range classes {
		if !reachesCPPClass(classes, idx, "IOUserClient") && !reachesCPPClass(classes, idx, "IOUserClient2022") {
			continue
		}
		for _, entry := range scanner.VtableEntries(classes[idx], kernelMaxVtableSlots) {
			calls, ok := callCache[entry.Address]
			if !ok {
				calls = vtableEntryCallsTarget(scanner, entry.Address, callees)
				callCache[entry.Address] = calls
			}
			if calls {
				counts[entry.Index]++
			}
		}
	}
	slot, ok := chooseVtableSlot(canonical, counts, "callee", stderr)
	if !ok {
		return
	}
	addVtableSlotTarget(scanner, classes, out, canonical, slot, stderr)
}

func vtableEntryCallsTarget(scanner *cpp.Scanner, addr uint64, targets xref.TargetSet) bool {
	if addr == 0 {
		return false
	}
	body, err := scanner.FunctionBodyAt(addr)
	if err != nil || len(body.Data) == 0 {
		return false
	}
	return xref.MayContainDirectCallTarget(body.Data, body.Function.StartAddr, targets)
}

func ioUserClientMethodStarts(scanner *cpp.Scanner, classes []cpp.Class) xref.TargetSet {
	out := xref.NewTargetSet()
	seen := make(map[uint64]struct{})
	for idx := range classes {
		if !reachesCPPClass(classes, idx, "IOUserClient") && !reachesCPPClass(classes, idx, "IOUserClient2022") {
			continue
		}
		for _, entry := range scanner.VtableEntries(classes[idx], kernelMaxVtableSlots) {
			if entry.Address == 0 {
				continue
			}
			if _, ok := seen[entry.Address]; ok {
				continue
			}
			seen[entry.Address] = struct{}{}
			body, err := scanner.FunctionBodyAt(entry.Address)
			if err == nil {
				out.Add(body.Function.StartAddr)
				continue
			}
			out.Add(entry.Address)
		}
	}
	return out
}

func chooseVtableSlot(canonical string, counts map[int]int, source string, stderr io.Writer) (int, bool) {
	if len(counts) == 0 {
		return 0, false
	}
	candidates := make([]convergenceCandidate, 0, len(counts))
	for slot, count := range counts {
		candidates = append(candidates, convergenceCandidate{slot: slot, count: count})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count != candidates[j].count {
			return candidates[i].count > candidates[j].count
		}
		return candidates[i].slot < candidates[j].slot
	})
	if len(candidates) > 1 && candidates[0].count == candidates[1].count {
		progress(stderr, "kernelcache: %s vtable slot ambiguous via %s: %v\n", canonical, source, counts)
		return 0, false
	}
	return candidates[0].slot, true
}

func collectCStringConvergence(images []kernelScanImage, stderr io.Writer) cstringConvergence {
	out := cstringConvergence{
		direct:       make(map[uint64][]targetSpec),
		virtualSlots: make(map[string]int),
	}
	directCounts := map[int]map[uint64]map[uint64]struct{}{
		0: make(map[uint64]map[uint64]struct{}),
		1: make(map[uint64]map[uint64]struct{}),
	}
	virtualCounts := make(map[int]map[uint64]struct{})

	totalKeys := 0
	for _, image := range images {
		keys := entitlementCStringAddrs(image.m)
		if len(keys) == 0 {
			continue
		}
		totalKeys += len(keys)
		keyTargets := xref.NewTargetSet()
		for addr := range keys {
			keyTargets.Add(addr)
		}
		mem := machoMemory{m: image.m}
		for _, fn := range sortedFunctions(image.m.GetFunctions()) {
			data, err := image.m.GetFunctionData(fn)
			if err != nil {
				continue
			}
			instrs := xref.Decode(data, fn.StartAddr)
			refs := xref.ScanInstructions(instrs, xref.Options{
				Targets: keyTargets,
				Reader:  mem,
				Mode:    xref.ModeReferences,
			})
			for _, ref := range refs {
				call := nextCallAfterReference(instrs, ref.Index)
				if !call.ok {
					continue
				}
				state := xref.StateBefore(instrs, call.index, mem, xref.DefaultMaxInstructions)
				for reg := range 2 {
					if !stateRegisterMatches(state, reg, ref.Target) {
						continue
					}
					if call.direct != 0 {
						addDistinctCaller(directCounts[reg], call.direct, fn.StartAddr)
					} else if call.virtualSlot >= 0 && reg == 1 {
						addDistinctSlotCaller(virtualCounts, call.virtualSlot, fn.StartAddr)
					}
				}
			}
		}
	}
	if totalKeys == 0 {
		return out
	}
	progress(stderr, "kernelcache: cstring convergence scanned %d entitlement-looking strings\n", totalKeys)

	iotask, iotaskOK := chooseConvergenceAddress("IOTaskHasEntitlement", directCounts[1], stderr)
	current, currentOK := chooseConvergenceAddress("IOCurrentTaskHasEntitlement", directCounts[0], stderr)
	if iotaskOK && currentOK && iotask.addr == current.addr {
		if current.count > iotask.count {
			iotaskOK = false
		} else {
			currentOK = false
		}
	}
	if iotaskOK {
		addConvergenceTarget(out.direct, iotask.addr, "IOTaskHasEntitlement")
		progress(stderr, "kernelcache: cstring convergence found IOTaskHasEntitlement target=%#x callers=%d\n", iotask.addr, iotask.count)
	}
	if currentOK {
		addConvergenceTarget(out.direct, current.addr, "IOCurrentTaskHasEntitlement")
		progress(stderr, "kernelcache: cstring convergence found IOCurrentTaskHasEntitlement target=%#x callers=%d\n", current.addr, current.count)
	}
	if candidate, ok := chooseConvergenceSlot("IOUserClient::copyClientEntitlement", virtualCounts, stderr); ok {
		out.virtualSlots["IOUserClient::copyClientEntitlement"] = candidate.slot
		progress(stderr, "kernelcache: vtable-slot convergence found IOUserClient::copyClientEntitlement slot=%d callers=%d\n", candidate.slot, candidate.count)
	}
	return out
}

type followingCall struct {
	index       int
	direct      uint64
	virtualSlot int
	ok          bool
}

func nextCallAfterReference(instrs []xref.Instruction, refIdx int) followingCall {
	end := min(len(instrs), refIdx+9)
	for idx := refIdx + 1; idx < end; idx++ {
		inst := &instrs[idx].Inst
		if target, ok := directBLTarget(inst); ok {
			return followingCall{index: idx, direct: target, virtualSlot: -1, ok: true}
		}
		if reg, ok := indirectCallReg(inst); ok {
			if slot, _, ok := vtableSlotForCall(instrs, idx, reg); ok {
				return followingCall{index: idx, virtualSlot: slot, ok: true}
			}
			return followingCall{}
		}
		if isTerminalBranch(inst.Operation) {
			return followingCall{}
		}
	}
	return followingCall{}
}

func directBLTarget(inst *disassemble.Inst) (uint64, bool) {
	if inst.Operation != disassemble.ARM64_BL {
		return 0, false
	}
	return xref.LabelTarget(inst)
}

func isTerminalBranch(op disassemble.Operation) bool {
	switch op {
	case disassemble.ARM64_B, disassemble.ARM64_BR,
		disassemble.ARM64_BRAA, disassemble.ARM64_BRAAZ,
		disassemble.ARM64_BRAB, disassemble.ARM64_BRABZ,
		disassemble.ARM64_RET, disassemble.ARM64_RETAA, disassemble.ARM64_RETAB:
		return true
	default:
		return false
	}
}

func stateRegisterMatches(state xref.RegisterState, reg int, addr uint64) bool {
	val, note := state.Register(reg)
	return note == "" && val.KnownAddress() && val.Addr == addr
}

func addDistinctCaller(counts map[uint64]map[uint64]struct{}, target uint64, caller uint64) {
	if counts[target] == nil {
		counts[target] = make(map[uint64]struct{})
	}
	counts[target][caller] = struct{}{}
}

func addDistinctSlotCaller(counts map[int]map[uint64]struct{}, slot int, caller uint64) {
	if counts[slot] == nil {
		counts[slot] = make(map[uint64]struct{})
	}
	counts[slot][caller] = struct{}{}
}

func chooseConvergenceAddress(canonical string, counts map[uint64]map[uint64]struct{}, stderr io.Writer) (convergenceCandidate, bool) {
	candidates := make([]convergenceCandidate, 0, len(counts))
	for addr, callers := range counts {
		candidates = append(candidates, convergenceCandidate{addr: addr, count: len(callers)})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count != candidates[j].count {
			return candidates[i].count > candidates[j].count
		}
		return candidates[i].addr < candidates[j].addr
	})
	if len(candidates) == 0 {
		return convergenceCandidate{}, false
	}
	if candidates[0].count < kernelCStringThreshold {
		progress(stderr, "kernelcache: cstring convergence %s top candidate below threshold %d: %s\n", canonical, kernelCStringThreshold, formatTopAddressCandidates(candidates, 5))
		return candidates[0], false
	}
	return candidates[0], true
}

func chooseConvergenceSlot(canonical string, counts map[int]map[uint64]struct{}, stderr io.Writer) (convergenceCandidate, bool) {
	candidates := make([]convergenceCandidate, 0, len(counts))
	for slot, callers := range counts {
		candidates = append(candidates, convergenceCandidate{slot: slot, count: len(callers)})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count != candidates[j].count {
			return candidates[i].count > candidates[j].count
		}
		return candidates[i].slot < candidates[j].slot
	})
	if len(candidates) == 0 {
		return convergenceCandidate{}, false
	}
	if candidates[0].count < kernelCStringThreshold {
		progress(stderr, "kernelcache: vtable-slot convergence %s top candidate below threshold %d: %s\n", canonical, kernelCStringThreshold, formatTopSlotCandidates(candidates, 5))
		return candidates[0], false
	}
	return candidates[0], true
}

func addConvergenceTarget(targets map[uint64][]targetSpec, addr uint64, canonical string) {
	target, ok := kernelTargetByCanonical(canonical, "cstring_convergence")
	if !ok {
		return
	}
	addTarget(targets, addr, target)
}

func entitlementCStringAddrs(m *macho.File) map[uint64]string {
	out := make(map[uint64]string)
	for _, sec := range m.Sections {
		if sec.Name != "__cstring" || sec.Size == 0 {
			continue
		}
		data := make([]byte, sec.Size)
		if _, err := m.ReadAtAddr(data, sec.Addr); err != nil {
			continue
		}
		for off := 0; off < len(data); {
			end := bytes.IndexByte(data[off:], 0)
			if end < 0 {
				break
			}
			raw := data[off : off+end]
			if len(raw) > 0 {
				s := string(raw)
				if entitlementKeyLike(s) {
					out[sec.Addr+uint64(off)] = s
				}
			}
			off += end + 1
		}
	}
	return out
}

func entitlementKeyLike(s string) bool {
	return validLiteralString(s) &&
		(strings.HasPrefix(s, "com.apple.private.") ||
			strings.HasPrefix(s, "com.apple.security.") ||
			strings.HasPrefix(s, "com.apple.developer."))
}

func kernelTargetByCanonical(canonical string, discovery string) (targetSpec, bool) {
	for _, target := range kernelTargets() {
		if target.Canonical == canonical {
			target.Discovery = discovery
			return target, true
		}
	}
	return targetSpec{}, false
}

func virtualMethodTargetSpec(target targetSpec) targetSpec {
	switch target.Canonical {
	case "IOUserClient::copyClientEntitlement", "IOUserClient::clientHasPrivilege":
		target.KeyReg = 2
	case "IOUserClient::copyClientEntitlementVnode":
		target.KeyReg = 3
	}
	return target
}

func addVirtualTarget(targets map[int][]targetSpec, slot int, target targetSpec) {
	for _, existing := range targets[slot] {
		if existing.Canonical == target.Canonical {
			return
		}
	}
	targets[slot] = append(targets[slot], target)
	sort.Slice(targets[slot], func(i, j int) bool {
		return targets[slot][i].Canonical < targets[slot][j].Canonical
	})
}

func virtualHasCanonical(targets map[int][]targetSpec, canonical string) bool {
	for _, specs := range targets {
		for _, spec := range specs {
			if spec.Canonical == canonical {
				return true
			}
		}
	}
	return false
}

func findCPPClass(classes []cpp.Class, name string) int {
	for idx := range classes {
		if classes[idx].Name == name {
			return idx
		}
	}
	return -1
}

func reachesCPPClass(classes []cpp.Class, idx int, target string) bool {
	seen := make(map[int]struct{})
	for idx >= 0 && idx < len(classes) {
		if _, ok := seen[idx]; ok {
			return false
		}
		seen[idx] = struct{}{}
		if classes[idx].Name == target {
			return true
		}
		idx = classes[idx].SuperIndex
	}
	return false
}

func isNamedCPPMethod(symbolName string, method string) bool {
	return symbolName != "" &&
		(strings.Contains(symbolName, "::"+method+"(") ||
			strings.Contains(symbolName, "::"+method+" "))
}

func formatTopAddressCandidates(candidates []convergenceCandidate, limit int) string {
	limit = min(limit, len(candidates))
	parts := make([]string, 0, limit)
	for idx := 0; idx < limit; idx++ {
		parts = append(parts, fmt.Sprintf("(%#x,%d)", candidates[idx].addr, candidates[idx].count))
	}
	return strings.Join(parts, " ")
}

func formatTopSlotCandidates(candidates []convergenceCandidate, limit int) string {
	limit = min(limit, len(candidates))
	parts := make([]string, 0, limit)
	for idx := 0; idx < limit; idx++ {
		parts = append(parts, fmt.Sprintf("(slot:%d,%d)", candidates[idx].slot, candidates[idx].count))
	}
	return strings.Join(parts, " ")
}
