package xrefs

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/pacx"
	"github.com/blacktop/ipsw/pkg/xref"
)

type pacEntTarget struct {
	target    targetSpec
	record    pacx.PacRecord
	candidate pacx.PacCandidate
}

type pacEntTargetKey struct {
	callerFunc uint64
	callsite   uint64
	canonical  string
	keyReg     int
	valueReg   int
	vfunc      uint64
	class      string
}

func collectPacEntitlementTargets(root *macho.File, name string, targets map[uint64][]targetSpec, virtualSlots map[int][]targetSpec, stderr io.Writer) map[uint64]map[uint64][]pacEntTarget {
	records, err := pacx.ScanKernelcache(root, pacx.ScanConfig{Name: name})
	if err != nil {
		progress(stderr, "kernelcache: pacx entitlement edge scan failed: %v\n", err)
		return nil
	}

	byFunc := make(map[uint64]map[uint64][]pacEntTarget)
	seen := make(map[pacEntTargetKey]struct{})
	added := 0
	for _, rec := range records {
		for _, cand := range rec.Candidates {
			for _, target := range entitlementSpecsForPacCandidate(rec, cand, targets, virtualSlots) {
				key := pacEntTargetKey{
					callerFunc: rec.CallerFunc,
					callsite:   rec.Callsite,
					canonical:  target.Canonical,
					keyReg:     target.KeyReg,
					valueReg:   target.ValueReg,
					vfunc:      cand.Vfunc,
					class:      cand.Class,
				}
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				if byFunc[rec.CallerFunc] == nil {
					byFunc[rec.CallerFunc] = make(map[uint64][]pacEntTarget)
				}
				byFunc[rec.CallerFunc][rec.Callsite] = append(byFunc[rec.CallerFunc][rec.Callsite], pacEntTarget{
					target:    target,
					record:    rec,
					candidate: cand,
				})
				added++
			}
		}
	}
	if added > 0 {
		progress(stderr, "kernelcache: pacx matched %d entitlement-check virtual-call candidates\n", added)
	}
	return byFunc
}

func entitlementSpecsForPacCandidate(rec pacx.PacRecord, cand pacx.PacCandidate, targets map[uint64][]targetSpec, virtualSlots map[int][]targetSpec) []targetSpec {
	seen := make(map[string]struct{})
	var out []targetSpec
	for _, target := range targets[cand.Vfunc] {
		out = appendPacTarget(out, seen, target)
	}
	for _, target := range virtualSlotSpecsForPacRecord(rec, virtualSlots) {
		out = appendPacTarget(out, seen, target)
	}
	if cand.VfuncSymbol != "" {
		if target, ok := matchTarget(SourceKernelcache, cand.VfuncSymbol); ok {
			out = appendPacTarget(out, seen, target)
		}
	}
	return out
}

func virtualSlotSpecsForPacRecord(rec pacx.PacRecord, virtualSlots map[int][]targetSpec) []targetSpec {
	if rec.SlotIndex >= 0 {
		if targets := virtualSlots[rec.SlotIndex]; len(targets) > 0 {
			return targets
		}
	}
	if rec.SlotOffset%8 != 0 {
		return nil
	}
	return virtualSlots[int(rec.SlotOffset/8)]
}

func appendPacTarget(out []targetSpec, seen map[string]struct{}, target targetSpec) []targetSpec {
	if _, ok := seen[target.Canonical]; ok {
		return out
	}
	seen[target.Canonical] = struct{}{}
	target = virtualMethodTargetSpec(target)
	target.Discovery = appendDiscovery(target.Discovery, "pacx")
	return append(out, target)
}

func appendDiscovery(existing, next string) string {
	if existing == "" {
		return next
	}
	parts := strings.Split(existing, ",")
	if slices.Contains(parts, next) {
		return existing
	}
	parts = append(parts, next)
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func scanPacEntitlementCalls(scan functionScan, instrs []xref.Instruction, existing []Record) []Record {
	if len(scan.pacEntTargets) == 0 {
		return nil
	}
	existingSeen := existingEntRecordKeys(existing)
	pacSeen := make(map[string]struct{})
	var records []Record
	for idx := range instrs {
		targets := scan.pacEntTargets[instrs[idx].Address]
		if len(targets) == 0 {
			continue
		}
		state := xref.StateBefore(instrs, idx, scan.mem, xref.DefaultMaxInstructions)
		for _, target := range targets {
			value := ""
			if target.target.hasValue() {
				if v, _ := resolveRegister(state, target.target.ValueReg, scan.mem); v != "" {
					value = v
				}
			}
			for _, key := range resolveTargetKeys(state, target.target, scan.mem) {
				rec := buildRecord(scan, instrs[idx].Address, target.target, key, value)
				addPacEntitlementExtra(&rec, target)
				if _, ok := existingSeen[entRecordKey(rec)]; ok {
					continue
				}
				recKey := pacEntRecordKey(rec, target)
				if _, ok := pacSeen[recKey]; ok {
					continue
				}
				pacSeen[recKey] = struct{}{}
				records = append(records, rec)
			}
		}
	}
	return records
}

func existingEntRecordKeys(records []Record) map[string]struct{} {
	seen := make(map[string]struct{}, len(records))
	for _, rec := range records {
		seen[entRecordKey(rec)] = struct{}{}
	}
	return seen
}

func entRecordKey(rec Record) string {
	return strings.Join([]string{
		rec.Source,
		rec.Image,
		rec.Callsite,
		rec.CheckFn,
		rec.Key,
		rec.Value,
	}, "\x00")
}

func pacEntRecordKey(rec Record, target pacEntTarget) string {
	return entRecordKey(rec) + "\x00" +
		fmt.Sprintf("%#x", target.candidate.Vfunc) + "\x00" +
		target.candidate.Class
}

func addPacEntitlementExtra(rec *Record, target pacEntTarget) {
	if rec.Extra == nil {
		rec.Extra = map[string]string{}
	}
	rec.Extra["pacx_auth"] = target.record.Auth
	rec.Extra["pacx_candidate_count"] = strconv.Itoa(len(target.record.Candidates))
	rec.Extra["pacx_class"] = target.candidate.Class
	rec.Extra["pacx_confidence"] = target.record.Confidence
	rec.Extra["pacx_pac"] = fmt.Sprintf("0x%04x", target.record.PAC)
	rec.Extra["pacx_slot_index"] = strconv.Itoa(target.record.SlotIndex)
	rec.Extra["pacx_slot_offset"] = fmt.Sprintf("%#x", target.record.SlotOffset)
	rec.Extra["pacx_vfunc"] = fmt.Sprintf("%#x", target.candidate.Vfunc)
	if target.candidate.VfuncSymbol != "" {
		rec.Extra["pacx_vfunc_symbol"] = target.candidate.VfuncSymbol
	}
}
