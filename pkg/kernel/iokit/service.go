package iokit

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

type plistBundle struct {
	ID                 string         `plist:"CFBundleIdentifier,omitempty"`
	IOKitPersonalities map[string]any `plist:"IOKitPersonalities,omitempty"`
}

func (a *analyzer) personalityRecords() []Record {
	bundles := kextBundles(a.root)
	bundles = append(bundles, a.filesetPlistBundles()...)

	records := make([]Record, 0, len(bundles))
	for _, bundle := range bundles {
		bundleID := bundle.ID
		if bundleID == "" {
			bundleID = bundle.Name
		}
		for name, raw := range bundle.IOKitPersonalities {
			personality, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			serviceClass := stringField(personality, "IOClass")
			userClientClass := stringField(personality, "IOUserClientClass")
			if userClientClass == "" {
				continue
			}
			rec := a.serviceRecord(serviceClass, bundleID, userClientClass, SourceIOKitPersonality)
			if rec.Extra == nil {
				rec.Extra = map[string]string{}
			}
			rec.Extra["personality"] = name
			records = append(records, rec)
		}
	}
	return records
}

func (a *analyzer) filesetPlistBundles() []kernelcache.CFBundle {
	if a.root == nil || a.root.FileHeader.Type != mtypes.MH_FILESET {
		return nil
	}
	var bundles []kernelcache.CFBundle
	for _, fs := range a.root.FileSets() {
		m, err := a.root.GetFileSetFileByName(fs.EntryID)
		if err != nil {
			progress(a.stderr, "kernel iokit-methods: failed to open fileset %s for plist scan: %v\n", fs.EntryID, err)
			continue
		}
		bundle, ok := readInfoPlistBundle(m)
		if !ok || len(bundle.IOKitPersonalities) == 0 {
			continue
		}
		if bundle.ID == "" {
			bundle.ID = fs.EntryID
		}
		bundles = append(bundles, kernelcache.CFBundle{
			ID:                    bundle.ID,
			IOKitPersonalities:    bundle.IOKitPersonalities,
			ExecutableLoadAddr:    m.GetBaseAddress(),
			Executable:            fs.EntryID,
			BundlePath:            fs.EntryID,
			RelativePath:          fs.EntryID,
			InfoDictionaryVersion: "",
		})
	}
	return bundles
}

func readInfoPlistBundle(m *macho.File) (plistBundle, bool) {
	for _, sec := range m.Sections {
		if sec == nil || sec.Size == 0 {
			continue
		}
		if sec.Name != "__info_plist" && sec.Name != "__info" {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		var bundle plistBundle
		if err := plist.NewDecoder(bytes.NewReader(bytes.Trim(data, "\x00"))).Decode(&bundle); err != nil {
			continue
		}
		return bundle, true
	}
	return plistBundle{}, false
}

func stringField(m map[string]any, key string) string {
	value, ok := m[key]
	if !ok {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func (a *analyzer) serviceRecord(serviceClass, serviceBundle, userClientClass, source string) Record {
	ucInfos := a.byName[userClientClass]
	serviceInfos := a.byName[serviceClass]
	extra := map[string]string{}
	resolved := true
	if serviceClass == "" {
		resolved = false
		extra["slice_notes"] = appendNote(extra["slice_notes"], "service_class_unknown")
	} else if !classExists(serviceInfos) {
		resolved = false
		extra["slice_notes"] = appendNote(extra["slice_notes"], "service_class_unresolved")
	}
	if !classExists(ucInfos) {
		resolved = false
		extra["slice_notes"] = appendNote(extra["slice_notes"], "user_client_class_unresolved")
	}
	userClientBundle := classBundle(ucInfos)
	if serviceBundle == "" {
		serviceBundle = classBundle(serviceInfos)
	}
	return Record{
		Kind:             KindServiceClient,
		ServiceClass:     serviceClass,
		ServiceBundle:    serviceBundle,
		UserClientClass:  userClientClass,
		UserClientBundle: userClientBundle,
		Source:           source,
		Resolved:         resolved,
		Extra:            extra,
	}
}

func appendNote(existing, note string) string {
	if existing == "" {
		return note
	}
	if note == "" {
		return existing
	}
	parts := strings.Split(existing, ",")
	if slices.Contains(parts, note) {
		return existing
	}
	parts = append(parts, note)
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (a *analyzer) newUserClientRecords() []Record {
	slot, ok := a.newUserClientSlot()
	if !ok {
		return a.newUserClientFallbackRecords()
	}
	records := make([]Record, 0, 64)
	for _, info := range a.infos {
		if !info.isService {
			continue
		}
		entry, ok := a.scanner.VtableEntry(info.Class, slot)
		if !ok || entry.Address == 0 {
			continue
		}
		clients := a.userClientsReferencedBy(entry.Address)
		for _, client := range clients {
			records = append(records, a.newUserClientRecord(info, client, entry.Address, ""))
		}
	}
	return records
}

func (a *analyzer) newUserClientFallbackRecords() []Record {
	records := make([]Record, 0, 64)
	for _, info := range a.infos {
		if !info.isService || info.userClient {
			continue
		}
		for _, entry := range a.scanner.VtableEntries(info.Class, a.maxSlots) {
			if entry.Address == 0 {
				continue
			}
			clients := a.userClientsReferencedBy(entry.Address)
			for _, client := range clients {
				records = append(records, a.newUserClientRecord(info, client, entry.Address, "newUserClient_slot_unresolved"))
			}
		}
	}
	return records
}

func (a *analyzer) newUserClientRecord(info *classInfo, client string, methodAddr uint64, note string) Record {
	rec := a.serviceRecord(info.Name, info.Bundle, client, SourceNewUserClient)
	if rec.Extra == nil {
		rec.Extra = map[string]string{}
	}
	rec.Extra["method_addr"] = hexAddr(methodAddr)
	if symbol := a.symbolName(methodAddr); symbol != "" {
		rec.Extra["method_symbol"] = symbol
	}
	if note != "" {
		rec.Resolved = false
		rec.Extra["slice_notes"] = appendNote(rec.Extra["slice_notes"], note)
	}
	return rec
}

func (a *analyzer) newUserClientSlot() (int, bool) {
	slots := make(map[int]int)
	for _, info := range a.infos {
		if !info.isService {
			continue
		}
		for _, entry := range a.scanner.VtableEntries(info.Class, a.maxSlots) {
			if isNamedMethod(a.symbolName(entry.Address), "newUserClient") {
				slots[entry.Index]++
			}
		}
	}
	if len(slots) == 0 {
		return -1, false
	}
	slot, err := chooseSlot("IOService", slots, "newUserClient symbol")
	if err != nil {
		progress(a.stderr, "kernel iokit-methods: %v\n", err)
		return -1, false
	}
	return slot, true
}

func (a *analyzer) userClientsReferencedBy(methodAddr uint64) []string {
	if cached, ok := a.ucRefs[methodAddr]; ok {
		return cached
	}
	body, err := a.scanner.FunctionBodyAt(methodAddr)
	if err != nil {
		a.ucRefs[methodAddr] = nil
		return nil
	}
	instrs := decodeInstructions(body.Data, body.Function.StartAddr, a.maxInst)
	var regs [31]linearExpr
	found := make(map[string]struct{})
	for idx := range instrs {
		inst := &instrs[idx].Inst
		applyMethodInstruction(a, body.Owner, inst, regs[:])
		for regIdx := range regs {
			expr := regs[regIdx]
			if !expr.valid || expr.coeff != 0 || expr.base == 0 {
				continue
			}
			if client := a.userClientForStaticValue(body.Owner, expr.base); client != "" {
				found[client] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(found))
	for client := range found {
		out = append(out, client)
	}
	sort.Strings(out)
	a.ucRefs[methodAddr] = out
	return out
}

func (a *analyzer) userClientForStaticValue(owner *macho.File, addr uint64) string {
	for _, info := range a.byName {
		for _, candidate := range info {
			if candidate.userClient && candidate.MetaPtr == addr {
				return candidate.Name
			}
		}
	}
	if str, err := a.scanner.ReadCStringAt(owner, addr); err == nil && validLiteralString(str) {
		if _, ok := a.userClient[str]; ok {
			return str
		}
	}
	if ptr, ok := a.scanner.ReadPointerAt(owner, addr); ok {
		if str, err := a.scanner.ReadCStringAt(owner, ptr); err == nil && validLiteralString(str) {
			if _, ok := a.userClient[str]; ok {
				return str
			}
		}
	}
	return ""
}
