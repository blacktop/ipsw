package xrefs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/blacktop/ipsw/pkg/symbols"
	"github.com/blacktop/ipsw/pkg/xref"
)

var ErrNoTargetSymbols = errors.New("no entitlement-check target symbols found")

type Config struct {
	Kernelcache string
	DSC         string
	Stderr      io.Writer
}

func Scan(conf Config) ([]Record, error) {
	var records []Record
	targetSymbols := 0
	if conf.Kernelcache != "" {
		recs, targets, err := ScanKernelcache(conf.Kernelcache, conf.Stderr)
		if err != nil {
			return nil, err
		}
		records = append(records, recs...)
		targetSymbols += targets
	}
	if conf.DSC != "" {
		recs, targets, err := ScanDSC(conf.DSC, conf.Stderr)
		if err != nil {
			return nil, err
		}
		records = append(records, recs...)
		targetSymbols += targets
	}
	if targetSymbols == 0 {
		return nil, ErrNoTargetSymbols
	}
	SortRecords(records)
	return records, nil
}

func ScanKernelcache(path string, stderr io.Writer) ([]Record, int, error) {
	m, closeFn, err := openKernelcache(path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open kernelcache: %w", err)
	}
	defer closeFn()

	symbolicatedTargets := collectKernelSymbolicatedTargets(m, path, stderr)
	if m.FileTOC.FileHeader.Type == mtypes.MH_FILESET {
		return scanKernelFileset(m, symbolicatedTargets, stderr)
	}

	targets := collectMachOTargets(SourceKernelcache, m)
	mergeTargets(targets, symbolicatedTargets)
	discoveredTargets, virtualSlots, virtualCallers := discoverKernelTargets(m, []kernelScanImage{{name: "com.apple.kernel", m: m}}, stderr)
	mergeTargets(targets, discoveredTargets)
	if len(targets) == 0 && len(virtualSlots) == 0 {
		progress(stderr, "kernelcache: no entitlement-check target symbols found\n")
		return nil, 0, nil
	}
	progress(stderr, "kernelcache: found %d target addresses and %d virtual target slots\n", len(targets), len(virtualSlots))

	ranges := kernelImageRanges(m)
	mem := machoMemory{m: m}
	targetAddrs := targetSetFromSpecs(targets)
	hints := hintsForTargets(targets, virtualSlots)
	var scanner xref.Scanner
	var records []Record
	for _, fn := range sortedFunctions(m.GetFunctions()) {
		data, err := m.GetFunctionData(fn)
		if err != nil {
			progress(stderr, "kernelcache: failed to read function %#x: %v\n", fn.StartAddr, err)
			continue
		}
		records = append(records, scanFunction(functionScan{
			source:       SourceKernelcache,
			image:        ranges.imageFor(fn.StartAddr),
			callerSymbol: functionSymbol(m, fn.StartAddr),
			data:         data,
			start:        fn.StartAddr,
			targets:      targets,
			targetAddrs:  targetAddrs,
			virtualSlots: virtualSlots,
			mem:          mem,
			allowVirtual: virtualCallers.Has(fn.StartAddr),
			scanner:      &scanner,
			targetHints:  hints,
		})...)
	}
	SortRecords(records)
	return records, len(targets) + len(virtualSlots), nil
}

func scanKernelFileset(root *macho.File, symbolicatedTargets map[uint64][]targetSpec, stderr io.Writer) ([]Record, int, error) {
	globalTargets := make(map[uint64][]targetSpec)
	entries := root.FileSets()
	images := kernelFilesetScanImages(root, entries, stderr)
	for _, image := range images {
		mergeTargets(globalTargets, collectMachOTargets(SourceKernelcache, image.m))
	}
	mergeTargets(globalTargets, symbolicatedTargets)
	discoveredTargets, virtualSlots, virtualCallers := discoverKernelTargets(root, images, stderr)
	mergeTargets(globalTargets, discoveredTargets)
	if len(globalTargets) == 0 && len(virtualSlots) == 0 {
		progress(stderr, "kernelcache: no entitlement-check target symbols found\n")
		return nil, 0, nil
	}
	progress(stderr, "kernelcache: found %d fileset target addresses and %d virtual target slots\n", len(globalTargets), len(virtualSlots))

	targetAddrs := targetSetFromSpecs(globalTargets)
	hints := hintsForTargets(globalTargets, virtualSlots)
	var records []Record
	for _, image := range images {
		m := image.m
		targets := cloneTargets(globalTargets)
		mem := machoMemory{m: m}
		var scanner xref.Scanner
		for _, fn := range sortedFunctions(m.GetFunctions()) {
			data, err := m.GetFunctionData(fn)
			if err != nil {
				progress(stderr, "kernelcache: failed to read %s function %#x: %v\n", image.name, fn.StartAddr, err)
				continue
			}
			records = append(records, scanFunction(functionScan{
				source:       SourceKernelcache,
				image:        image.name,
				callerSymbol: functionSymbol(m, fn.StartAddr),
				data:         data,
				start:        fn.StartAddr,
				targets:      targets,
				targetAddrs:  targetAddrs,
				virtualSlots: virtualSlots,
				mem:          mem,
				allowVirtual: virtualCallers.Has(fn.StartAddr),
				scanner:      &scanner,
				targetHints:  hints,
			})...)
		}
	}
	SortRecords(records)
	return records, len(globalTargets) + len(virtualSlots), nil
}

func collectKernelSymbolicatedTargets(m *macho.File, path string, stderr io.Writer) map[uint64][]targetSpec {
	targets := make(map[uint64][]targetSpec)
	smap := signature.NewSymbolMap()
	if loaded := loadKernelSymbolMap(smap, path); loaded != "" {
		progress(stderr, "kernelcache: loaded symbol map %s\n", loaded)
	} else {
		if err := smap.SymbolicateMachO(m, filepath.Base(path), nil, true); err != nil {
			progress(stderr, "kernelcache: symbolicator fallback failed: %v\n", err)
			return targets
		}
	}
	for addr, name := range smap {
		if target, ok := matchTarget(SourceKernelcache, name); ok {
			addTarget(targets, addr, target)
		}
	}
	if len(targets) > 0 {
		progress(stderr, "kernelcache: symbolicator found %d entitlement-check target addresses\n", len(targets))
	}
	return targets
}

func loadKernelSymbolMap(smap signature.SymbolMap, path string) string {
	for _, candidate := range kernelSymbolMapCandidates(path) {
		if err := smap.LoadJSON(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func kernelSymbolMapCandidates(path string) []string {
	base := filepath.Base(path) + ".symbols.json"
	seen := make(map[string]struct{})
	var out []string
	add := func(candidate string) {
		candidate = filepath.Clean(candidate)
		if _, ok := seen[candidate]; ok {
			return
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}

	dir := filepath.Dir(path)
	for range 4 {
		add(filepath.Join(dir, base))
		matches, _ := filepath.Glob(filepath.Join(dir, "*", base))
		sort.Strings(matches)
		for _, match := range matches {
			add(match)
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return out
}

func ScanDSC(path string, stderr io.Writer) ([]Record, int, error) {
	f, err := dyld.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open DSC: %w", err)
	}
	defer f.Close()
	if !f.IsArm64() {
		return nil, 0, fmt.Errorf("DSC must be arm64/arm64e")
	}

	globalTargets, directTargets, selectorImages := collectDSCTargetIndex(f, stderr)
	if len(globalTargets) == 0 {
		progress(stderr, "dsc: no entitlement-check target symbols found\n")
		return nil, 0, nil
	}
	if _, err := f.GetAllObjCSelectors(false); err != nil {
		progress(stderr, "dsc: failed to load Objective-C selector table: %v\n", err)
	}
	patchTargets := map[string]map[uint64][]targetSpec{}
	patchTargetSlots := map[uint64][]targetSpec{}
	if err := f.ParsePatchInfo(); err != nil {
		progress(stderr, "dsc: failed to parse patch info: %v\n", err)
	} else {
		patchTargets, patchTargetSlots = collectDSCPatchTargets(f)
	}
	addDSCStubIslandTargets(f, globalTargets, patchTargetSlots, stderr)
	progress(stderr, "dsc: found %d global target addresses\n", len(globalTargets))

	mem := dyldMemory{f: f, boundPointers: make(map[uint64]uint64)}
	var records []Record
	for _, img := range f.Images {
		m, err := img.GetMacho()
		if err != nil {
			progress(stderr, "dsc: failed to parse %s: %v\n", img.Name, err)
			img.Free()
			continue
		}
		targets := cloneTargets(directTargets[img.Name])
		includeObjCSelectors := selectorImages[img.Name]
		bindTargets := collectDSCBoundTargets(m)
		mergeTargets(bindTargets, patchTargets[img.Name])
		addDSCBoundPointerTargets(targets, bindTargets, mem.boundPointers)
		addDSCBindStubTargets(img, m, targets, bindTargets, stderr)
		addDSCResolvedStubTargets(img, targets, globalTargets, includeObjCSelectors, stderr)
		gotTargetsAdded := addDSCResolvedGOTTargets(img, targets, globalTargets, includeObjCSelectors, stderr)
		addDSCObjCStubTargets(f, img, targets)
		addFilteredGlobalTargets(targets, globalTargets, includeObjCSelectors)
		if len(targets) == 0 {
			img.Free()
			continue
		}
		skipIndirect := skipIndirectDSCScan(bindTargets, gotTargetsAdded)
		targetAddrs := targetSetFromSpecs(targets)
		hints := hintsForTargets(targets, nil)
		reader := newDyldFunctionReader(f, img, m)
		funcs := sortedFunctions(m.GetFunctions())
		var scanner xref.Scanner
		progress(stderr, "dsc: scanning %s (%d target refs)\n", img.Name, len(targets))
		for _, fn := range funcs {
			data, err := reader.read(fn)
			if err != nil {
				progress(stderr, "dsc: failed to read %s function %#x: %v\n", img.Name, fn.StartAddr, err)
				continue
			}
			if skipIndirect && !xref.MayContainDirectCallTarget(data, fn.StartAddr, targetAddrs) {
				continue
			}
			records = append(records, scanFunction(functionScan{
				source:       SourceDSC,
				image:        img.Name,
				callerSymbol: functionSymbol(m, fn.StartAddr),
				data:         data,
				start:        fn.StartAddr,
				targets:      targets,
				targetAddrs:  targetAddrs,
				mem:          mem,
				skipIndirect: skipIndirect,
				scanner:      &scanner,
				targetHints:  hints,
			})...)
		}
		for _, window := range reader.directTargetWindows(targetAddrs, funcs) {
			records = append(records, scanFunction(functionScan{
				source:       SourceDSC,
				image:        img.Name,
				data:         window.data,
				start:        window.start,
				targets:      targets,
				targetAddrs:  targetAddrs,
				mem:          mem,
				skipIndirect: true,
				scanner:      &scanner,
				targetHints:  hints,
			})...)
		}
		img.Free()
	}
	SortRecords(records)
	return records, len(globalTargets), nil
}

func skipIndirectDSCScan(bindTargets map[uint64][]targetSpec, gotTargetsAdded bool) bool {
	return len(bindTargets) == 0 && !gotTargetsAdded
}

func openKernelcache(path string) (*macho.File, func(), error) {
	if m, err := macho.Open(path); err == nil {
		return m, func() { _ = m.Close() }, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if cc, err := kernelcache.ParseImg4Data(data); err == nil {
		dec, err := kernelcache.DecompressData(cc)
		if err != nil {
			return nil, nil, err
		}
		m, err := macho.NewFile(bytes.NewReader(dec))
		if err != nil {
			return nil, nil, err
		}
		return m, func() {}, nil
	}
	if dec, err := kernelcache.DecompressKernelManagementData(path); err == nil {
		m, err := macho.NewFile(bytes.NewReader(dec))
		if err != nil {
			return nil, nil, err
		}
		return m, func() {}, nil
	}
	return nil, nil, fmt.Errorf("not a Mach-O or supported compressed kernelcache")
}

func collectMachOTargets(source Source, m *macho.File) map[uint64][]targetSpec {
	targets := make(map[uint64][]targetSpec)
	add := func(addr uint64, name string) {
		if addr == 0 {
			return
		}
		if target, ok := matchTarget(source, name); ok {
			addTarget(targets, addr, target)
		}
	}
	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			add(sym.Value, sym.Name)
		}
	}
	if exports, err := m.GetExports(); err == nil {
		for _, sym := range exports {
			add(sym.Address, sym.Name)
		}
	}
	if exports, err := m.DyldExports(); err == nil {
		for _, sym := range exports {
			add(sym.Address, sym.Name)
		}
	}
	return targets
}

func collectDSCPatchTargets(f *dyld.File) (map[string]map[uint64][]targetSpec, map[uint64][]targetSpec) {
	targets := make(map[string]map[uint64][]targetSpec)
	slotTargets := make(map[uint64][]targetSpec)
	add := func(imageIndex int, addr uint64, target targetSpec) {
		if addr == 0 {
			return
		}
		addTarget(slotTargets, addr, target)
		if imageIndex < 0 || imageIndex >= len(f.Images) {
			return
		}
		imageTargets := targets[f.Images[imageIndex].Name]
		if imageTargets == nil {
			imageTargets = make(map[uint64][]targetSpec)
			targets[f.Images[imageIndex].Name] = imageTargets
		}
		addTarget(imageTargets, addr, target)
	}

	for _, image := range f.Images {
		for _, patch := range image.PatchableExports {
			target, ok := matchTarget(SourceDSC, patch.GetName())
			if !ok {
				continue
			}
			clientIndex := int(patch.GetClientIndex())
			if clientIndex < 0 || clientIndex >= len(f.Images) {
				continue
			}
			clientBase := f.Images[clientIndex].LoadAddress
			switch locs := patch.GetPatchLocations().(type) {
			case []dyld.CachePatchableLocationV2:
				for _, loc := range locs {
					add(clientIndex, clientBase+uint64(loc.DylibOffsetOfUse), target)
				}
			case []dyld.CachePatchableLocationV4:
				for _, loc := range locs {
					add(clientIndex, clientBase+uint64(loc.DylibOffsetOfUse), target)
				}
			}
		}
	}

	for imageIndex, image := range f.Images {
		for _, patch := range image.PatchableGOTs {
			target, ok := matchTarget(SourceDSC, patch.GetName())
			if !ok {
				continue
			}
			switch locs := patch.GetGotLocations().(type) {
			case []dyld.CachePatchableLocationV3:
				for _, loc := range locs {
					if _, addr, err := f.GetCacheVMAddress(loc.CacheOffsetOfUse); err == nil {
						add(imageIndex, addr, target)
					}
				}
			case []dyld.CachePatchableLocationV4Got:
				for _, loc := range locs {
					if _, addr, err := f.GetCacheVMAddress(loc.CacheOffsetOfUse); err == nil {
						add(imageIndex, addr, target)
					}
				}
			}
		}
	}

	return targets, slotTargets
}

func collectDSCTargetIndex(f *dyld.File, stderr io.Writer) (map[uint64][]targetSpec, map[string]map[uint64][]targetSpec, map[string]bool) {
	globalTargets := make(map[uint64][]targetSpec)
	directTargets := make(map[string]map[uint64][]targetSpec)
	selectorImages := make(map[string]bool)
	for _, img := range f.Images {
		m, err := img.GetMacho()
		if err != nil {
			progress(stderr, "dsc: failed to parse %s during target discovery: %v\n", img.Name, err)
			img.Free()
			continue
		}
		targets := collectMachOTargets(SourceDSC, m)
		addDSCExportTrieTargets(f, img, targets)
		if len(targets) > 0 {
			directTargets[img.Name] = targets
			mergeTargets(globalTargets, targets)
		}
		selectorImages[img.Name] = imageHasSelector(m, "valueForEntitlement:")
		img.Free()
	}
	return globalTargets, directTargets, selectorImages
}

func addDSCExportTrieTargets(f *dyld.File, img *dyld.CacheImage, targets map[uint64][]targetSpec) {
	exports, err := f.GetExportTrieSymbols(img)
	if err != nil {
		return
	}
	for _, sym := range exports {
		if sym.Address == 0 {
			continue
		}
		if target, ok := matchTarget(SourceDSC, sym.Name); ok {
			addTarget(targets, sym.Address, target)
		}
	}
}

func addDSCStubIslandTargets(f *dyld.File, globalTargets map[uint64][]targetSpec, patchTargetSlots map[uint64][]targetSpec, stderr io.Writer) {
	stubs, err := f.GetStubIslandTargets()
	if err != nil {
		progress(stderr, "dsc: failed to parse stub islands: %v\n", err)
		return
	}
	stubTargets := make(map[uint64][]targetSpec)
	for stub, targetAddr := range stubs {
		for _, target := range globalTargets[targetAddr] {
			addTarget(stubTargets, stub, target)
		}
	}
	slots, err := f.GetStubIslandPointerSlots()
	if err != nil {
		progress(stderr, "dsc: failed to parse stub-island slots: %v\n", err)
	} else {
		for stub, slot := range slots {
			for _, target := range patchTargetSlots[slot] {
				addTarget(stubTargets, stub, target)
			}
		}
	}
	mergeTargets(globalTargets, stubTargets)
	if len(stubTargets) > 0 {
		progress(stderr, "dsc: resolved %d entitlement-check stub-island targets\n", len(stubTargets))
	}
}

func addDSCResolvedStubTargets(img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, includeObjCSelectors bool, stderr io.Writer) {
	if err := img.ParseStubs(); err != nil {
		progress(stderr, "dsc: failed to parse %s stubs: %v\n", img.Name, err)
		return
	}
	for stub, targetAddr := range img.Analysis.SymbolStubs {
		addResolvedAddressTarget(targets, globalTargets, stub, targetAddr, includeObjCSelectors)
	}
}

func collectDSCBoundTargets(m *macho.File) map[uint64][]targetSpec {
	targets := make(map[uint64][]targetSpec)
	add := func(addr uint64, name string) {
		if addr == 0 || name == "" {
			return
		}
		if target, ok := matchTarget(SourceDSC, name); ok {
			addTarget(targets, addr, target)
		}
	}

	if binds, err := m.GetBindInfo(); err == nil {
		for _, bind := range binds {
			add(bind.Start+bind.SegOffset, bind.Name)
		}
	}
	if !m.HasDyldChainedFixups() {
		return targets
	}
	dcf, err := m.DyldChainedFixups()
	if err != nil {
		return targets
	}
	if _, err := dcf.Parse(); err != nil {
		return targets
	}
	for _, start := range dcf.Starts {
		for _, bind := range start.Binds() {
			slot, err := m.GetVMAddress(bind.Offset())
			if err != nil {
				continue
			}
			add(slot, bind.Name())
		}
	}
	return targets
}

func addDSCBoundPointerTargets(targets, bindTargets map[uint64][]targetSpec, boundPointers map[uint64]uint64) {
	for slot, specs := range bindTargets {
		boundPointers[slot] = slot
		for _, spec := range specs {
			addTarget(targets, slot, spec)
		}
	}
}

func addDSCBindStubTargets(img *dyld.CacheImage, m *macho.File, targets, bindTargets map[uint64][]targetSpec, stderr io.Writer) {
	if len(bindTargets) == 0 {
		return
	}
	stubSlots, err := parseDSCStubPointerSlots(img, m)
	if err != nil {
		progress(stderr, "dsc: failed to parse %s stub slots: %v\n", img.Name, err)
		return
	}
	for stub, slot := range stubSlots {
		for _, target := range bindTargets[slot] {
			addTarget(targets, stub, target)
		}
	}
}

func parseDSCStubPointerSlots(img *dyld.CacheImage, m *macho.File) (map[uint64]uint64, error) {
	slots := make(map[uint64]uint64)
	for _, sec := range m.Sections {
		if !sec.Flags.IsSymbolStubs() {
			continue
		}
		data := make([]byte, sec.Size)
		if _, err := img.ReadAtAddr(data, sec.Addr); err != nil {
			return nil, err
		}
		maps.Copy(slots, xref.StubPointerSlotsFromInstructions(xref.Decode(data, sec.Addr)))
	}
	return slots, nil
}

func addDSCResolvedGOTTargets(img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, includeObjCSelectors bool, stderr io.Writer) bool {
	if err := img.ParseGOT(); err != nil {
		progress(stderr, "dsc: failed to parse %s GOT: %v\n", img.Name, err)
		return false
	}
	added := false
	for _, targetAddr := range img.Analysis.GotPointers {
		if addResolvedAddressTarget(targets, globalTargets, targetAddr, targetAddr, includeObjCSelectors) {
			added = true
		}
	}
	return added
}

func addDSCObjCStubTargets(f *dyld.File, img *dyld.CacheImage, targets map[uint64][]targetSpec) {
	if err := f.GetObjCStubsForImage(img.Name); err != nil {
		return
	}
	for stubAddr, stub := range img.ObjC.Stubs {
		if stub != nil && stub.Name == "valueForEntitlement:" {
			addTarget(targets, stubAddr, objcValueForEntitlementTarget())
		}
	}
}

func addResolvedAddressTarget(targets, globalTargets map[uint64][]targetSpec, callTarget, resolvedTarget uint64, includeObjCSelectors bool) bool {
	added := false
	for _, target := range globalTargets[resolvedTarget] {
		if target.Selector != "" && !includeObjCSelectors {
			continue
		}
		addTarget(targets, callTarget, target)
		added = true
	}
	return added
}

func addFilteredGlobalTargets(targets, globalTargets map[uint64][]targetSpec, includeObjCSelectors bool) {
	for addr := range globalTargets {
		addResolvedAddressTarget(targets, globalTargets, addr, addr, includeObjCSelectors)
	}
}

func cloneTargets(in map[uint64][]targetSpec) map[uint64][]targetSpec {
	out := make(map[uint64][]targetSpec, len(in))
	for addr, targets := range in {
		out[addr] = append([]targetSpec(nil), targets...)
	}
	return out
}

func mergeTargets(dst, src map[uint64][]targetSpec) {
	for addr, targets := range src {
		for _, target := range targets {
			addTarget(dst, addr, target)
		}
	}
}

func addTarget(targets map[uint64][]targetSpec, addr uint64, target targetSpec) {
	for _, existing := range targets[addr] {
		if existing.Canonical == target.Canonical {
			return
		}
	}
	targets[addr] = append(targets[addr], target)
	sort.Slice(targets[addr], func(i, j int) bool {
		return targets[addr][i].Canonical < targets[addr][j].Canonical
	})
}

func readDyldFunction(f *dyld.File, fn mtypes.Function) ([]byte, error) {
	uuid, off, err := f.GetOffset(fn.StartAddr)
	if err != nil {
		return nil, err
	}
	return f.ReadBytesForUUID(uuid, int64(off), fn.EndAddr-fn.StartAddr)
}

type dyldTextSection struct {
	start uint64
	end   uint64
	data  []byte
}

type dyldDirectWindow struct {
	start uint64
	data  []byte
}

type dyldFunctionReader struct {
	f        *dyld.File
	sections []dyldTextSection
}

func newDyldFunctionReader(f *dyld.File, img *dyld.CacheImage, m *macho.File) dyldFunctionReader {
	reader := dyldFunctionReader{f: f}
	for _, sec := range m.Sections {
		if sec.Name != "__text" || (sec.Seg != "__TEXT" && sec.Seg != "__TEXT_EXEC") || sec.Size == 0 {
			continue
		}
		data := make([]byte, sec.Size)
		if _, err := img.ReadAtAddr(data, sec.Addr); err != nil {
			continue
		}
		reader.sections = append(reader.sections, dyldTextSection{
			start: sec.Addr,
			end:   sec.Addr + sec.Size,
			data:  data,
		})
	}
	return reader
}

func (r dyldFunctionReader) read(fn mtypes.Function) ([]byte, error) {
	for _, sec := range r.sections {
		if fn.StartAddr < sec.start || fn.EndAddr > sec.end {
			continue
		}
		start := fn.StartAddr - sec.start
		end := fn.EndAddr - sec.start
		return sec.data[start:end], nil
	}
	return readDyldFunction(r.f, fn)
}

func (r dyldFunctionReader) directTargetWindows(targetAddrs xref.TargetSet, funcs []mtypes.Function) []dyldDirectWindow {
	var windows []dyldDirectWindow
	for _, sec := range r.sections {
		fnIdx := sort.Search(len(funcs), func(i int) bool {
			return funcs[i].EndAddr > sec.start
		})
		for off := 0; off+4 <= len(sec.data); off += 4 {
			addr := sec.start + uint64(off)
			for fnIdx < len(funcs) && funcs[fnIdx].EndAddr <= addr {
				fnIdx++
			}
			if fnIdx < len(funcs) && funcs[fnIdx].StartAddr <= addr && addr < funcs[fnIdx].EndAddr {
				continue
			}
			raw := binary.LittleEndian.Uint32(sec.data[off : off+4])
			target, ok := xref.DirectBranchTarget(raw, addr)
			if !ok || !targetAddrs.Has(target) {
				continue
			}
			startOff := off - min(off, xref.DefaultMaxInstructions*4)
			windows = append(windows, dyldDirectWindow{
				start: sec.start + uint64(startOff),
				data:  sec.data[startOff : off+4],
			})
		}
	}
	return windows
}

func sortedFunctions(funcs []mtypes.Function) []mtypes.Function {
	out := append([]mtypes.Function(nil), funcs...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartAddr < out[j].StartAddr
	})
	return out
}

func functionSymbol(m *macho.File, addr uint64) string {
	syms, err := m.FindAddressSymbols(addr)
	if err != nil {
		return ""
	}
	for _, sym := range syms {
		if sym.Name != "" && sym.Name != "<redacted>" {
			return symbols.DemangleSymbolName(sym.Name)
		}
	}
	return ""
}

func imageHasSelector(m *macho.File, selector string) bool {
	if selector == "" || !m.HasObjC() {
		return false
	}
	if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
		for _, sel := range selRefs {
			if sel != nil && sel.Name == selector {
				return true
			}
		}
	}
	if sec := m.Section("__TEXT", "__objc_methname"); sec != nil {
		if data, err := sec.Data(); err == nil {
			return bytes.Contains(data, []byte(selector+"\x00"))
		}
	}
	return false
}

type machoMemory struct {
	m *macho.File
}

func (m machoMemory) ReadPointer(addr uint64) (uint64, error) {
	return m.m.GetPointerAtAddress(addr)
}

func (m machoMemory) ReadUint64(addr uint64) (uint64, error) {
	var buf [8]byte
	if _, err := m.m.ReadAtAddr(buf[:], addr); err != nil {
		return 0, err
	}
	return m.m.ByteOrder.Uint64(buf[:]), nil
}

func (m machoMemory) ReadCString(addr uint64) (string, error) {
	return m.m.GetCString(addr)
}

type dyldMemory struct {
	f             *dyld.File
	boundPointers map[uint64]uint64
}

func (m dyldMemory) ReadPointer(addr uint64) (uint64, error) {
	if ptr := m.boundPointers[addr]; ptr != 0 {
		return ptr, nil
	}
	ptr, err := m.f.ReadPointerAtAddress(addr)
	if err != nil {
		return 0, err
	}
	return m.f.SlideInfo.SlidePointer(ptr), nil
}

func (m dyldMemory) ReadUint64(addr uint64) (uint64, error) {
	uuid, off, err := m.f.GetOffset(addr)
	if err != nil {
		return 0, err
	}
	return m.f.ReadPointerForUUID(uuid, off)
}

func (m dyldMemory) ReadCString(addr uint64) (string, error) {
	return m.f.GetCString(addr)
}

type imageRange struct {
	start uint64
	end   uint64
	image string
}

type imageRanges []imageRange

func kernelImageRanges(m *macho.File) imageRanges {
	bundles, err := kernelcache.GetKexts(m)
	if err != nil {
		return nil
	}
	infos, _ := kernelcache.GetKextInfos(m)
	ranges := make(imageRanges, 0, len(bundles))
	for _, bundle := range bundles {
		name := bundle.ID
		if name == "" {
			name = bundle.Name
		}
		start := bundle.ExecutableLoadAddr
		end := uint64(0)
		moduleIndex := int(bundle.ModuleIndex)
		if moduleIndex < len(infos) {
			if infos[moduleIndex].StartAddr != 0 {
				start = infos[moduleIndex].StartAddr
			}
			end = infos[moduleIndex].StopAddr
		}
		if start == 0 || name == "" {
			continue
		}
		ranges = append(ranges, imageRange{start: start, end: end, image: name})
	}
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})
	for idx := range ranges {
		if ranges[idx].end == 0 && idx+1 < len(ranges) {
			ranges[idx].end = ranges[idx+1].start
		}
	}
	return ranges
}

func (rs imageRanges) imageFor(addr uint64) string {
	for _, r := range rs {
		if r.start <= addr && (r.end == 0 || addr < r.end) {
			return r.image
		}
	}
	return "com.apple.kernel"
}

func progress(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, format, args...)
	}
}
