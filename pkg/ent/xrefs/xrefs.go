package xrefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/blacktop/ipsw/pkg/symbols"
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
	if len(targets) == 0 {
		progress(stderr, "kernelcache: no entitlement-check target symbols found\n")
		return nil, 0, nil
	}
	progress(stderr, "kernelcache: found %d target addresses\n", len(targets))

	ranges := kernelImageRanges(m)
	mem := machoMemory{m: m}
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
			mem:          mem,
		})...)
	}
	SortRecords(records)
	return records, len(targets), nil
}

func scanKernelFileset(root *macho.File, symbolicatedTargets map[uint64][]targetSpec, stderr io.Writer) ([]Record, int, error) {
	globalTargets := make(map[uint64][]targetSpec)
	entries := root.FileSets()
	for _, entry := range entries {
		m, err := root.GetFileSetFileByName(entry.EntryID)
		if err != nil {
			progress(stderr, "kernelcache: failed to parse fileset entry %s: %v\n", entry.EntryID, err)
			continue
		}
		mergeTargets(globalTargets, collectMachOTargets(SourceKernelcache, m))
	}
	mergeTargets(globalTargets, symbolicatedTargets)
	if len(globalTargets) == 0 {
		progress(stderr, "kernelcache: no entitlement-check target symbols found\n")
		return nil, 0, nil
	}
	progress(stderr, "kernelcache: found %d fileset target addresses\n", len(globalTargets))

	var records []Record
	for _, entry := range entries {
		m, err := root.GetFileSetFileByName(entry.EntryID)
		if err != nil {
			progress(stderr, "kernelcache: failed to parse fileset entry %s: %v\n", entry.EntryID, err)
			continue
		}
		targets := cloneTargets(globalTargets)
		mem := machoMemory{m: m}
		for _, fn := range sortedFunctions(m.GetFunctions()) {
			data, err := m.GetFunctionData(fn)
			if err != nil {
				progress(stderr, "kernelcache: failed to read %s function %#x: %v\n", entry.EntryID, fn.StartAddr, err)
				continue
			}
			records = append(records, scanFunction(functionScan{
				source:       SourceKernelcache,
				image:        entry.EntryID,
				callerSymbol: functionSymbol(m, fn.StartAddr),
				data:         data,
				start:        fn.StartAddr,
				targets:      targets,
				mem:          mem,
			})...)
		}
	}
	SortRecords(records)
	return records, len(globalTargets), nil
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
	progress(stderr, "dsc: found %d global target addresses\n", len(globalTargets))
	if _, err := f.GetAllObjCSelectors(false); err != nil {
		progress(stderr, "dsc: failed to load Objective-C selector table: %v\n", err)
	}

	mem := dyldMemory{f: f}
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
		addDSCResolvedStubTargets(img, targets, globalTargets, includeObjCSelectors, stderr)
		addDSCResolvedGOTTargets(img, targets, globalTargets, includeObjCSelectors, stderr)
		addDSCObjCStubTargets(f, img, targets)
		if len(targets) > 0 || includeObjCSelectors {
			addFilteredGlobalTargets(targets, globalTargets, includeObjCSelectors)
		}
		if len(targets) == 0 {
			img.Free()
			continue
		}
		progress(stderr, "dsc: scanning %s (%d target refs)\n", img.Name, len(targets))
		for _, fn := range sortedFunctions(m.GetFunctions()) {
			data, err := readDyldFunction(f, fn)
			if err != nil {
				progress(stderr, "dsc: failed to read %s function %#x: %v\n", img.Name, fn.StartAddr, err)
				continue
			}
			records = append(records, scanFunction(functionScan{
				source:       SourceDSC,
				image:        img.Name,
				callerSymbol: functionSymbol(m, fn.StartAddr),
				data:         data,
				start:        fn.StartAddr,
				targets:      targets,
				mem:          mem,
			})...)
		}
		img.Free()
	}
	SortRecords(records)
	return records, len(globalTargets), nil
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
	return targets
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

func addDSCResolvedStubTargets(img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, includeObjCSelectors bool, stderr io.Writer) {
	if err := img.ParseStubs(); err != nil {
		progress(stderr, "dsc: failed to parse %s stubs: %v\n", img.Name, err)
		return
	}
	for stub, targetAddr := range img.Analysis.SymbolStubs {
		addResolvedAddressTarget(targets, globalTargets, stub, targetAddr, includeObjCSelectors)
	}
}

func addDSCResolvedGOTTargets(img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, includeObjCSelectors bool, stderr io.Writer) {
	if err := img.ParseGOT(); err != nil {
		progress(stderr, "dsc: failed to parse %s GOT: %v\n", img.Name, err)
		return
	}
	for _, targetAddr := range img.Analysis.GotPointers {
		addResolvedAddressTarget(targets, globalTargets, targetAddr, targetAddr, includeObjCSelectors)
	}
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
	f *dyld.File
}

func (m dyldMemory) ReadPointer(addr uint64) (uint64, error) {
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
