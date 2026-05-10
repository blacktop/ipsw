package iokit

import (
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/blacktop/ipsw/pkg/symbols"
)

const (
	defaultMaxFunctionInstructions = 320
	defaultMaxVtableSlots          = 240
)

type analyzer struct {
	root       *macho.File
	scanner    *cpp.Scanner
	classes    []cpp.Class
	infos      []*classInfo
	byName     map[string][]*classInfo
	symbolMap  map[uint64]string
	symCache   map[uint64]string
	methods    map[methodCacheKey]methodAnalysis
	ucRefs     map[uint64][]string
	stderr     io.Writer
	maxInst    int
	maxSlots   int
	userClient map[string]struct{}
}

type classInfo struct {
	cpp.Class
	index      int
	family     string
	isService  bool
	userClient bool
}

func Scan(root *macho.File, conf Config) ([]Record, error) {
	if root == nil {
		return nil, fmt.Errorf("nil kernelcache")
	}
	if conf.MaxFunctionInstructions == 0 {
		conf.MaxFunctionInstructions = defaultMaxFunctionInstructions
	}
	if conf.MaxVtableSlots == 0 {
		conf.MaxVtableSlots = defaultMaxVtableSlots
	}

	scanner := cpp.NewScanner(root, cpp.Config{})
	classes, err := scanner.Scan()
	if err != nil {
		return nil, fmt.Errorf("cpp scan: %w", err)
	}

	a := newAnalyzer(root, scanner, classes, conf)
	userClients := a.userClientClasses()
	if len(userClients) == 0 {
		return nil, ErrNoIOUserClients
	}
	progress(conf.Stderr, "kernel iokit-methods: discovered %d IOUserClient subclasses\n", len(userClients))

	records, err := a.methodRecords(userClients)
	if err != nil {
		return nil, err
	}
	records = append(records, a.serviceClientRecords()...)
	records = dedupeRecords(records)
	SortRecords(records)
	return records, nil
}

func newAnalyzer(root *macho.File, scanner *cpp.Scanner, classes []cpp.Class, conf Config) *analyzer {
	a := &analyzer{
		root:       root,
		scanner:    scanner,
		classes:    classes,
		byName:     make(map[string][]*classInfo),
		symbolMap:  loadKernelSymbolMap(conf.Kernelcache, conf.Stderr),
		symCache:   make(map[uint64]string),
		methods:    make(map[methodCacheKey]methodAnalysis),
		ucRefs:     make(map[uint64][]string),
		stderr:     conf.Stderr,
		maxInst:    conf.MaxFunctionInstructions,
		maxSlots:   conf.MaxVtableSlots,
		userClient: make(map[string]struct{}),
	}
	a.buildClassInfos()
	return a
}

func (a *analyzer) buildClassInfos() {
	a.infos = make([]*classInfo, 0, len(a.classes))
	for idx := range a.classes {
		info := &classInfo{
			Class: a.classes[idx],
			index: idx,
		}
		if reachesClass(a.classes, idx, "IOUserClient2022") {
			info.family = "IOUserClient2022"
		} else if reachesClass(a.classes, idx, "IOUserClient") {
			info.family = "IOUserClient"
		}
		info.userClient = info.family != "" &&
			info.Name != "IOUserClient" &&
			info.Name != "IOUserClient2022"
		info.isService = reachesClass(a.classes, idx, "IOService") && info.Name != "IOService"
		a.infos = append(a.infos, info)
		a.byName[info.Name] = append(a.byName[info.Name], info)
		if info.userClient {
			a.userClient[info.Name] = struct{}{}
		}
	}
	for _, infos := range a.byName {
		sort.SliceStable(infos, func(i, j int) bool {
			if infos[i].Bundle != infos[j].Bundle {
				return infos[i].Bundle < infos[j].Bundle
			}
			return infos[i].MetaPtr < infos[j].MetaPtr
		})
	}
}

func reachesClass(classes []cpp.Class, idx int, target string) bool {
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

func (a *analyzer) userClientClasses() []*classInfo {
	out := make([]*classInfo, 0, 128)
	for _, info := range a.infos {
		if info.userClient {
			out = append(out, info)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Bundle != out[j].Bundle {
			return out[i].Bundle < out[j].Bundle
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (a *analyzer) methodRecords(userClients []*classInfo) ([]Record, error) {
	slots, err := a.externalMethodSlots(userClients)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(userClients))
	for _, info := range userClients {
		slot, ok := slots[info.family]
		if !ok {
			records = append(records, a.unknownMethodRecord(info, 0, "vtable_unresolved"))
			continue
		}
		entry, ok := a.scanner.VtableEntry(info.Class, slot)
		if !ok || entry.Address == 0 {
			records = append(records, a.unknownMethodRecord(info, 0, "vtable_unresolved"))
			continue
		}
		analysis := a.analyzeExternalMethod(entry.Address, dispatchKindHintForFamily(info.family))
		switch analysis.kind {
		case DispatchExternalMethod, DispatchExternalMethod2022:
			recs, err := a.dispatchRecords(info, analysis)
			if err != nil {
				return nil, err
			}
			records = append(records, recs...)
		case DispatchSwitch:
			records = append(records, a.switchRecords(info, analysis)...)
		default:
			note := analysis.note
			if note == "" {
				note = "indirect"
			}
			records = append(records, a.unknownMethodRecord(info, entry.Address, note))
		}
	}
	return records, nil
}

func (a *analyzer) externalMethodSlots(userClients []*classInfo) (map[string]int, error) {
	symbolSlots := make(map[string]map[int]int)
	for _, info := range userClients {
		for _, entry := range a.scanner.VtableEntries(info.Class, a.maxSlots) {
			if isNamedMethod(a.symbolName(entry.Address), "externalMethod") {
				addSlot(symbolSlots, info.family, entry.Index)
			}
		}
	}

	out := make(map[string]int)
	for family, slots := range symbolSlots {
		slot, err := chooseSlot(family, slots, "symbol")
		if err != nil {
			return nil, err
		}
		out[family] = slot
	}

	patternSlots := make(map[string]map[int]int)
	for _, info := range userClients {
		if _, ok := out[info.family]; ok {
			continue
		}
		for _, entry := range a.scanner.VtableEntries(info.Class, a.maxSlots) {
			analysis := a.analyzeExternalMethod(entry.Address, dispatchKindHintForFamily(info.family))
			if analysis.kind == DispatchExternalMethod ||
				analysis.kind == DispatchExternalMethod2022 ||
				analysis.kind == DispatchSwitch {
				addSlot(patternSlots, info.family, entry.Index)
			}
		}
	}
	for family, slots := range patternSlots {
		if _, ok := out[family]; ok {
			continue
		}
		slot, err := chooseSlot(family, slots, "pattern")
		if err != nil {
			return nil, err
		}
		out[family] = slot
	}
	return out, nil
}

func addSlot(slots map[string]map[int]int, family string, slot int) {
	if family == "" || slot < 0 {
		return
	}
	if slots[family] == nil {
		slots[family] = make(map[int]int)
	}
	slots[family][slot]++
}

func chooseSlot(family string, slots map[int]int, source string) (int, error) {
	if len(slots) == 0 {
		return -1, fmt.Errorf("no %s externalMethod slot candidates for %s", source, family)
	}
	type candidate struct {
		slot  int
		count int
	}
	candidates := make([]candidate, 0, len(slots))
	for slot, count := range slots {
		candidates = append(candidates, candidate{slot: slot, count: count})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count != candidates[j].count {
			return candidates[i].count > candidates[j].count
		}
		return candidates[i].slot < candidates[j].slot
	})
	if len(candidates) > 1 && candidates[0].count == candidates[1].count {
		return -1, fmt.Errorf("externalMethod vtable slot differs across %s hierarchy (%s candidates: %v)", family, source, slots)
	}
	return candidates[0].slot, nil
}

func isNamedMethod(symbolName string, method string) bool {
	if symbolName == "" {
		return false
	}
	return strings.Contains(symbolName, "::"+method+"(") ||
		strings.Contains(symbolName, "::"+method+" ")
}

func (a *analyzer) unknownMethodRecord(info *classInfo, methodAddr uint64, note string) Record {
	extra := map[string]string{"slice_notes": note}
	return Record{
		Kind:              KindMethod,
		Class:             info.Name,
		Bundle:            info.Bundle,
		Selector:          -1,
		MethodAddr:        hexAddr(methodAddr),
		MethodSymbol:      a.symbolName(methodAddr),
		DispatchKind:      DispatchUnknown,
		ScalarInputCount:  -1,
		ScalarOutputCount: -1,
		StructInputSize:   -1,
		StructOutputSize:  -1,
		Flags:             -1,
		Resolved:          false,
		Extra:             extra,
	}
}

func (a *analyzer) symbolName(addr uint64) string {
	if addr == 0 {
		return ""
	}
	if cached, ok := a.symCache[addr]; ok {
		return cached
	}
	if name := a.symbolMap[addr]; name != "" {
		name = symbols.DemangleSymbolName(name)
		a.symCache[addr] = name
		return name
	}
	if name := a.scanner.SymbolName(addr); name != "" {
		a.symCache[addr] = name
		return name
	}
	if body, err := a.scanner.FunctionBodyAt(addr); err == nil && body.Function.StartAddr != addr {
		if name := a.symbolMap[body.Function.StartAddr]; name != "" {
			name = symbols.DemangleSymbolName(name)
			a.symCache[addr] = name
			return name
		}
		if name := a.scanner.SymbolName(body.Function.StartAddr); name != "" {
			a.symCache[addr] = name
			return name
		}
	}
	a.symCache[addr] = ""
	return ""
}

func loadKernelSymbolMap(path string, stderr io.Writer) map[uint64]string {
	out := make(map[uint64]string)
	if path == "" {
		return out
	}
	smap := signature.NewSymbolMap()
	for _, candidate := range kernelSymbolMapCandidates(path) {
		if err := smap.LoadJSON(candidate); err == nil {
			maps.Copy(out, smap)
			progress(stderr, "kernel iokit-methods: loaded symbol map %s\n", candidate)
			return out
		}
	}
	return out
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

func (a *analyzer) serviceClientRecords() []Record {
	records := a.personalityRecords()
	records = append(records, a.newUserClientRecords()...)
	return records
}

func classBundle(infos []*classInfo) string {
	if len(infos) == 0 {
		return ""
	}
	return infos[0].Bundle
}

func classExists(infos []*classInfo) bool {
	return len(infos) > 0
}

func hexAddr(addr uint64) string {
	if addr == 0 {
		return "0x0"
	}
	return fmt.Sprintf("%#x", addr)
}

func dedupeRecords(records []Record) []Record {
	if len(records) < 2 {
		return records
	}
	SortRecords(records)
	out := records[:0]
	var last string
	for _, rec := range records {
		key := recordKey(rec)
		if key == last {
			continue
		}
		out = append(out, rec)
		last = key
	}
	return out
}

func recordKey(r Record) string {
	return strings.Join([]string{
		r.Kind,
		r.Bundle,
		r.Class,
		fmt.Sprint(r.Selector),
		r.MethodAddr,
		r.DispatchKind,
		r.ServiceBundle,
		r.ServiceClass,
		r.UserClientBundle,
		r.UserClientClass,
		r.Source,
		extraSortString(r.Extra),
	}, "\x00")
}

func progress(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, format, args...)
	}
}

func rootForPrelink(root *macho.File) *macho.File {
	if root == nil || root.FileHeader.Type != mtypes.MH_FILESET {
		return root
	}
	if kernelFile, err := root.GetFileSetFileByName("com.apple.kernel"); err == nil {
		return kernelFile
	}
	if kernelFile, err := root.GetFileSetFileByName("kernel"); err == nil {
		return kernelFile
	}
	return root
}

func kextBundles(root *macho.File) []kernelcache.CFBundle {
	if root == nil {
		return nil
	}
	if bundles, err := kernelcache.GetKexts(root); err == nil {
		return bundles
	}
	if kernelRoot := rootForPrelink(root); kernelRoot != root {
		if bundles, err := kernelcache.GetKexts(kernelRoot); err == nil {
			return bundles
		}
	}
	return nil
}
