package nsxpc

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/ipsw/pkg/dyld"
)

var (
	ErrNoObjCProtocols     = errors.New("no Objective-C protocol metadata found")
	ErrNoResolvedInterface = errors.New("no resolved NSXPCInterface interfaceWithProtocol callsites found")
)

type Config struct {
	DSC    string
	Stderr io.Writer
}

type scanner struct {
	f             *dyld.File
	stderr        io.Writer
	classNames    map[uint64]string
	protocols     map[string]objc.Protocol
	globalTargets map[uint64][]targetSpec
	directTargets map[string]map[uint64][]targetSpec
}

type imageMeta struct {
	classNames       map[uint64]string
	protocolNames    map[uint64]string
	hasNSXPCSelector bool
	initMethods      map[uint64][]string
}

func Scan(conf Config) ([]Record, error) {
	f, err := dyld.Open(conf.DSC)
	if err != nil {
		return nil, fmt.Errorf("failed to open DSC: %w", err)
	}
	defer f.Close()
	if !f.IsArm64() {
		return nil, fmt.Errorf("DSC must be arm64/arm64e")
	}

	s := &scanner{
		f:             f,
		stderr:        conf.Stderr,
		classNames:    make(map[uint64]string),
		protocols:     make(map[string]objc.Protocol),
		globalTargets: make(map[uint64][]targetSpec),
		directTargets: make(map[string]map[uint64][]targetSpec),
	}
	if _, err := f.GetAllObjCSelectors(false); err != nil {
		progress(conf.Stderr, "dsc: failed to load Objective-C selector table: %v\n", err)
	}
	if _, err := f.GetAllObjCProtocols(false); err != nil {
		progress(conf.Stderr, "dsc: failed to load Objective-C protocol table: %v\n", err)
	}

	s.collectIndexes()
	if len(s.protocols) == 0 {
		return nil, ErrNoObjCProtocols
	}

	var records []Record
	for _, img := range f.Images {
		recs, err := s.scanImage(img)
		if err != nil {
			progress(conf.Stderr, "dsc: failed to scan %s: %v\n", img.Name, err)
			img.Free()
			continue
		}
		records = append(records, recs...)
		img.Free()
	}

	namedProtocols := make(map[string]struct{})
	resolvedInterfaces := 0
	for _, rec := range records {
		if rec.Kind == KindInterface && rec.Resolved && rec.Protocol != "" {
			namedProtocols[rec.Protocol] = struct{}{}
			resolvedInterfaces++
		}
	}
	if resolvedInterfaces == 0 {
		return nil, ErrNoResolvedInterface
	}
	records = append(records, s.protocolMethodRecords(namedProtocols)...)
	SortRecords(records)
	return records, nil
}

func (s *scanner) collectIndexes() {
	for _, img := range s.f.Images {
		m, err := img.GetMacho()
		if err != nil {
			progress(s.stderr, "dsc: failed to parse %s during index: %v\n", img.Name, err)
			img.Free()
			continue
		}
		targets := collectMachOTargets(m)
		addDSCExportTrieTargets(s.f, img, targets)
		addRuntimeHelperTargets(s.f, img, targets, s.stderr)
		if len(targets) > 0 {
			s.directTargets[img.Name] = targets
			mergeTargets(s.globalTargets, targets)
		}
		if protocols, err := m.GetObjCProtocols(); err == nil {
			for _, proto := range protocols {
				if proto.Name != "" {
					s.protocols[proto.Name] = proto
				}
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			progress(s.stderr, "dsc: failed to read protocols for %s: %v\n", img.Name, err)
		}
		if classes, err := m.GetObjCClasses(); err == nil {
			for _, cls := range classes {
				addClassName(s.classNames, cls.ClassPtr, &cls)
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			progress(s.stderr, "dsc: failed to read classes for %s during index: %v\n", img.Name, err)
		}
		img.Free()
	}
	s.addKnownRuntimeSymbols()
	s.collectRuntimeStubs()
	progress(s.stderr, "dsc: indexed %d Objective-C protocols and %d runtime target addresses\n", len(s.protocols), len(s.globalTargets))
}

func (s *scanner) addKnownRuntimeSymbols() {
	for _, name := range []string{
		"_objc_msgSend",
		"_objc_getClass",
		"_objc_lookUpClass",
		"_objc_getRequiredClass",
		"_objc_getProtocol",
		"_objc_opt_class",
	} {
		addr, img, err := s.f.GetSymbolAddress(name)
		if err != nil || addr == 0 {
			continue
		}
		target, ok := matchRuntimeTarget(name)
		if !ok {
			continue
		}
		addTarget(s.globalTargets, addr, target)
		if img != nil {
			if s.directTargets[img.Name] == nil {
				s.directTargets[img.Name] = make(map[uint64][]targetSpec)
			}
			addTarget(s.directTargets[img.Name], addr, target)
		}
	}
}

func (s *scanner) collectRuntimeStubs() {
	for _, img := range s.f.Images {
		targets := cloneTargets(s.directTargets[img.Name])
		before := countTargets(targets)
		addResolvedHelperTargets(s.f, img, targets, s.globalTargets, nil)
		addResolvedStubTargets(img, targets, s.globalTargets, nil)
		if countTargets(targets) > before {
			s.directTargets[img.Name] = targets
			mergeTargets(s.globalTargets, targets)
		}
		img.Free()
	}
}

func (s *scanner) scanImage(img *dyld.CacheImage) ([]Record, error) {
	m, err := img.GetMacho()
	if err != nil {
		return nil, err
	}
	meta := s.imageMeta(img, m)
	if !meta.hasNSXPCSelector && len(meta.initMethods) == 0 {
		return nil, nil
	}

	targets := cloneTargets(s.directTargets[img.Name])
	addResolvedHelperTargets(s.f, img, targets, s.globalTargets, s.stderr)
	addResolvedStubTargets(img, targets, s.globalTargets, s.stderr)
	addResolvedGOTTargets(img, targets, s.globalTargets, s.stderr)
	addObjCStubTargets(s.f, img, targets)
	addFilteredGlobalTargets(targets, s.globalTargets)
	if len(targets) == 0 {
		return nil, nil
	}
	progress(s.stderr, "dsc: scanning %s (%d target refs)\n", img.Name, len(targets))

	mem := dscMemory{f: s.f, classes: meta.classNames, globalClasses: s.classNames, protocols: meta.protocolNames}
	var records []Record
	for _, fn := range sortedFunctions(m.GetFunctions()) {
		data, err := readDyldFunction(s.f, fn)
		if err != nil {
			progress(s.stderr, "dsc: failed to read %s function %#x: %v\n", img.Name, fn.StartAddr, err)
			continue
		}
		if meta.hasNSXPCSelector {
			records = append(records, scanFunction(functionScan{
				image:   img.Name,
				data:    data,
				start:   fn.StartAddr,
				targets: targets,
				mem:     mem,
			})...)
		}
		if classNames := meta.initMethods[fn.StartAddr]; len(classNames) > 0 {
			records = append(records, scanFunction(functionScan{
				image:      img.Name,
				classNames: classNames,
				data:       data,
				start:      fn.StartAddr,
				targets:    targets,
				mem:        mem,
				secureOnly: true,
			})...)
		}
	}
	return records, nil
}

func (s *scanner) imageMeta(img *dyld.CacheImage, m *macho.File) imageMeta {
	meta := imageMeta{
		classNames:    make(map[uint64]string),
		protocolNames: make(map[uint64]string),
		initMethods:   make(map[uint64][]string),
	}
	if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
		for _, sel := range selRefs {
			if sel != nil {
				if isNSXPCSelector(sel.Name) {
					meta.hasNSXPCSelector = true
				}
			}
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		progress(s.stderr, "dsc: failed to read selectors for %s: %v\n", img.Name, err)
	}
	if err := s.f.GetObjCStubsForImage(img.Name); err == nil {
		for _, stub := range img.ObjC.Stubs {
			if stub != nil {
				if isNSXPCSelector(stub.Name) {
					meta.hasNSXPCSelector = true
				}
			}
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		progress(s.stderr, "dsc: failed to read ObjC stubs for %s: %v\n", img.Name, err)
	}
	if classRefs, err := m.GetObjCClassReferences(); err == nil {
		for loc, cls := range classRefs {
			addClassName(meta.classNames, loc, cls)
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		progress(s.stderr, "dsc: failed to read class refs for %s: %v\n", img.Name, err)
	}
	addBoundClassPointers(m, meta.classNames)
	if protoRefs, err := m.GetObjCProtoReferences(); err == nil {
		for loc, proto := range protoRefs {
			addProtocolName(meta.protocolNames, loc, proto)
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		progress(s.stderr, "dsc: failed to read protocol refs for %s: %v\n", img.Name, err)
	}
	funcs := sortedFunctions(m.GetFunctions())
	if classes, err := m.GetObjCClasses(); err == nil {
		for _, cls := range classes {
			addClassName(meta.classNames, cls.ClassPtr, &cls)
			for _, method := range cls.InstanceMethods {
				if method.Name != "initWithCoder:" || method.ImpVMAddr == 0 {
					continue
				}
				fn, ok := functionContaining(funcs, method.ImpVMAddr)
				if !ok {
					continue
				}
				meta.initMethods[fn.StartAddr] = append(meta.initMethods[fn.StartAddr], cls.Name)
			}
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		progress(s.stderr, "dsc: failed to read classes for %s: %v\n", img.Name, err)
	}
	for fn, classes := range meta.initMethods {
		meta.initMethods[fn] = sortedStrings(classes)
	}
	return meta
}

func addBoundClassPointers(m *macho.File, classes map[uint64]string) {
	for _, sec := range m.Sections {
		if sec.Size == 0 || sec.Size%8 != 0 {
			continue
		}
		switch sec.Name {
		case "__auth_ptr", "__got", "__auth_got", "__objc_classrefs", "__objc_superrefs":
		default:
			continue
		}
		for off := uint64(0); off < sec.Size; off += 8 {
			loc := sec.Addr + off
			bind, err := m.GetBindName(loc)
			if err != nil {
				continue
			}
			if name := classNameFromSymbol(bind); name != "" {
				classes[loc] = name
			}
		}
	}
}

func addClassName(dst map[uint64]string, addr uint64, cls *objc.Class) {
	if cls == nil || cls.Name == "" {
		return
	}
	dst[addr] = cls.Name
	if cls.ClassPtr != 0 {
		dst[cls.ClassPtr] = cls.Name
	}
}

func addProtocolName(dst map[uint64]string, addr uint64, proto *objc.Protocol) {
	if proto == nil || proto.Name == "" {
		return
	}
	dst[addr] = proto.Name
	if proto.Ptr != 0 {
		dst[proto.Ptr] = proto.Name
	}
}

func (s *scanner) protocolMethodRecords(named map[string]struct{}) []Record {
	var records []Record
	for name := range named {
		proto, ok := s.protocols[name]
		if !ok {
			continue
		}
		seen := make(map[protocolMethodKey]struct{})
		records = append(records, s.methodRecordsForProtocolTree(proto.Name, proto, seen, make(map[string]bool))...)
	}
	return records
}

type protocolMethodKey struct {
	selector     string
	instance     bool
	required     bool
	typeEncoding string
}

func (s *scanner) methodRecordsForProtocolTree(protocol string, proto objc.Protocol, seen map[protocolMethodKey]struct{}, visiting map[string]bool) []Record {
	visitKey := protocolVisitKey(proto)
	if visitKey != "" {
		if visiting[visitKey] {
			return nil
		}
		visiting[visitKey] = true
		defer delete(visiting, visitKey)
	}

	var records []Record
	appendMethodRecords(&records, seen, protocol, true, true, proto.InstanceMethods)
	appendMethodRecords(&records, seen, protocol, false, true, proto.ClassMethods)
	appendMethodRecords(&records, seen, protocol, true, false, proto.OptionalInstanceMethods)
	appendMethodRecords(&records, seen, protocol, false, false, proto.OptionalClassMethods)

	for _, parent := range proto.Prots {
		if indexed, ok := s.protocols[parent.Name]; ok {
			parent = indexed
		}
		records = append(records, s.methodRecordsForProtocolTree(protocol, parent, seen, visiting)...)
	}

	return records
}

func protocolVisitKey(proto objc.Protocol) string {
	if proto.Name != "" {
		return proto.Name
	}
	if proto.Ptr != 0 {
		return fmt.Sprintf("%#x", proto.Ptr)
	}
	return ""
}

func appendMethodRecords(records *[]Record, seen map[protocolMethodKey]struct{}, protocol string, instance, required bool, methods []objc.Method) {
	for _, method := range methods {
		if method.Name == "" {
			continue
		}
		key := protocolMethodKey{
			selector:     method.Name,
			instance:     instance,
			required:     required,
			typeEncoding: method.Types,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		info := decodeMethodTypeClasses(method.Types)
		*records = append(*records, Record{
			Kind:         KindProtocolMethod,
			Protocol:     protocol,
			Selector:     method.Name,
			Required:     required,
			Instance:     instance,
			TypeEncoding: method.Types,
			ParamClasses: info.ParamClasses,
			ReturnClass:  info.ReturnClass,
			Resolved:     true,
			Extra:        map[string]string{},
		})
	}
}

func collectMachOTargets(m *macho.File) map[uint64][]targetSpec {
	targets := make(map[uint64][]targetSpec)
	add := func(addr uint64, name string) {
		if addr == 0 {
			return
		}
		if target, ok := matchRuntimeTarget(name); ok {
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

func addDSCExportTrieTargets(f *dyld.File, img *dyld.CacheImage, targets map[uint64][]targetSpec) {
	exports, err := f.GetExportTrieSymbols(img)
	if err != nil {
		return
	}
	for _, sym := range exports {
		if sym.Address == 0 {
			continue
		}
		if target, ok := matchRuntimeTarget(sym.Name); ok {
			addTarget(targets, sym.Address, target)
		}
	}
}

func addResolvedStubTargets(img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, stderr io.Writer) {
	if err := img.ParseStubs(); err != nil {
		progress(stderr, "dsc: failed to parse %s stubs: %v\n", img.Name, err)
		return
	}
	for stub, targetAddr := range img.Analysis.SymbolStubs {
		addResolvedAddressTarget(targets, globalTargets, stub, targetAddr)
	}
}

func addResolvedHelperTargets(f *dyld.File, img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, stderr io.Writer) {
	if err := img.ParseHelpers(); err != nil {
		progress(stderr, "dsc: failed to parse %s helper stubs: %v\n", img.Name, err)
		return
	}
	for helper, targetAddr := range img.Analysis.Helpers {
		if addResolvedAddressTarget(targets, globalTargets, helper, targetAddr) {
			continue
		}
		if target, ok := runtimeTargetAtAddress(f, targetAddr); ok {
			addTarget(targets, helper, target)
		}
	}
}

func addRuntimeHelperTargets(f *dyld.File, img *dyld.CacheImage, targets map[uint64][]targetSpec, stderr io.Writer) {
	if err := img.ParseHelpers(); err != nil {
		if !errors.Is(err, macho.ErrMachOSectionNotFound) {
			progress(stderr, "dsc: failed to parse %s helper stubs during index: %v\n", img.Name, err)
		}
		return
	}
	for helper, targetAddr := range img.Analysis.Helpers {
		if target, ok := runtimeTargetAtAddress(f, targetAddr); ok {
			addTarget(targets, helper, target)
		}
	}
}

func runtimeTargetAtAddress(f *dyld.File, addr uint64) (targetSpec, bool) {
	if sym, ok := f.AddressToSymbol.Get(addr); ok {
		if target, ok := matchRuntimeTarget(sym); ok {
			return target, true
		}
	}
	img, err := f.GetImageContainingTextAddr(addr)
	if err != nil {
		return targetSpec{}, false
	}
	if name, err := img.FindLocalSymbolAtAddr(addr); err == nil && name != "" {
		return matchRuntimeTarget(name)
	}
	if err := img.ParsePublicSymbols(false); err == nil {
		if sym, ok := f.AddressToSymbol.Get(addr); ok {
			return matchRuntimeTarget(sym)
		}
	}
	if err := img.ParseLocalSymbols(false); err == nil {
		if sym, ok := f.AddressToSymbol.Get(addr); ok {
			return matchRuntimeTarget(sym)
		}
		if name, err := img.FindLocalSymbolAtAddr(addr); err == nil && name != "" {
			return matchRuntimeTarget(name)
		}
	}
	return targetSpec{}, false
}

func addResolvedGOTTargets(img *dyld.CacheImage, targets, globalTargets map[uint64][]targetSpec, stderr io.Writer) {
	if err := img.ParseGOT(); err != nil {
		progress(stderr, "dsc: failed to parse %s GOT: %v\n", img.Name, err)
		return
	}
	for _, targetAddr := range img.Analysis.GotPointers {
		addResolvedAddressTarget(targets, globalTargets, targetAddr, targetAddr)
	}
}

func addObjCStubTargets(f *dyld.File, img *dyld.CacheImage, targets map[uint64][]targetSpec) {
	if err := f.GetObjCStubsForImage(img.Name); err != nil {
		return
	}
	for stubAddr, stub := range img.ObjC.Stubs {
		if stub == nil {
			continue
		}
		if target, ok := targetForObjCStubSelector(stub.Name); ok {
			addTarget(targets, stubAddr, target)
		}
	}
}

func addResolvedAddressTarget(targets, globalTargets map[uint64][]targetSpec, callTarget, resolvedTarget uint64) bool {
	added := false
	for _, target := range globalTargets[resolvedTarget] {
		addTarget(targets, callTarget, target)
		added = true
	}
	return added
}

func addFilteredGlobalTargets(targets, globalTargets map[uint64][]targetSpec) {
	for addr := range globalTargets {
		addResolvedAddressTarget(targets, globalTargets, addr, addr)
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
		if existing.Kind == target.Kind && existing.Selector == target.Selector && existing.Name == target.Name {
			return
		}
	}
	targets[addr] = append(targets[addr], target)
	sort.Slice(targets[addr], func(i, j int) bool {
		if targets[addr][i].Kind != targets[addr][j].Kind {
			return targets[addr][i].Kind < targets[addr][j].Kind
		}
		if targets[addr][i].Selector != targets[addr][j].Selector {
			return targets[addr][i].Selector < targets[addr][j].Selector
		}
		return targets[addr][i].Name < targets[addr][j].Name
	})
}

func countTargets(targets map[uint64][]targetSpec) int {
	count := 0
	for _, specs := range targets {
		count += len(specs)
	}
	return count
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

func functionContaining(funcs []mtypes.Function, addr uint64) (mtypes.Function, bool) {
	idx := sort.Search(len(funcs), func(i int) bool {
		return funcs[i].StartAddr > addr
	})
	if idx == 0 {
		return mtypes.Function{}, false
	}
	fn := funcs[idx-1]
	return fn, fn.StartAddr <= addr && addr < fn.EndAddr
}

type dscMemory struct {
	f             *dyld.File
	classes       map[uint64]string
	globalClasses map[uint64]string
	protocols     map[uint64]string
}

func (m dscMemory) ReadPointer(addr uint64) (uint64, error) {
	ptr, err := m.f.ReadPointerAtAddress(addr)
	if err != nil {
		return 0, err
	}
	return m.f.SlideInfo.SlidePointer(ptr), nil
}

func (m dscMemory) ReadUint64(addr uint64) (uint64, error) {
	uuid, off, err := m.f.GetOffset(addr)
	if err != nil {
		return 0, err
	}
	return m.f.ReadPointerForUUID(uuid, off)
}

func (m dscMemory) ReadCString(addr uint64) (string, error) {
	return m.f.GetCString(addr)
}

func (m dscMemory) ClassName(addr uint64) (string, bool) {
	if name, ok := m.classes[addr]; ok {
		return name, true
	}
	if name, ok := m.globalClasses[addr]; ok {
		return name, true
	}
	if sym, ok := m.f.AddressToSymbol.Get(addr); ok {
		if name := classNameFromSymbol(sym); name != "" {
			m.classes[addr] = name
			return name, true
		}
	}
	return "", false
}

func (m dscMemory) ClassPointerName(addr uint64) (name string, ok bool) {
	if name, ok := m.ClassName(addr); ok {
		return name, true
	}
	return "", false
}

func (m dscMemory) ProtocolName(addr uint64) (string, bool) {
	name, ok := m.protocols[addr]
	return name, ok
}

func progress(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, format, args...)
	}
}

func classNameFromSymbol(sym string) string {
	sym = strings.TrimSpace(sym)
	if idx := strings.Index(sym, " ; "); idx >= 0 {
		sym = sym[:idx]
	}
	matched := false
	for _, prefix := range []string{
		"class_",
		"_ptr.",
		"ptr.",
		"_OBJC_CLASS_$_",
		"OBJC_CLASS_$_",
		"__OBJC_CLASS_$_",
	} {
		if after, ok := strings.CutPrefix(sym, prefix); ok {
			sym = after
			matched = true
			break
		}
	}
	if !matched || sym == "" || strings.HasPrefix(sym, "0x") || strings.ContainsAny(sym, " ()[]{}") {
		return ""
	}
	return sym
}
