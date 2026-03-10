package cpp

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func normalizeEntryID(entry string) string {
	switch strings.TrimSpace(entry) {
	case "", "kernel", "__kernel__", kernelBundleName:
		return kernelBundleName
	default:
		return entry
	}
}

func validKernelPointer(ptr uint64) bool {
	return ptr >= kernelAddrFloor
}

func validMetaPointer(ptr uint64) bool {
	return ptr >= kernelAddrFloor && ptr%8 == 0
}

func addSignedOffset(addr uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		return addr + uint64(offset), true
	}
	neg := uint64(-offset)
	if neg > addr {
		return 0, false
	}
	return addr - neg, true
}

func decodeBLTarget(addr uint64, instr uint32) (uint64, bool) {
	if (instr >> 26) != 0b100101 {
		return 0, false
	}
	imm26 := int64(instr & 0x03ffffff)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int64(0x03ffffff)
	}
	return addSignedOffset(addr, imm26<<2)
}

func decodeBTarget(addr uint64, instr uint32) (uint64, bool) {
	if (instr >> 26) != 0b000101 {
		return 0, false
	}
	imm26 := int64(instr & 0x03ffffff)
	if imm26&(1<<25) != 0 {
		imm26 |= ^int64(0x03ffffff)
	}
	return addSignedOffset(addr, imm26<<2)
}

func decodeADRPImmediate(pc uint64, raw uint32) (uint64, bool) {
	immlo := int64((raw >> 29) & 0x3)
	immhi := int64((raw >> 5) & 0x7ffff)
	imm := (immhi << 2) | immlo
	if (imm & (int64(1) << 20)) != 0 {
		imm |= ^((int64(1) << 21) - 1)
	}
	offset := imm << 12
	base := pc & ^uint64(0xfff)
	if offset >= 0 {
		return base + uint64(offset), true
	}
	return base - uint64(-offset), true
}

func isArm64Nop(instr uint32) bool {
	switch instr {
	case 0xd503201f, 0xd503205f, 0xd503207f, 0xd50320bf, 0xd50320ff:
		return true
	default:
		return false
	}
}

func isPacibsp(raw uint32) bool {
	return raw == 0xd503237f
}

func (s *Scanner) decodeArm64Instruction(addr uint64, raw uint32, inst *disassemble.Inst) error {
	return s.decoder.DecomposeInto(addr, raw, inst)
}

func operandCount(inst *disassemble.Inst) int {
	if inst == nil {
		return 0
	}
	return int(inst.NumOps)
}

func instPtr(ok bool, inst *disassemble.Inst) *disassemble.Inst {
	if !ok {
		return nil
	}
	return inst
}

func operandRegisterCount(op *disassemble.Op) int {
	if op == nil {
		return 0
	}
	return int(op.NumRegisters)
}

func operandRegister(op *disassemble.Op, idx int) (disassemble.Register, bool) {
	if idx < 0 || idx >= operandRegisterCount(op) {
		return 0, false
	}
	return op.Registers[idx], true
}

func operandHasRegister(op *disassemble.Op, reg disassemble.Register) bool {
	if op == nil {
		return false
	}
	for idx := 0; idx < int(op.NumRegisters); idx++ {
		if op.Registers[idx] == reg {
			return true
		}
	}
	return false
}

func trackedStaticAddress(regBase [31]uint64, op *disassemble.Op) (uint64, bool) {
	if op == nil {
		return 0, false
	}
	if op.Class == disassemble.LABEL {
		return op.GetImmediate(), true
	}
	baseReg, ok := operandRegister(op, 0)
	if !ok {
		return 0, false
	}
	baseIdx, ok := registerToIndex(baseReg)
	if !ok || baseIdx >= 31 || regBase[baseIdx] == 0 {
		return 0, false
	}
	switch op.Class {
	case disassemble.MEM_OFFSET, disassemble.MEM_PRE_IDX, disassemble.MEM_POST_IDX:
		return addSignedOffset(regBase[baseIdx], int64(op.GetImmediate()))
	default:
		return 0, false
	}
}

func operandIsSPPreIndex(op *disassemble.Op) bool {
	baseReg, ok := operandRegister(op, 0)
	return ok && op.Class == disassemble.MEM_PRE_IDX && baseReg == disassemble.REG_SP
}

func isFrameSetupInstruction(inst *disassemble.Inst) bool {
	if inst == nil {
		return false
	}
	switch inst.Operation {
	case disassemble.ARM64_PACIBSP:
		return true
	case disassemble.ARM64_STP:
		if operandCount(inst) < 3 {
			return false
		}
		return operandHasRegister(&inst.Operands[0], disassemble.REG_X29) &&
			operandHasRegister(&inst.Operands[1], disassemble.REG_X30) &&
			operandIsSPPreIndex(&inst.Operands[2])
	case disassemble.ARM64_SUB:
		if operandCount(inst) < 3 {
			return false
		}
		return operandHasRegister(&inst.Operands[0], disassemble.REG_SP) &&
			operandHasRegister(&inst.Operands[1], disassemble.REG_SP) &&
			inst.Operands[2].Class == disassemble.IMM64 &&
			inst.Operands[2].GetImmediate() > 0
	default:
		return false
	}
}

type staticValueTrackOptions struct {
	acceptAnyLoadAddr      bool
	propagateLoadAddrInAdd bool
	handleLoadPairs        bool
}

func (s *Scanner) trackStaticValueInstruction(owner *macho.File, regBase, regLoadAddr, regValue *[31]uint64, ins *disassemble.Inst, opts staticValueTrackOptions) {
	if ins == nil || operandCount(ins) == 0 {
		return
	}

	switch ins.Operation {
	case disassemble.ARM64_ADD:
		dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
		srcReg, srcOK := operandRegister(&ins.Operands[1], 0)
		if operandCount(ins) < 3 || !dstOK || !srcOK {
			return
		}
		dstIdx, dstOK := registerToIndex(dstReg)
		srcIdx, srcOK := registerToIndex(srcReg)
		if !dstOK || !srcOK || dstIdx >= 31 || srcIdx >= 31 {
			return
		}
		srcBase := regBase[srcIdx]
		srcLoadAddr := regLoadAddr[srcIdx]
		srcValue := regValue[srcIdx]
		regBase[dstIdx], regLoadAddr[dstIdx], regValue[dstIdx] = 0, 0, 0
		if srcBase != 0 {
			if addr, ok := addSignedOffset(srcBase, int64(ins.Operands[2].GetImmediate())); ok {
				regBase[dstIdx] = addr
				regValue[dstIdx] = addr
			}
			return
		}
		if opts.propagateLoadAddrInAdd && srcLoadAddr != 0 {
			if addr, ok := addSignedOffset(srcLoadAddr, int64(ins.Operands[2].GetImmediate())); ok {
				regLoadAddr[dstIdx] = addr
			}
			return
		}
		if srcValue != 0 {
			if value, ok := addSignedOffset(srcValue, int64(ins.Operands[2].GetImmediate())); ok {
				regValue[dstIdx] = value
			}
		}
	case disassemble.ARM64_MOV:
		dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
		if !dstOK {
			return
		}
		dstIdx, dstOK := registerToIndex(dstReg)
		if !dstOK || dstIdx >= 31 {
			return
		}
		regBase[dstIdx], regLoadAddr[dstIdx], regValue[dstIdx] = 0, 0, 0
		if operandCount(ins) <= 1 {
			return
		}
		srcReg, srcOK := operandRegister(&ins.Operands[1], 0)
		if !srcOK {
			regValue[dstIdx] = ins.Operands[1].GetImmediate()
			return
		}
		srcIdx, srcOK := registerToIndex(srcReg)
		if !srcOK || srcIdx >= 31 {
			return
		}
		regBase[dstIdx] = regBase[srcIdx]
		regLoadAddr[dstIdx] = regLoadAddr[srcIdx]
		regValue[dstIdx] = regValue[srcIdx]
	case disassemble.ARM64_ORR:
		dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
		if operandCount(ins) < 3 || !dstOK {
			return
		}
		dstIdx, dstOK := registerToIndex(dstReg)
		if !dstOK || dstIdx >= 31 {
			return
		}
		regBase[dstIdx], regLoadAddr[dstIdx], regValue[dstIdx] = 0, 0, 0
		reg1, reg1OK := operandRegister(&ins.Operands[1], 0)
		reg2, reg2OK := operandRegister(&ins.Operands[2], 0)
		switch {
		case reg1OK && reg2OK && (reg1 == disassemble.REG_XZR || reg1 == disassemble.REG_WZR):
			if srcIdx, ok := registerToIndex(reg2); ok && srcIdx < 31 {
				regBase[dstIdx] = regBase[srcIdx]
				regLoadAddr[dstIdx] = regLoadAddr[srcIdx]
				regValue[dstIdx] = regValue[srcIdx]
			}
		case reg1OK && reg2OK && (reg2 == disassemble.REG_XZR || reg2 == disassemble.REG_WZR):
			if srcIdx, ok := registerToIndex(reg1); ok && srcIdx < 31 {
				regBase[dstIdx] = regBase[srcIdx]
				regLoadAddr[dstIdx] = regLoadAddr[srcIdx]
				regValue[dstIdx] = regValue[srcIdx]
			}
		}
	case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
		dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
		if operandCount(ins) < 2 || !dstOK {
			return
		}
		dstIdx, dstOK := registerToIndex(dstReg)
		if !dstOK || dstIdx >= 31 {
			return
		}
		regBase[dstIdx], regLoadAddr[dstIdx], regValue[dstIdx] = 0, 0, 0
		addr, ok := trackedStaticAddress(*regBase, &ins.Operands[1])
		if !ok {
			return
		}
		regLoadAddr[dstIdx] = addr
		if ptr, ok := s.resolvePointerAt(owner, addr); ok {
			regValue[dstIdx] = ptr
			return
		}
		if opts.acceptAnyLoadAddr || validKernelPointer(addr) {
			regValue[dstIdx] = addr
		}
	case disassemble.ARM64_LDP:
		if !opts.handleLoadPairs {
			return
		}
		if operandCount(ins) < 3 {
			return
		}
		if reg, ok := operandRegister(&ins.Operands[0], 0); ok {
			if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
				regBase[dstIdx], regLoadAddr[dstIdx], regValue[dstIdx] = 0, 0, 0
			}
		}
		if reg, ok := operandRegister(&ins.Operands[1], 0); ok {
			if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
				regBase[dstIdx], regLoadAddr[dstIdx], regValue[dstIdx] = 0, 0, 0
			}
		}
		addr, ok := trackedStaticAddress(*regBase, &ins.Operands[2])
		if !ok {
			return
		}
		if reg, ok := operandRegister(&ins.Operands[0], 0); ok {
			if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
				regLoadAddr[dstIdx] = addr
				if ptr, ok := s.resolvePointerAt(owner, addr); ok {
					regValue[dstIdx] = ptr
				} else if opts.acceptAnyLoadAddr || validKernelPointer(addr) {
					regValue[dstIdx] = addr
				}
			}
		}
		if reg, ok := operandRegister(&ins.Operands[1], 0); ok {
			if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
				if addr2, ok := addSignedOffset(addr, 8); ok {
					regLoadAddr[dstIdx] = addr2
					if ptr, ok := s.resolvePointerAt(owner, addr2); ok {
						regValue[dstIdx] = ptr
					} else if opts.acceptAnyLoadAddr || validKernelPointer(addr2) {
						regValue[dstIdx] = addr2
					}
				}
			}
		}
	}
}

func findFunctionStartInSection(sectionAddr uint64, data []byte, targetAddr uint64) (uint64, error) {
	if targetAddr < sectionAddr || targetAddr >= sectionAddr+uint64(len(data)) {
		return 0, fmt.Errorf("target %#x not inside section [%#x, %#x)", targetAddr, sectionAddr, sectionAddr+uint64(len(data)))
	}
	cursor := int(targetAddr - sectionAddr)
	cursor -= cursor % 4
	const maxScan = 256
	var decoder disassemble.Decoder
	for steps := 0; steps < maxScan && cursor >= 0; steps++ {
		if cursor+4 > len(data) {
			break
		}
		raw := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		addr := sectionAddr + uint64(cursor)
		if isPacibsp(raw) {
			return addr, nil
		}
		var inst disassemble.Inst
		if err := decoder.DecomposeInto(addr, raw, &inst); err == nil && isFrameSetupInstruction(&inst) {
			return addr, nil
		}
		cursor -= 4
	}
	return 0, fmt.Errorf("no prologue found before %#x", targetAddr)
}

func (s *Scanner) includeEntry(entry string) bool {
	if len(s.cfg.Entries) == 0 {
		return true
	}
	norm := normalizeEntryID(entry)
	for _, candidate := range s.cfg.Entries {
		want := normalizeEntryID(candidate)
		if norm == want || strings.EqualFold(entry, candidate) || strings.HasSuffix(strings.ToLower(norm), strings.ToLower(candidate)) {
			return true
		}
	}
	return false
}

func (s *Scanner) buildTargets() ([]scanTarget, error) {
	targets := make([]scanTarget, 0, 1+len(s.root.FileSets()))
	if s.includeEntry(kernelBundleName) {
		targets = append(targets, scanTarget{file: s.root, entryID: kernelBundleName})
	}
	if s.root.FileHeader.Type != types.MH_FILESET {
		return targets, nil
	}
	for _, fs := range s.root.FileSets() {
		entryID := normalizeEntryID(fs.EntryID)
		if !s.includeEntry(entryID) {
			continue
		}
		m, err := s.root.GetFileSetFileByName(fs.EntryID)
		if err != nil {
			return nil, fmt.Errorf("open fileset entry %s: %w", fs.EntryID, err)
		}
		s.fileEntries[m] = entryID
		targets = append(targets, scanTarget{file: m, entryID: entryID})
	}
	return targets, nil
}

func (s *Scanner) fileForVMAddr(addr uint64) *macho.File {
	if s.root.FileHeader.Type != types.MH_FILESET {
		if fileOwnsVMAddr(s.root, addr) {
			return s.root
		}
		return nil
	}

	for _, target := range s.targets {
		if target.file == s.root {
			continue
		}
		if fileOwnsVMAddr(target.file, addr) {
			return target.file
		}
	}
	if fileOwnsVMAddr(s.root, addr) {
		return s.root
	}
	return nil
}

func (s *Scanner) entryForFile(m *macho.File) string {
	if entry, ok := s.fileEntries[m]; ok {
		return entry
	}
	if m == s.root {
		return kernelBundleName
	}
	return ""
}

func (s *Scanner) readSectionData(m *macho.File, sec *types.Section) ([]byte, error) {
	key := sectionKey{file: m, addr: sec.Addr}
	if data, ok := s.sectionData[key]; ok {
		return data, nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil, err
	}
	s.sectionData[key] = data
	return data, nil
}

func (s *Scanner) functionsForFile(m *macho.File) ([]types.Function, error) {
	if funcs, ok := s.functions[m]; ok {
		return funcs, nil
	}
	funcs := m.GetFunctions()
	if len(funcs) == 0 {
		var err error
		funcs, err = m.GenerateFunctionStarts()
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].StartAddr < funcs[j].StartAddr
	})
	s.functions[m] = funcs
	return funcs, nil
}

func (s *Scanner) functionForAddr(m *macho.File, addr uint64) (types.Function, error) {
	funcs, err := s.functionsForFile(m)
	if err == nil {
		idx := sort.Search(len(funcs), func(i int) bool {
			return funcs[i].StartAddr > addr
		})
		if idx > 0 {
			fn := funcs[idx-1]
			if addr >= fn.StartAddr && addr < fn.EndAddr {
				return fn, nil
			}
		}
	}

	sec := m.FindSectionForVMAddr(addr)
	if sec == nil {
		return types.Function{}, fmt.Errorf("address %#x not inside executable section", addr)
	}
	data, err := s.readSectionData(m, sec)
	if err != nil {
		return types.Function{}, err
	}
	start, err := findFunctionStartInSection(sec.Addr, data, addr)
	if err != nil {
		return types.Function{}, err
	}
	funcs, err = s.functionsForFile(m)
	if err != nil {
		return types.Function{}, err
	}
	end := sec.Addr + sec.Size
	idx := sort.Search(len(funcs), func(i int) bool {
		return funcs[i].StartAddr > start
	})
	if idx < len(funcs) {
		end = funcs[idx].StartAddr
	}

	fn := types.Function{StartAddr: start, EndAddr: end}
	funcs = append(funcs, fn)
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].StartAddr < funcs[j].StartAddr
	})
	s.functions[m] = slices.CompactFunc(funcs, func(a, b types.Function) bool {
		return a.StartAddr == b.StartAddr && a.EndAddr == b.EndAddr
	})
	delete(s.callerIndex, m)
	delete(s.pointerIndex, m)
	return fn, nil
}

func (s *Scanner) functionForAddrInAnyFile(preferred *macho.File, addr uint64) (types.Function, *macho.File, error) {
	if preferred != nil {
		if fn, err := s.functionForAddr(preferred, addr); err == nil {
			return fn, preferred, nil
		}
	}
	if owner := s.fileForVMAddr(addr); owner != nil && owner != preferred {
		if fn, err := s.functionForAddr(owner, addr); err == nil {
			return fn, owner, nil
		}
	}
	return types.Function{}, nil, fmt.Errorf("address %#x not inside known function", addr)
}

func (s *Scanner) functionDataFor(m *macho.File, fn types.Function) ([]byte, error) {
	key := fileFuncKey{file: m, start: fn.StartAddr}
	if data, ok := s.functionData[key]; ok {
		return data, nil
	}
	if fn.EndAddr > fn.StartAddr {
		if sec := m.FindSectionForVMAddr(fn.StartAddr); sec != nil {
			if fn.EndAddr <= sec.Addr+sec.Size {
				if data, err := s.readSectionData(m, sec); err == nil {
					start := int(fn.StartAddr - sec.Addr)
					end := int(fn.EndAddr - sec.Addr)
					if start >= 0 && end <= len(data) && start < end {
						window := data[start:end:end]
						s.functionData[key] = window
						return window, nil
					}
				}
			}
		}
	}
	data, err := m.GetFunctionData(fn)
	if err != nil {
		return nil, err
	}
	s.functionData[key] = data
	return data, nil
}

func getCStringFromAny(root *macho.File, owner *macho.File, addr uint64) (string, error) {
	if owner != nil {
		if str, err := owner.GetCString(addr); err == nil && str != "" {
			return str, nil
		}
	}
	return root.GetCString(addr)
}

func (s *Scanner) cachedCStringAt(addr uint64) (string, error) {
	if addr == 0 {
		return "", fmt.Errorf("zero cstring address")
	}
	if cached, ok := s.nameStrings[addr]; ok {
		if !cached.ok {
			return "", fmt.Errorf("cached cstring miss at %#x", addr)
		}
		return cached.value, nil
	}
	value, err := getCStringFromAny(s.root, s.fileForVMAddr(addr), addr)
	s.nameStrings[addr] = cachedCString{value: value, ok: err == nil && value != ""}
	return value, err
}

func looksLikeRecoveredClassName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	first := true
	hasUpper := false
	leadingUnderscore := false
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
		if first {
			first = false
			leadingUnderscore = r == '_'
		}
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
		case r == '_', r == ':', r == '<', r == '>', r == '*', r == '·':
		default:
			return false
		}
	}
	return hasUpper || leadingUnderscore || looksLikeRecoveredLowercaseClassName(name)
}

func looksLikeRecoveredLowercaseClassName(name string) bool {
	switch {
	case strings.HasPrefix(name, "com_"):
		return true
	case strings.HasSuffix(name, "_t"):
		return true
	case name == "cache":
		return true
	case strings.HasSuffix(name, "_init"),
		strings.HasSuffix(name, "_bootstrap"),
		strings.HasSuffix(name, "_event"):
		return false
	default:
		return false
	}
}

func recoveredClassNameScore(name string) int {
	if name == "" {
		return 0
	}
	if strings.HasPrefix(name, "UnknownClass_") {
		return 1
	}
	if !looksLikeRecoveredClassName(name) {
		return 1
	}
	score := 2
	if strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ:<>*·") {
		score++
	}
	switch {
	case strings.HasSuffix(name, "_init"),
		strings.HasSuffix(name, "_bootstrap"),
		strings.HasSuffix(name, "_event"):
		score--
	}
	if score < 1 {
		return 1
	}
	return score
}

func hasStrongClassEvidence(class discoveredClass) bool {
	return class.SuperMeta != 0 || class.MetaVtableAddr != 0 || class.VtableAddr != 0
}

func fileOwnsVMAddr(m *macho.File, addr uint64) bool {
	for _, sec := range m.Sections {
		if sec.Addr <= addr && addr < sec.Addr+sec.Size {
			return true
		}
	}
	return false
}

func (s *Scanner) clearDiscoveryCaches() {
	clear(s.functionData)
	clear(s.sectionData)
	clear(s.callerIndex)
	clear(s.callsiteCtx)
	clear(s.getMetaCands)
	clear(s.staticCalls)
}

func (s *Scanner) repairClassesFromCallsite(classes []discoveredClass) {
	for i := range classes {
		owner := classes[i].file
		if owner == nil {
			owner = s.fileForVMAddr(classes[i].Ctor)
			classes[i].file = owner
		}
		if owner == nil || classes[i].Ctor == 0 {
			continue
		}
		if validMetaPointer(classes[i].SuperMeta) && classes[i].MetaVtableAddr != 0 {
			continue
		}
		ctx, ok := s.recoverCallsiteContext(owner, &classes[i])
		if !ok {
			continue
		}
		if classes[i].MetaPtr == 0 && validKernelPointer(ctx.x0) {
			classes[i].MetaPtr = ctx.x0
		}
		if !validMetaPointer(classes[i].SuperMeta) {
			if super := s.recoverSuperMetaFromCtorPattern(owner, &classes[i]); validMetaPointer(super) {
				classes[i].SuperMeta = super
			}
		}
		if !validMetaPointer(classes[i].SuperMeta) {
			if super := s.normalizeLoadedPointer(owner, ctx.x2); validMetaPointer(super) {
				classes[i].SuperMeta = super
			}
		}
		if classes[i].Size == 0 && ctx.x3 > 0 && ctx.x3 <= 0xffffffff {
			classes[i].Size = uint32(ctx.x3)
		}
		if classes[i].MetaVtableAddr == 0 && validKernelPointer(ctx.metaVtab) {
			classes[i].MetaVtableAddr = ctx.metaVtab
		}
	}
}

// recoverSuperMetaFromModInit fills in missing SuperMeta values by
// statically analyzing mod_init_func wrapper functions. Each wrapper
// sets up x0 (metaclass ptr) and x2 (parent metaclass ptr) before
// calling the constructor. When x2 is loaded from a GOT slot
// (cross-kext parent), the pointer is resolved via chained fixups.
func (s *Scanner) recoverSuperMetaFromModInit(classes []discoveredClass) {
	needsRecovery := false
	for i := range classes {
		if classes[i].SuperMeta == 0 && classes[i].MetaPtr != 0 {
			needsRecovery = true
			break
		}
	}
	if !needsRecovery {
		return
	}

	metaPtrToIdx := make(map[uint64]int, len(classes))
	for i := range classes {
		if classes[i].MetaPtr != 0 && classes[i].SuperMeta == 0 {
			metaPtrToIdx[classes[i].MetaPtr] = i
		}
	}

	for _, target := range s.targets {
		if len(metaPtrToIdx) == 0 {
			break
		}
		ptrs, err := s.modInitPointers(target.file)
		if err != nil {
			continue
		}
		for _, ptr := range ptrs {
			x0, x2 := s.extractModInitPair(target.file, ptr)
			if x0 == 0 || x2 == 0 {
				continue
			}
			idx, ok := metaPtrToIdx[x0]
			if !ok {
				continue
			}
			if validMetaPointer(x2) {
				classes[idx].SuperMeta = x2
				delete(metaPtrToIdx, x0)
			}
		}
	}
}

// extractModInitPair statically traces a mod_init_func wrapper to
// extract the x0 (metaclass ptr) and x2 (parent metaclass ptr)
// values at the last BL/BRAA call that has both set. When x2 is
// loaded from a GOT slot, the chained fixup pointer is resolved.
func (s *Scanner) extractModInitPair(owner *macho.File, funcAddr uint64) (uint64, uint64) {
	buf := make([]byte, 80*4)
	if _, err := s.root.ReadAtAddr(buf, funcAddr); err != nil {
		return 0, 0
	}

	type regState struct {
		adrpBase uint64
		computed uint64
		loadAddr uint64
		isLoad   bool
	}
	var regs [31]regState

	var bestX0, bestX2 uint64
	for i := 0; i+4 <= len(buf); i += 4 {
		pc := funcAddr + uint64(i)
		raw := readUint32At(buf, i)

		// ADRP
		if (raw & 0x9f000000) == 0x90000000 {
			rd := int(raw & 0x1f)
			if rd < 31 {
				if addr, ok := decodeADRPImmediate(pc, raw); ok {
					regs[rd] = regState{adrpBase: addr}
				}
			}
			continue
		}
		// ADD imm (64-bit, sf=1)
		if (raw & 0xff800000) == 0x91000000 {
			rd := int(raw & 0x1f)
			rn := int((raw >> 5) & 0x1f)
			imm12 := uint64((raw >> 10) & 0xfff)
			if (raw>>22)&1 == 1 {
				imm12 <<= 12
			}
			if rd < 31 && rn < 31 && regs[rn].adrpBase != 0 {
				regs[rd] = regState{computed: regs[rn].adrpBase + imm12}
			}
			continue
		}
		// LDR unsigned offset (64-bit)
		if (raw & 0xffc00000) == 0xf9400000 {
			rt := int(raw & 0x1f)
			rn := int((raw >> 5) & 0x1f)
			imm12 := uint64((raw>>10)&0xfff) * 8
			if rt < 31 && rn < 31 {
				var la uint64
				if regs[rn].adrpBase != 0 {
					la = regs[rn].adrpBase + imm12
				} else if regs[rn].computed != 0 {
					la = regs[rn].computed + imm12
				}
				regs[rt] = regState{loadAddr: la, isLoad: true}
			}
			continue
		}
		// MOV Xd, Xm (ORR Xd, XZR, Xm)
		if (raw & 0xffe0ffe0) == 0xaa0003e0 {
			rd := int(raw & 0x1f)
			rm := int((raw >> 16) & 0x1f)
			if rd < 31 && rm < 31 {
				regs[rd] = regs[rm]
			}
			continue
		}
		// MOVZ (64-bit)
		if (raw & 0xff800000) == 0xd2800000 {
			rd := int(raw & 0x1f)
			if rd < 31 {
				regs[rd] = regState{}
			}
			continue
		}
		// RET
		if raw == 0xd65f03c0 || raw == 0xd65f0fff {
			break
		}
		// BL or BRAA/BLRAA - capture register state
		isBL := (raw >> 26) == 0b100101
		isAuthBranch := (raw&0xfffff800) == 0xd71f0800 ||
			(raw&0xfffff800) == 0xd63f0800
		if !isBL && !isAuthBranch {
			continue
		}

		// x0: prefer computed (ADRP+ADD), fall back to adrpBase
		var x0 uint64
		if regs[0].computed != 0 {
			x0 = regs[0].computed
		} else if regs[0].adrpBase != 0 {
			x0 = regs[0].adrpBase
		}

		// x2: if loaded from GOT, resolve the pointer
		var x2 uint64
		if regs[2].computed != 0 {
			x2 = regs[2].computed
		} else if regs[2].adrpBase != 0 && !regs[2].isLoad {
			x2 = regs[2].adrpBase
		} else if regs[2].loadAddr != 0 {
			if ptr, ok := s.resolvePointerAt(owner, regs[2].loadAddr); ok {
				x2 = ptr
			}
		}

		if x0 != 0 && x2 != 0 {
			bestX0, bestX2 = x0, x2
		}
	}

	return bestX0, bestX2
}

func (s *Scanner) validateSuperMeta(classes []discoveredClass) {
	known := make(map[uint64]bool, len(classes))
	for i := range classes {
		if classes[i].MetaPtr != 0 {
			known[classes[i].MetaPtr] = true
		}
	}
	for i := range classes {
		if validMetaPointer(classes[i].SuperMeta) {
			continue
		}

		owner := classes[i].file
		if owner == nil {
			owner = s.fileForVMAddr(classes[i].Ctor)
		}

		if recovered := s.recoverSuperMetaFromCtorPattern(owner, &classes[i]); validMetaPointer(recovered) {
			classes[i].SuperMeta = recovered
			continue
		}
		if ctx, ok := s.recoverCallsiteContext(owner, &classes[i]); ok {
			if super := s.normalizeLoadedPointer(owner, ctx.x2); validMetaPointer(super) {
				classes[i].SuperMeta = super
				continue
			}
		}
		if classes[i].SuperMeta != 0 && known[classes[i].SuperMeta] {
			continue
		}
		classes[i].SuperMeta = 0
	}
}

func (s *Scanner) normalizeLoadedPointer(owner *macho.File, value uint64) uint64 {
	if validKernelPointer(value) || value == 0 {
		return value
	}

	// Try root first — in a fileset cache, the root MH_FILESET
	// decodes chained fixup binds to canonical kernel addresses,
	// while individual entry handles may resolve to local offsets.
	if s.root != nil {
		if slid := s.root.SlidePointer(value); validKernelPointer(slid) {
			return slid
		}
	}
	if owner != nil && owner != s.root {
		if slid := owner.SlidePointer(value); validKernelPointer(slid) {
			return slid
		}
	}
	return value
}

func pointerCacheCoversAddress(m *macho.File, addr uint64) bool {
	if m == nil {
		return false
	}
	sec := m.FindSectionForVMAddr(addr)
	if sec == nil || sec.Size < 8 {
		return false
	}
	if sec.Seg == "__TEXT" || sec.Seg == "__TEXT_EXEC" {
		return false
	}
	if strings.HasSuffix(sec.Name, "__bss") || strings.HasSuffix(sec.Name, "__common") {
		return false
	}
	return true
}

func (s *Scanner) resolvePointerAt(owner *macho.File, addr uint64) (uint64, bool) {
	// Fast path: check forward pointer cache built by buildPointerIndex.
	if fwd := s.forwardPointers[owner]; fwd != nil {
		if ptr, ok := fwd[addr]; ok {
			s.stats.ptrCacheHits++
			return ptr, true
		}
	}
	if s.root != nil && owner != s.root {
		if fwd := s.forwardPointers[s.root]; fwd != nil {
			if ptr, ok := fwd[addr]; ok {
				s.stats.ptrCacheHits++
				return ptr, true
			}
		}
	}
	s.stats.ptrCacheMisses++
	// The forward pointer cache (built by buildPointerIndex) covers
	// every 8-byte-aligned slot in every DATA section.  If the addr
	// isn't there, the I/O path (pread) almost certainly won't find
	// a valid kernel pointer either — and the syscall cost is the
	// dominant bottleneck.  Skip the slow path only for addresses the
	// cache actually covers once it has been warmed for this file.
	if s.forwardPointers[owner] != nil && pointerCacheCoversAddress(owner, addr) {
		return 0, false
	}
	if s.root != nil && s.forwardPointers[s.root] != nil && pointerCacheCoversAddress(s.root, addr) {
		return 0, false
	}
	// Slow path: I/O via go-macho (only reached before cache warm).
	if s.root != nil {
		if ptr, err := s.root.GetSlidPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
			return ptr, true
		}
		if ptr, err := s.root.GetPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
			return ptr, true
		}
	}
	if owner != nil && owner != s.root {
		if ptr, err := owner.GetSlidPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
			return ptr, true
		}
		if ptr, err := owner.GetPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
			return ptr, true
		}
	}
	return 0, false
}

func (s *Scanner) fallbackPointerAt(owner *macho.File, addr uint64) (uint64, bool) {
	if owner == nil {
		return 0, false
	}
	// Fast path: check forward pointer cache built by buildPointerIndex.
	if fwd := s.forwardPointers[owner]; fwd != nil {
		if ptr, ok := fwd[addr]; ok {
			return ptr, true
		}
	}
	if s.root != nil && owner != s.root {
		if fwd := s.forwardPointers[s.root]; fwd != nil {
			if ptr, ok := fwd[addr]; ok {
				return ptr, true
			}
		}
	}
	// Skip slow I/O path only for addresses covered by the warmed cache.
	if s.forwardPointers[owner] != nil && pointerCacheCoversAddress(owner, addr) {
		return 0, false
	}
	if s.root != nil && s.forwardPointers[s.root] != nil && pointerCacheCoversAddress(s.root, addr) {
		return 0, false
	}
	// Slow path: I/O via go-macho (only reached before cache warm).
	if s.root != nil && s.root.FileHeader.Type == types.MH_FILESET {
		if ptr, err := s.root.GetSlidPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
			return ptr, true
		}
		if ptr, err := s.root.GetPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
			return ptr, true
		}
		if owner != s.root {
			if ptr, err := owner.GetSlidPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
				return ptr, true
			}
			if ptr, err := owner.GetPointerAtAddress(addr); err == nil && validKernelPointer(ptr) {
				return ptr, true
			}
		}
		return 0, false
	}
	ptr, err := owner.GetPointerAtAddress(addr)
	if err != nil {
		return 0, false
	}
	return ptr, true
}

// isStubFor checks whether stubAddr is a small auth stub (ADRP+ADD+BR
// or ADRP+LDR+BR) that ultimately branches to targetFunc.
func (s *Scanner) isStubFor(m *macho.File, stubAddr, targetFunc uint64) bool {
	if stubAddr == 0 || targetFunc == 0 {
		return false
	}
	var buf [12]byte
	owner := m
	if s.root != nil {
		if _, err := s.root.ReadAtAddr(buf[:], stubAddr); err != nil {
			if owner == nil {
				return false
			}
			if _, err := owner.ReadAtAddr(buf[:], stubAddr); err != nil {
				return false
			}
		}
	} else if owner != nil {
		if _, err := owner.ReadAtAddr(buf[:], stubAddr); err != nil {
			return false
		}
	} else {
		return false
	}

	i0 := binary.LittleEndian.Uint32(buf[0:4])
	i1 := binary.LittleEndian.Uint32(buf[4:8])

	// First instruction must be ADRP Xd, #page
	if i0&0x9F000000 != 0x90000000 {
		return false
	}
	rd := i0 & 0x1F
	immlo := (i0 >> 29) & 0x3
	immhi := (i0 >> 5) & 0x7FFFF
	imm := int64((uint64(immhi)<<2 | uint64(immlo)) << 12)
	if imm&(1<<32) != 0 {
		imm |= ^int64((1 << 33) - 1)
	}
	page := (stubAddr &^ 0xFFF) + uint64(imm)

	// Second instruction: ADD Xd, Xd, #imm12 or LDR Xd, [Xd, #imm12]
	if i1&0xFFC00000 == 0x91000000 && (i1&0x1F) == rd && ((i1>>5)&0x1F) == rd {
		// ADD immediate
		addImm := uint64((i1 >> 10) & 0xFFF)
		if (i1>>22)&1 != 0 {
			addImm <<= 12
		}
		target := page + addImm
		return target == targetFunc
	}
	if i1&0xFFC00000 == 0xF9400000 && (i1&0x1F) == rd && ((i1>>5)&0x1F) == rd {
		// LDR X, [X, #imm12] (unsigned offset, scale 8)
		ldrOff := uint64((i1>>10)&0xFFF) * 8
		gotSlot := page + ldrOff
		ptr, ok := s.resolvePointerAt(m, gotSlot)
		if !ok {
			return false
		}
		return ptr == targetFunc
	}
	return false
}

func (s *Scanner) recoverSuperMetaFromCtorPattern(m *macho.File, class *discoveredClass) uint64 {
	if class == nil || class.Ctor == 0 {
		return 0
	}
	fn, owner, err := s.functionForAddrInAnyFile(m, class.Ctor)
	if err != nil {
		return 0
	}
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		return 0
	}

	callOffset := int(class.Ctor - fn.StartAddr)
	if callOffset < 0 || callOffset >= len(data) {
		return 0
	}

	start := max(callOffset-32*4, 0)

	var regBase [31]uint64
	var regLoadAddr [31]uint64
	for i := start; i+4 <= callOffset; i += 4 {
		pc := fn.StartAddr + uint64(i)
		raw := readUint32At(data, i)

		if (raw & 0x9f000000) == 0x90000000 {
			rd := int(raw & 0x1f)
			if rd < 31 {
				if addr, ok := decodeADRPImmediate(pc, raw); ok {
					regBase[rd] = addr
					regLoadAddr[rd] = 0
				}
			}
			continue
		}

		var ins disassemble.Inst
		if err := s.decodeArm64Instruction(pc, raw, &ins); err != nil {
			continue
		}

		switch ins.Operation {
		case disassemble.ARM64_ADD:
			dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
			srcReg, srcOK := operandRegister(&ins.Operands[1], 0)
			if operandCount(&ins) < 3 || !dstOK || !srcOK {
				continue
			}
			dstIdx, dstOk := registerToIndex(dstReg)
			srcIdx, srcOk := registerToIndex(srcReg)
			if dstOk && srcOk && dstIdx < 31 && srcIdx < 31 {
				srcBase := regBase[srcIdx]
				regLoadAddr[dstIdx] = 0
				regBase[dstIdx] = 0
				if srcBase != 0 {
					if addr, ok := addSignedOffset(srcBase, int64(ins.Operands[2].GetImmediate())); ok {
						regBase[dstIdx] = addr
					}
				}
			}
		case disassemble.ARM64_SUB, disassemble.ARM64_ADR:
			if dstReg, ok := operandRegister(&ins.Operands[0], 0); operandCount(&ins) > 0 && ok {
				if dstIdx, ok := registerToIndex(dstReg); ok && dstIdx < 31 {
					regBase[dstIdx] = 0
					regLoadAddr[dstIdx] = 0
				}
			}
		case disassemble.ARM64_MOV:
			dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
			if operandCount(&ins) < 2 || !dstOK {
				continue
			}
			dstIdx, dstOK := registerToIndex(dstReg)
			if !dstOK || dstIdx >= 31 {
				continue
			}
			regBase[dstIdx] = 0
			regLoadAddr[dstIdx] = 0
			srcReg, srcOK := operandRegister(&ins.Operands[1], 0)
			if !srcOK {
				continue
			}
			srcIdx, srcOK := registerToIndex(srcReg)
			if !srcOK || srcIdx >= 31 {
				continue
			}
			regBase[dstIdx] = regBase[srcIdx]
			regLoadAddr[dstIdx] = regLoadAddr[srcIdx]
		case disassemble.ARM64_ORR:
			dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
			if operandCount(&ins) < 3 || !dstOK {
				continue
			}
			dstIdx, dstOK := registerToIndex(dstReg)
			if !dstOK || dstIdx >= 31 {
				continue
			}
			regBase[dstIdx] = 0
			regLoadAddr[dstIdx] = 0
			reg1, reg1OK := operandRegister(&ins.Operands[1], 0)
			reg2, reg2OK := operandRegister(&ins.Operands[2], 0)
			switch {
			case reg1OK && reg2OK && (reg1 == disassemble.REG_XZR || reg1 == disassemble.REG_WZR):
				if srcIdx, ok := registerToIndex(reg2); ok && srcIdx < 31 {
					regBase[dstIdx] = regBase[srcIdx]
					regLoadAddr[dstIdx] = regLoadAddr[srcIdx]
				}
			case reg1OK && reg2OK && (reg2 == disassemble.REG_XZR || reg2 == disassemble.REG_WZR):
				if srcIdx, ok := registerToIndex(reg1); ok && srcIdx < 31 {
					regBase[dstIdx] = regBase[srcIdx]
					regLoadAddr[dstIdx] = regLoadAddr[srcIdx]
				}
			}
		case disassemble.ARM64_LDR, disassemble.ARM64_LDUR:
			dstReg, dstOK := operandRegister(&ins.Operands[0], 0)
			if operandCount(&ins) < 2 || !dstOK {
				continue
			}
			dstIdx, dstOK := registerToIndex(dstReg)
			if !dstOK || dstIdx >= 31 {
				continue
			}
			regBase[dstIdx] = 0
			regLoadAddr[dstIdx] = 0
			if addr, ok := trackedStaticAddress(regBase, &ins.Operands[1]); ok {
				regLoadAddr[dstIdx] = addr
			}
		case disassemble.ARM64_LDP:
			if operandCount(&ins) < 3 {
				continue
			}
			if reg, ok := operandRegister(&ins.Operands[0], 0); ok {
				if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
					regBase[dstIdx] = 0
					regLoadAddr[dstIdx] = 0
				}
			}
			if reg, ok := operandRegister(&ins.Operands[1], 0); ok {
				if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
					regBase[dstIdx] = 0
					regLoadAddr[dstIdx] = 0
				}
			}
			addr, ok := trackedStaticAddress(regBase, &ins.Operands[2])
			if !ok {
				continue
			}
			if reg, ok := operandRegister(&ins.Operands[0], 0); ok {
				if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
					regLoadAddr[dstIdx] = addr
				}
			}
			if reg, ok := operandRegister(&ins.Operands[1], 0); ok {
				if dstIdx, ok := registerToIndex(reg); ok && dstIdx < 31 {
					if addr2, ok := addSignedOffset(addr, 8); ok {
						regLoadAddr[dstIdx] = addr2
					}
				}
			}
		}
	}

	if regLoadAddr[2] != 0 {
		if ptr, ok := s.resolvePointerAt(owner, regLoadAddr[2]); ok {
			return ptr
		}
	}
	if validKernelPointer(regBase[2]) {
		return regBase[2]
	}

	return 0
}

func readUint32At(data []byte, offset int) uint32 {
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

func (s *Scanner) inferMetaPtrFromDirectCallers(owner *macho.File, target uint64) uint64 {
	return s.inferMetaPtrFromDirectCallersDepth(owner, target, 0)
}

func (s *Scanner) inferMetaPtrFromDirectCallersDepth(owner *macho.File, target uint64, depth int) uint64 {
	if owner == nil || target == 0 || depth > s.cfg.MaxWrapperDepth {
		return 0
	}
	index, err := s.directCallerIndex(owner)
	if err != nil {
		return 0
	}
	for _, callerStart := range index[target] {
		fn, err := s.functionForAddr(owner, callerStart)
		if err != nil {
			continue
		}
		metaPtr, found := s.metaPtrAtDirectCall(owner, fn, target)
		if !found {
			continue
		}
		if validKernelPointer(metaPtr) {
			return metaPtr
		}
		if inferred := s.inferMetaPtrFromDirectCallersDepth(owner, callerStart, depth+1); validKernelPointer(inferred) {
			return inferred
		}
	}
	return 0
}

func (s *Scanner) directCallerIndex(m *macho.File) (map[uint64][]uint64, error) {
	if index, ok := s.callerIndex[m]; ok {
		return index, nil
	}

	funcs, err := s.functionsForFile(m)
	if err != nil {
		return nil, err
	}

	index := make(map[uint64][]uint64)
	for _, fn := range funcs {
		data, err := s.functionDataFor(m, fn)
		if err != nil {
			continue
		}
		for off := 0; off+4 <= len(data); off += 4 {
			pc := fn.StartAddr + uint64(off)
			raw := readUint32At(data, off)
			if target, ok := decodeBLTarget(pc, raw); ok && target != 0 {
				index[target] = append(index[target], fn.StartAddr)
				continue
			}
			if target, ok := decodeBTarget(pc, raw); ok && target != 0 {
				index[target] = append(index[target], fn.StartAddr)
			}
		}
	}

	for target, callers := range index {
		slices.Sort(callers)
		index[target] = slices.Compact(callers)
	}

	s.callerIndex[m] = index
	return index, nil
}

func (s *Scanner) metaPtrAtDirectCall(owner *macho.File, fn types.Function, target uint64) (uint64, bool) {
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		return 0, false
	}

	var regBase [31]uint64
	var regLoadAddr [31]uint64
	var regValue [31]uint64
	for i := 0; i+4 <= len(data); i += 4 {
		pc := fn.StartAddr + uint64(i)
		raw := readUint32At(data, i)

		// BL / B to target → return tracked x0.
		if callTarget, ok := decodeBLTarget(pc, raw); ok && callTarget == target {
			return metaPtrResult(regBase, regValue), true
		}
		if callTarget, ok := decodeBTarget(pc, raw); ok && callTarget == target {
			return metaPtrResult(regBase, regValue), true
		}

		if (raw & 0x9f000000) == 0x90000000 {
			rd := int(raw & 0x1f)
			if rd < 31 {
				if addr, ok := decodeADRPImmediate(pc, raw); ok {
					regBase[rd] = addr
					regLoadAddr[rd] = 0
					regValue[rd] = 0
				}
			}
			continue
		}

		var ins disassemble.Inst
		if err := s.decodeArm64Instruction(pc, raw, &ins); err != nil || operandCount(&ins) == 0 {
			continue
		}

		s.trackStaticValueInstruction(owner, &regBase, &regLoadAddr, &regValue, &ins, staticValueTrackOptions{
			acceptAnyLoadAddr:      false,
			propagateLoadAddrInAdd: true,
			handleLoadPairs:        true,
		})
	}
	return 0, false
}

func metaPtrResult(regBase, regValue [31]uint64) uint64 {
	if validKernelPointer(regValue[0]) {
		return regValue[0]
	}
	if validKernelPointer(regBase[0]) {
		return regBase[0]
	}
	return 0
}

// trackRegisterRaw performs register tracking using raw ARM64
// instruction bitmasks, avoiding CGo entirely.  It handles the
// instruction subset needed by metaPtrAtDirectCall and similar
// callers: ADRP, ADD(imm), LDR(uoff/reg), LDUR, LDP, MOV, ORR, SUB(imm).
func trackRegisterRaw(s *Scanner, owner *macho.File, raw uint32, pc uint64, regBase, regValue *[31]uint64) {
	switch {
	// ADRP: sf 1 0000 immlo immhi Rd
	case (raw & 0x9f000000) == 0x90000000:
		rd := int(raw & 0x1f)
		if rd < 31 {
			if addr, ok := decodeADRPImmediate(pc, raw); ok {
				regBase[rd] = addr
				regValue[rd] = 0
			}
		}

	// ADR: sf 0 0000 immlo immhi Rd
	case (raw & 0x9f000000) == 0x10000000:
		rd := int(raw & 0x1f)
		if rd < 31 {
			immhi := int64((raw >> 5) & 0x7ffff)
			immlo := int64((raw >> 29) & 0x3)
			offset := (immhi << 2) | immlo
			if offset&(1<<20) != 0 {
				offset |= ^int64((1 << 21) - 1)
			}
			addr := uint64(int64(pc) + offset)
			regBase[rd] = addr
			regValue[rd] = addr
		}

	// ADD (immediate, 64-bit): 1 00 10001 sh imm12 Rn Rd
	case (raw & 0xff000000) == 0x91000000:
		rd := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		if rd < 31 && rn < 31 {
			imm := uint64((raw >> 10) & 0xfff)
			if (raw>>22)&1 == 1 {
				imm <<= 12
			}
			srcBase := regBase[rn]
			regBase[rd] = 0
			regValue[rd] = 0
			if srcBase != 0 {
				regBase[rd] = srcBase + imm
				regValue[rd] = srcBase + imm
			} else if regValue[rn] != 0 {
				regValue[rd] = regValue[rn] + imm
			}
		}

	// SUB (immediate, 64-bit): 1 10 10001 sh imm12 Rn Rd
	case (raw & 0xff000000) == 0xd1000000:
		rd := int(raw & 0x1f)
		if rd < 31 {
			regBase[rd] = 0
			regValue[rd] = 0
		}

	// ORR (shifted register, 64-bit): 1 01 01010 sh 0 Rm imm6 Rn Rd
	// MOV register is ORR Xd, XZR, Xm (Rn == XZR, shift == 0, imm6 == 0)
	case (raw & 0xff200000) == 0xaa000000:
		rd := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		rm := int((raw >> 16) & 0x1f)
		imm6 := (raw >> 10) & 0x3f
		if rd < 31 {
			regBase[rd] = 0
			regValue[rd] = 0
			if rn == 31 && imm6 == 0 && rm < 31 {
				// MOV Xd, Xm
				regBase[rd] = regBase[rm]
				regValue[rd] = regValue[rm]
			} else if rm == 31 && imm6 == 0 && rn < 31 {
				// MOV Xd, Xn (rare but valid)
				regBase[rd] = regBase[rn]
				regValue[rd] = regValue[rn]
			}
		}

	// MOVZ (32/64): sf 10 100101 hw imm16 Rd
	case (raw & 0x7f800000) == 0x52800000:
		rd := int(raw & 0x1f)
		if rd < 31 {
			imm := uint64((raw >> 5) & 0xffff)
			hw := (raw >> 21) & 0x3
			regBase[rd] = 0
			regValue[rd] = imm << (hw * 16)
			if (raw>>31)&1 == 0 {
				regValue[rd] &= 0xffff_ffff
			}
		}

	// MOVK (32/64): sf 11 100101 hw imm16 Rd
	case (raw & 0x7f800000) == 0x72800000:
		rd := int(raw & 0x1f)
		if rd < 31 {
			imm := uint64((raw >> 5) & 0xffff)
			hw := (raw >> 21) & 0x3
			shift := hw * 16
			mask := uint64(0xffff) << shift
			regBase[rd] = 0
			regValue[rd] = (regValue[rd] &^ mask) | (imm << shift)
			if (raw>>31)&1 == 0 {
				regValue[rd] &= 0xffff_ffff
			}
		}

	// LDR (unsigned offset, 64-bit): 11 111 00101 imm12 Rn Rt
	case (raw & 0xffc00000) == 0xf9400000:
		rt := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		if rt < 31 && rn < 31 {
			imm := uint64((raw>>10)&0xfff) * 8
			regBase[rt] = 0
			regValue[rt] = 0
			base := regBase[rn]
			if base == 0 {
				base = regValue[rn]
			}
			if base != 0 {
				addr := base + imm
				if ptr, ok := s.resolvePointerAt(owner, addr); ok {
					regValue[rt] = ptr
				} else if validKernelPointer(addr) {
					regValue[rt] = addr
				}
			}
		}

	// LDR (unsigned offset, 32-bit): 10 111 00101 imm12 Rn Rt
	case (raw & 0xffc00000) == 0xb9400000:
		rt := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		if rt < 31 && rn < 31 {
			imm := uint64((raw>>10)&0xfff) * 4
			regBase[rt] = 0
			regValue[rt] = 0
			base := regBase[rn]
			if base == 0 {
				base = regValue[rn]
			}
			if base != 0 {
				addr := base + imm
				if ptr, ok := s.resolvePointerAt(owner, addr); ok {
					regValue[rt] = ptr
				} else if validKernelPointer(addr) {
					regValue[rt] = addr
				}
			}
		}

	// LDUR (64-bit): 11 111000 010 imm9 00 Rn Rt
	case (raw & 0xffe00c00) == 0xf8400000:
		rt := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		if rt < 31 && rn < 31 {
			imm9 := int64((raw >> 12) & 0x1ff)
			if imm9&(1<<8) != 0 {
				imm9 |= ^int64((1 << 9) - 1)
			}
			regBase[rt] = 0
			regValue[rt] = 0
			base := regBase[rn]
			if base == 0 {
				base = regValue[rn]
			}
			if base != 0 {
				addr := uint64(int64(base) + imm9)
				if ptr, ok := s.resolvePointerAt(owner, addr); ok {
					regValue[rt] = ptr
				} else if validKernelPointer(addr) {
					regValue[rt] = addr
				}
			}
		}

	// LDP (signed offset, 64-bit): x0 101 0 010 1 imm7 Rt2 Rn Rt
	case (raw & 0x7fc00000) == 0xa9400000:
		rt := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		rt2 := int((raw >> 10) & 0x1f)
		if rn < 31 {
			imm7 := int64((raw >> 15) & 0x7f)
			if imm7&(1<<6) != 0 {
				imm7 |= ^int64((1 << 7) - 1)
			}
			base := regBase[rn]
			if base == 0 {
				base = regValue[rn]
			}
			addr := uint64(0)
			if base != 0 {
				addr = uint64(int64(base) + imm7*8)
			}
			if rt < 31 {
				regBase[rt] = 0
				regValue[rt] = 0
				if addr != 0 {
					if ptr, ok := s.resolvePointerAt(owner, addr); ok {
						regValue[rt] = ptr
					} else if validKernelPointer(addr) {
						regValue[rt] = addr
					}
				}
			}
			if rt2 < 31 {
				regBase[rt2] = 0
				regValue[rt2] = 0
				if addr != 0 {
					addr2 := addr + 8
					if ptr, ok := s.resolvePointerAt(owner, addr2); ok {
						regValue[rt2] = ptr
					} else if validKernelPointer(addr2) {
						regValue[rt2] = addr2
					}
				}
			}
		}
	}
}

func (s *Scanner) staticDirectCallContext(owner *macho.File, fn types.Function, callsite uint64, target uint64) (wrapperContext, bool) {
	key := staticCallKey{file: owner, start: fn.StartAddr, callsite: callsite, target: target}
	if cached, ok := s.staticCalls[key]; ok {
		return cached.ctx, cached.ok
	}
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		s.staticCalls[key] = cachedWrapperContext{}
		return wrapperContext{}, false
	}

	var regBase [31]uint64
	var regLoadAddr [31]uint64
	var regValue [31]uint64
	for i := 0; i+4 <= len(data); i += 4 {
		pc := fn.StartAddr + uint64(i)
		raw := readUint32At(data, i)

		if (raw & 0x9f000000) == 0x90000000 {
			rd := int(raw & 0x1f)
			if rd < 31 {
				if addr, ok := decodeADRPImmediate(pc, raw); ok {
					regBase[rd] = addr
					regLoadAddr[rd] = 0
					regValue[rd] = 0
				}
			}
			continue
		}

		if (callsite == 0 || pc == callsite) && target != 0 {
			if callTarget, ok := decodeBLTarget(pc, raw); ok && callTarget == target {
				ctx := s.staticDirectCallTrackedContext(owner, regBase, regLoadAddr, regValue, pc)
				s.staticCalls[key] = cachedWrapperContext{ctx: ctx, ok: true}
				return ctx, true
			}
			if callTarget, ok := decodeBTarget(pc, raw); ok && callTarget == target {
				ctx := s.staticDirectCallTrackedContext(owner, regBase, regLoadAddr, regValue, pc)
				s.staticCalls[key] = cachedWrapperContext{ctx: ctx, ok: true}
				return ctx, true
			}
		}

		var ins disassemble.Inst
		if err := s.decodeArm64Instruction(pc, raw, &ins); err != nil || operandCount(&ins) == 0 {
			continue
		}

		s.trackStaticValueInstruction(owner, &regBase, &regLoadAddr, &regValue, &ins, staticValueTrackOptions{
			acceptAnyLoadAddr:      false,
			propagateLoadAddrInAdd: true,
			handleLoadPairs:        true,
		})
	}
	s.staticCalls[key] = cachedWrapperContext{}
	return wrapperContext{}, false
}

func (s *Scanner) staticDirectCallTrackedContext(owner *macho.File, regBase [31]uint64, regLoadAddr [31]uint64, regValue [31]uint64, callsite uint64) wrapperContext {
	for reg := range 4 {
		if regValue[reg] == 0 && regBase[reg] != 0 {
			regValue[reg] = regBase[reg]
		}
		if reg == 2 && regValue[reg] != 0 && !validKernelPointer(regValue[reg]) {
			regValue[reg] = s.normalizeLoadedPointer(owner, regValue[reg])
		}
	}
	return wrapperContext{
		x0:       regValue[0],
		x1:       regValue[1],
		x2:       regValue[2],
		x3:       regValue[3],
		callsite: callsite,
	}
}

func mergeWrapperContext(dst, src wrapperContext) wrapperContext {
	if dst.x0 == 0 {
		dst.x0 = src.x0
	}
	if dst.x1 == 0 {
		dst.x1 = src.x1
	}
	if dst.x2 == 0 {
		dst.x2 = src.x2
	}
	if dst.x3 == 0 {
		dst.x3 = src.x3
	}
	if dst.metaVtab == 0 {
		dst.metaVtab = src.metaVtab
	}
	if dst.callsite == 0 {
		dst.callsite = src.callsite
	}
	return dst
}

func wrapperContextEmpty(ctx *wrapperContext) bool {
	return ctx == nil || (ctx.x0 == 0 && ctx.x1 == 0 && ctx.x2 == 0 && ctx.x3 == 0 && ctx.metaVtab == 0)
}

func (s *Scanner) recoverStaticWrapperContext(owner *macho.File, startAddr uint64, canonicalStart uint64) (*wrapperContext, bool) {
	ctx, ok := s.recoverStaticWrapperContextDepth(owner, startAddr, canonicalStart, 0, wrapperContext{})
	if !ok {
		return nil, false
	}
	return &ctx, true
}

func (s *Scanner) recoverStaticWrapperContextDepth(owner *macho.File, startAddr uint64, canonicalStart uint64, depth int, accum wrapperContext) (wrapperContext, bool) {
	if owner == nil || depth > s.cfg.MaxWrapperDepth {
		return wrapperContext{}, false
	}
	fn, _, err := s.functionForAddrInAnyFile(owner, startAddr)
	if err != nil {
		return wrapperContext{}, false
	}
	return s.staticWrapperContextAlongPath(owner, fn, canonicalStart, depth, accum)
}

func (s *Scanner) staticWrapperContextAlongPath(owner *macho.File, fn types.Function, canonicalStart uint64, depth int, accum wrapperContext) (wrapperContext, bool) {
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		return wrapperContext{}, false
	}

	var regBase [31]uint64
	var regLoadAddr [31]uint64
	var regValue [31]uint64

	for i := 0; i+4 <= len(data); i += 4 {
		pc := fn.StartAddr + uint64(i)
		raw := readUint32At(data, i)

		if (raw & 0x9f000000) == 0x90000000 {
			rd := int(raw & 0x1f)
			if rd < 31 {
				if addr, ok := decodeADRPImmediate(pc, raw); ok {
					regBase[rd] = addr
					regLoadAddr[rd] = 0
					regValue[rd] = 0
				}
			}
			continue
		}

		var ins disassemble.Inst
		if err := s.decodeArm64Instruction(pc, raw, &ins); err != nil || operandCount(&ins) == 0 {
			continue
		}

		s.trackStaticValueInstruction(owner, &regBase, &regLoadAddr, &regValue, &ins, staticValueTrackOptions{
			acceptAnyLoadAddr:      true,
			propagateLoadAddrInAdd: false,
			handleLoadPairs:        false,
		})

		for reg := range 4 {
			if regValue[reg] == 0 && regBase[reg] != 0 {
				regValue[reg] = regBase[reg]
			}
			if reg == 2 && regValue[reg] != 0 && !validKernelPointer(regValue[reg]) {
				regValue[reg] = s.normalizeLoadedPointer(owner, regValue[reg])
			}
		}

		var nextTarget uint64
		if blTarget, ok := decodeBLTarget(pc, raw); ok {
			nextTarget = blTarget
		} else if bTarget, ok := decodeBTarget(pc, raw); ok {
			nextTarget = bTarget
		}
		if nextTarget == 0 || s.isOSMetaClassVariant(nextTarget) {
			continue
		}

		ctx := mergeWrapperContext(accum, wrapperContext{
			x0:       regValue[0],
			x1:       regValue[1],
			x2:       regValue[2],
			x3:       regValue[3],
			callsite: pc,
		})
		if nextTarget == canonicalStart {
			return ctx, true
		}
		if depth >= s.cfg.MaxWrapperDepth {
			continue
		}
		if nested, ok := s.recoverStaticWrapperContextDepth(owner, nextTarget, canonicalStart, depth+1, ctx); ok {
			return nested, true
		}
	}
	return wrapperContext{}, false
}
