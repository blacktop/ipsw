package cpp

import (
	"fmt"
	"time"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
)

func registerToIndex(reg disassemble.Register) (int, bool) {
	switch {
	case reg >= disassemble.REG_X0 && reg <= disassemble.REG_X30:
		return int(reg - disassemble.REG_X0), true
	case reg >= disassemble.REG_W0 && reg <= disassemble.REG_W30:
		return int(reg - disassemble.REG_W0), true
	default:
		return 0, false
	}
}

func stackAddressFromOperand(state *microState, op *disassemble.Op) (uint64, bool) {
	baseReg, ok := operandRegister(op, 0)
	if !ok || baseReg != disassemble.REG_SP {
		return 0, false
	}

	base := state.GetSP()
	switch op.Class {
	case disassemble.MEM_OFFSET:
		return addSignedOffset(base, int64(op.GetImmediate()))
	case disassemble.MEM_PRE_IDX:
		return addSignedOffset(base, int64(op.GetImmediate()))
	case disassemble.MEM_POST_IDX:
		return base, true
	default:
		return 0, false
	}
}

func captureX0Spill(state *microState, inst *disassemble.Inst) (uint64, uint64, bool) {
	if inst == nil {
		return 0, 0, false
	}

	switch inst.Operation {
	case disassemble.ARM64_STR, disassemble.ARM64_STUR:
		if operandCount(inst) < 2 || !operandHasRegister(&inst.Operands[0], disassemble.REG_X0) {
			return 0, 0, false
		}
		addr, ok := stackAddressFromOperand(state, &inst.Operands[1])
		if !ok {
			return 0, 0, false
		}
		return addr, state.GetX(0), true
	case disassemble.ARM64_STP:
		if operandCount(inst) < 3 {
			return 0, 0, false
		}
		addr, ok := stackAddressFromOperand(state, &inst.Operands[2])
		if !ok {
			return 0, 0, false
		}
		if operandHasRegister(&inst.Operands[0], disassemble.REG_X0) {
			return addr, state.GetX(0), true
		}
		if operandHasRegister(&inst.Operands[1], disassemble.REG_X0) {
			addr2, ok := addSignedOffset(addr, 8)
			if !ok {
				return addr, state.GetX(0), true
			}
			return addr2, state.GetX(0), true
		}
	}

	return 0, 0, false
}

type trackedSpill struct {
	addr  uint64
	value uint64
	valid bool
}

func recordTrackedSpill(spills *[4]trackedSpill, reg disassemble.Register, addr uint64, value uint64) {
	idx, ok := registerToIndex(reg)
	if !ok || idx < 0 || idx >= len(spills) {
		return
	}
	spills[idx] = trackedSpill{
		addr:  addr,
		value: value,
		valid: true,
	}
}

func captureRegisterSpills(state *microState, inst *disassemble.Inst, spills *[4]trackedSpill) {
	if inst == nil {
		return
	}

	switch inst.Operation {
	case disassemble.ARM64_STR, disassemble.ARM64_STUR:
		reg, ok := operandRegister(&inst.Operands[0], 0)
		if operandCount(inst) < 2 || !ok {
			return
		}
		addr, ok := stackAddressFromOperand(state, &inst.Operands[1])
		if !ok {
			return
		}
		idx, ok := registerToIndex(reg)
		if !ok || idx < 0 || idx >= len(spills) {
			return
		}
		recordTrackedSpill(spills, reg, addr, state.GetX(idx))
	case disassemble.ARM64_STP:
		if operandCount(inst) < 3 {
			return
		}
		addr, ok := stackAddressFromOperand(state, &inst.Operands[2])
		if !ok {
			return
		}
		if reg, ok := operandRegister(&inst.Operands[0], 0); ok {
			if idx, ok := registerToIndex(reg); ok && idx < len(spills) {
				recordTrackedSpill(spills, reg, addr, state.GetX(idx))
			}
		}
		if reg, ok := operandRegister(&inst.Operands[1], 0); ok {
			if addr2, ok := addSignedOffset(addr, 8); ok {
				if idx, ok := registerToIndex(reg); ok && idx < len(spills) {
					recordTrackedSpill(spills, reg, addr2, state.GetX(idx))
				}
			}
		}
	}
}

func recoverSpilledRegister(state *microState, spills *[4]trackedSpill, reg int) uint64 {
	value := state.GetX(reg)
	if value != 0 {
		return value
	}
	if reg < 0 || reg >= len(spills) {
		return value
	}
	if spills[reg].valid && spills[reg].value != 0 {
		return spills[reg].value
	}
	if spills[reg].addr != 0 {
		if restored, err := state.ReadUint64(spills[reg].addr); err == nil && restored != 0 {
			return restored
		}
	}
	return value
}

func (s *Scanner) extractClassesFromCtor(path ctorPath) ([]discoveredClass, error) {
	funcData, err := s.functionDataFor(path.owner, path.fn)
	if err != nil {
		return nil, fmt.Errorf("read ctor %#x: %w", path.fn.StartAddr, err)
	}

	requiredInstructions := s.cfg.MaxCtorInstructions
	lastAnchorOffset := -1
	ctorCallCount := 0
	for off := 0; off+4 <= len(funcData); off += 4 {
		pc := path.fn.StartAddr + uint64(off)
		raw := readUint32At(funcData, off)
		if target, ok := decodeBLTarget(pc, raw); ok && s.isOSMetaClassVariant(target) {
			lastAnchorOffset = off
			ctorCallCount++
			continue
		}
		if target, ok := decodeBTarget(pc, raw); ok && s.isOSMetaClassVariant(target) {
			lastAnchorOffset = off
			ctorCallCount++
		}
	}
	if lastAnchorOffset >= 0 {
		needed := (lastAnchorOffset / 4) + 128
		if needed > requiredInstructions {
			requiredInstructions = needed
		}
	}

	classes := make([]discoveredClass, 0, 4)
	var pending *pendingClass
	var lastSpillAddr uint64
	var lastSpillValue uint64

	finalizePending := func() {
		if pending == nil {
			return
		}
		if pending.metaVtableAddr == 0 && path.preload != nil && validKernelPointer(path.preload.metaVtab) {
			pending.metaVtableAddr = path.preload.metaVtab
		}
		if pending.metaVtableAddr == 0 {
			if fallback := s.readMetaVtableFallback(pending.metaPtr); validKernelPointer(fallback) {
				pending.metaVtableAddr = fallback
			}
		}
		className, err := s.cachedCStringAt(pending.namePtr)
		if err != nil || className == "" || !looksLikeRecoveredClassName(className) {
			className = fmt.Sprintf("UnknownClass_%#x", pending.metaPtr)
		}
		classes = append(classes, discoveredClass{
			Class: Class{
				Name:           className,
				Bundle:         path.entryID,
				Size:           uint32(pending.size),
				Ctor:           pending.ctor,
				MetaPtr:        pending.metaPtr,
				SuperMeta:      pending.superMeta,
				SuperIndex:     -1,
				MetaVtableAddr: pending.metaVtableAddr,
			},
			file: path.owner,
		})
		pending = nil
	}

	maxOffset := max(requiredInstructions*4-4, 0)
	plan := buildMicroPlan(path.fn.StartAddr, funcData, s.isOSMetaClassVariant, maxOffset)
	state := newMicroState(path.owner, path.fn.StartAddr)
	s.stats.engineCreations++
	if path.preload != nil {
		state.SetX(0, path.preload.x0)
		state.SetX(1, path.preload.x1)
		state.SetX(2, path.preload.x2)
		state.SetX(3, path.preload.x3)
	}

	visited := make([]bool, len(plan.tags))
	for off := 0; off+4 <= len(funcData) && off <= plan.maxOffset; {
		pc := path.fn.StartAddr + uint64(off)
		raw := readUint32At(funcData, off)
		idx := off / 4
		if idx < len(visited) && visited[idx] {
			break
		}
		if idx < len(visited) {
			visited[idx] = true
		}
		nextOff := off + 4

		if plan.tags[idx]&microTagRET != 0 {
			break
		}

		if plan.tags[idx]&(microTagBL|microTagB) != 0 && s.isOSMetaClassVariant(plan.targets[idx]) {
			finalizePending()

			metaPtr := recoveredTrackedValue(state, 0, true)
			if metaPtr == 0 {
				metaPtr = lastSpillValue
			}
			if metaPtr == 0 && lastSpillAddr != 0 {
				if val, err := state.ReadUint64(lastSpillAddr); err == nil {
					metaPtr = val
				}
			}
			if metaPtr == 0 && ctorCallCount == 1 {
				if inferred := s.inferMetaPtrFromDirectCallers(path.owner, path.fn.StartAddr); validKernelPointer(inferred) {
					metaPtr = inferred
					state.SetX(0, metaPtr)
				}
			}
			if metaPtr == 0 && path.preload != nil && validKernelPointer(path.preload.x0) {
				metaPtr = path.preload.x0
				state.SetX(0, metaPtr)
			}
			metaPtr = s.normalizeLoadedPointer(path.owner, metaPtr)
			if !validMetaPointer(metaPtr) {
				metaPtr = 0
			}
			var fallback wrapperContext
			var haveFallback bool
			if metaPtr == 0 {
				if fallback, haveFallback = s.staticDirectCallContext(path.owner, path.fn, pc, plan.targets[idx]); haveFallback {
					metaPtr = s.normalizeLoadedPointer(path.owner, fallback.x0)
					if !validMetaPointer(metaPtr) {
						metaPtr = 0
					}
				}
			}

			if metaPtr != 0 {
				namePtr := recoveredTrackedValue(state, 1, true)
				size := recoveredTrackedValue(state, 3, false)
				superMeta := state.GetX(2)
				if state.regLoadAddr[2] != 0 {
					if resolved, ok := s.resolvePointerAtReason(path.owner, state.regLoadAddr[2], pointerReasonX2LoadRecovery); ok {
						superMeta = resolved
					}
				}

				if namePtr == 0 || size == 0 || size > 0xffffffff || !validMetaPointer(superMeta) {
					if !haveFallback {
						fallback, haveFallback = s.staticDirectCallContext(path.owner, path.fn, pc, plan.targets[idx])
					}
					if haveFallback {
						if namePtr == 0 {
							namePtr = fallback.x1
						}
						if size == 0 {
							size = fallback.x3
						}
						if !validMetaPointer(superMeta) {
							superMeta = fallback.x2
						}
					}
				}
				if namePtr == 0 && path.preload != nil {
					namePtr = path.preload.x1
				}
				if size == 0 && path.preload != nil {
					size = path.preload.x3
				}
				if namePtr == 0 || size == 0 || size > 0xffffffff {
					lastSpillAddr = 0
					lastSpillValue = 0
					state.resetCallEvidence()
					off = nextOff
					continue
				}
				className, err := s.cachedCStringAt(namePtr)
				if err != nil || className == "" || !looksLikeRecoveredClassName(className) {
					lastSpillAddr = 0
					lastSpillValue = 0
					state.resetCallEvidence()
					off = nextOff
					continue
				}
				if !validMetaPointer(superMeta) && path.preload != nil {
					superMeta = path.preload.x2
				}
				if !validMetaPointer(superMeta) {
					superMeta = s.normalizeLoadedPointer(path.owner, superMeta)
				}
				if !validMetaPointer(superMeta) {
					superMeta = 0
				}
				pending = &pendingClass{
					metaPtr:        metaPtr,
					namePtr:        namePtr,
					superMeta:      superMeta,
					size:           size,
					ctor:           pc,
					metaVtableAddr: 0,
				}
				state.x16Candidate = 0
			}

			lastSpillAddr = 0
			lastSpillValue = 0
			state.resetCallEvidence()
			off = nextOff
			continue
		}

		var inst disassemble.Inst
		instOK := s.decodeArm64Instruction(pc, raw, &inst) == nil
		if instOK && isConditionalBranchOperation(inst.Operation) {
			break
		}
		if addr, val, ok := captureX0Spill(state, instPtr(instOK, &inst)); ok {
			lastSpillAddr = addr
			lastSpillValue = val
			recordTrackedSpill(&state.spills, disassemble.REG_X0, addr, val)
		}
		s.applyMicroInstruction(state, instPtr(instOK, &inst))

		if pending != nil && pending.metaVtableAddr == 0 {
			if access, src, count, ok := state.classifyStore(instPtr(instOK, &inst)); ok && access.addr == pending.metaPtr {
				for i := range count {
					if src[i] != 16 {
						continue
					}
					switch {
					case validKernelPointer(state.x16Candidate):
						pending.metaVtableAddr = state.x16Candidate
					case validKernelPointer(state.GetX(16)):
						pending.metaVtableAddr = state.GetX(16)
					}
					break
				}
			}
		}
		if plan.tags[idx]&microTagB != 0 {
			if branchOff, ok := localBranchOffset(path.fn.StartAddr, len(funcData), plan.maxOffset, plan.targets[idx]); ok {
				off = branchOff
				continue
			}
			break
		}
		if target, ok := branchTargetFromState(state, instPtr(instOK, &inst)); ok {
			if branchOff, ok := localBranchOffset(path.fn.StartAddr, len(funcData), plan.maxOffset, target); ok {
				off = branchOff
				continue
			}
			break
		}
		off = nextOff
	}

	finalizePending()
	tRecover := time.Now()
	classes = s.recoverStaticAnchorClasses(path, plan, classes)
	s.stats.phaseTimings.recoverStaticAnchorClasses += time.Since(tRecover)
	return classes, nil
}

func (s *Scanner) recoverStaticAnchorClasses(path ctorPath, plan microPlan, classes []discoveredClass) []discoveredClass {
	knownMeta := make(map[uint64]struct{}, len(classes))
	for _, class := range classes {
		if class.MetaPtr != 0 {
			knownMeta[class.MetaPtr] = struct{}{}
		}
	}

	// Batch: single pass through function data, capturing register
	// state at every anchor callsite instead of re-scanning from
	// byte 0 for each one.
	ctxMap := s.batchStaticCallContexts(path.owner, path.fn, plan)

	for idx, tag := range plan.tags {
		if tag&(microTagBL|microTagB) == 0 || !s.isOSMetaClassVariant(plan.targets[idx]) {
			continue
		}
		pc := path.fn.StartAddr + uint64(idx*4)
		ctx, ok := ctxMap[pc]
		if !ok {
			continue
		}

		metaPtr := s.normalizeLoadedPointer(path.owner, ctx.x0)
		if !validMetaPointer(metaPtr) {
			continue
		}
		if _, seen := knownMeta[metaPtr]; seen {
			continue
		}

		namePtr := ctx.x1
		size := ctx.x3
		if namePtr == 0 || size == 0 || size > 0xffffffff {
			continue
		}

		superMeta := ctx.x2
		if !validMetaPointer(superMeta) && path.preload != nil {
			superMeta = path.preload.x2
		}
		if !validMetaPointer(superMeta) {
			superMeta = s.normalizeLoadedPointer(path.owner, superMeta)
		}
		if !validMetaPointer(superMeta) {
			superMeta = 0
		}

		metaVtable := uint64(0)
		if path.preload != nil && validKernelPointer(path.preload.metaVtab) {
			metaVtable = path.preload.metaVtab
		}
		if metaVtable == 0 {
			if fallback := s.readMetaVtableFallback(metaPtr); validKernelPointer(fallback) {
				metaVtable = fallback
			}
		}

		className, err := getCStringFromAny(s.root, s.fileForVMAddr(namePtr), namePtr)
		if err != nil || className == "" || !looksLikeRecoveredClassName(className) {
			className = fmt.Sprintf("UnknownClass_%#x", metaPtr)
		}
		candidate := discoveredClass{
			Class: Class{
				Name:           className,
				Bundle:         path.entryID,
				Size:           uint32(size),
				Ctor:           pc,
				MetaPtr:        metaPtr,
				SuperMeta:      superMeta,
				SuperIndex:     -1,
				MetaVtableAddr: metaVtable,
			},
			file: path.owner,
		}
		if recoveredClassNameScore(candidate.Name) < 2 && !hasStrongClassEvidence(candidate) {
			continue
		}

		classes = append(classes, candidate)
		knownMeta[metaPtr] = struct{}{}
	}

	return classes
}

func (s *Scanner) simulateWrapperContext(startFile *macho.File, startAddr uint64, canonicalStart uint64) (*wrapperContext, bool) {
	fn, owner, err := s.functionForAddrInAnyFile(startFile, startAddr)
	if err != nil {
		return nil, false
	}
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		return nil, false
	}

	maxOffset := len(data) - 4
	if limit := 256*4 - 4; limit >= 0 && limit < maxOffset {
		maxOffset = limit
	}
	plan := buildMicroPlan(fn.StartAddr, data, nil, maxOffset)
	state := newMicroState(owner, fn.StartAddr)
	s.stats.engineCreations++

	resolveX2 := func(x2 uint64) uint64 {
		if state.regLoadAddr[2] != 0 {
			if ptr, ok := s.resolvePointerAtReason(owner, state.regLoadAddr[2], pointerReasonX2LoadRecovery); ok && validMetaPointer(ptr) {
				return ptr
			}
		}
		if validMetaPointer(x2) {
			return x2
		}
		resolved := s.normalizeLoadedPointer(owner, x2)
		if validMetaPointer(resolved) {
			return resolved
		}
		return 0
	}
	captureCtx := func(callsite uint64) *wrapperContext {
		return &wrapperContext{
			x0:       recoveredTrackedValue(state, 0, true),
			x1:       recoveredTrackedValue(state, 1, true),
			x2:       resolveX2(recoveredTrackedValue(state, 2, true)),
			x3:       recoveredTrackedValue(state, 3, false),
			callsite: callsite,
		}
	}

	var captured *wrapperContext
	visited := make([]bool, len(plan.tags))
	for off := 0; off+4 <= len(data) && off <= plan.maxOffset; {
		pc := fn.StartAddr + uint64(off)
		if pc == canonicalStart {
			return captureCtx(pc), true
		}

		raw := readUint32At(data, off)
		idx := off / 4
		if idx < len(visited) && visited[idx] {
			break
		}
		if idx < len(visited) {
			visited[idx] = true
		}
		nextOff := off + 4
		if plan.tags[idx]&microTagRET != 0 {
			break
		}
		if plan.tags[idx]&(microTagBL|microTagB) != 0 {
			target := plan.targets[idx]
			if target == canonicalStart {
				if captured == nil {
					captured = captureCtx(pc)
				}
				off = nextOff
				continue
			}
			if s.isOSMetaClassVariant(target) {
				off = nextOff
				continue
			}
		}

		var inst disassemble.Inst
		instOK := s.decodeArm64Instruction(pc, raw, &inst) == nil
		if instOK && isConditionalBranchOperation(inst.Operation) {
			break
		}
		s.applyMicroInstruction(state, instPtr(instOK, &inst))

		if captured != nil && captured.metaVtab == 0 {
			if access, src, count, ok := state.classifyStore(instPtr(instOK, &inst)); ok && access.addr == captured.x0 {
				for i := range count {
					if src[i] != 16 {
						continue
					}
					switch {
					case validKernelPointer(state.x16Candidate):
						captured.metaVtab = state.x16Candidate
					case validKernelPointer(state.GetX(16)):
						captured.metaVtab = state.GetX(16)
					}
					if captured.metaVtab != 0 {
						return captured, true
					}
				}
			}
		}
		if plan.tags[idx]&microTagB != 0 {
			target := plan.targets[idx]
			if target == canonicalStart {
				return captureCtx(canonicalStart), true
			}
			if branchOff, ok := localBranchOffset(fn.StartAddr, len(data), plan.maxOffset, target); ok {
				off = branchOff
				continue
			}
			break
		}
		if target, ok := branchTargetFromState(state, instPtr(instOK, &inst)); ok {
			if target == canonicalStart {
				return captureCtx(canonicalStart), true
			}
			if branchOff, ok := localBranchOffset(fn.StartAddr, len(data), plan.maxOffset, target); ok {
				off = branchOff
				continue
			}
			break
		}
		off = nextOff
	}

	return captured, captured != nil
}

func (s *Scanner) recoverMetaVtableFromCaller(m *macho.File, class *discoveredClass) uint64 {
	if ctx, ok := s.recoverCallsiteContext(m, class); ok && validKernelPointer(ctx.metaVtab) {
		return ctx.metaVtab
	}
	return 0
}

func (s *Scanner) recoverCallsiteContext(m *macho.File, class *discoveredClass) (wrapperContext, bool) {
	if class == nil || class.Ctor == 0 {
		return wrapperContext{}, false
	}
	key := fileAddrKey{file: m, addr: class.Ctor}
	if ctx, ok := s.callsiteCtx[key]; ok {
		return ctx, true
	}

	fn, owner, err := s.functionForAddrInAnyFile(m, class.Ctor)
	if err != nil {
		return wrapperContext{}, false
	}
	data, err := s.functionDataFor(owner, fn)
	if err != nil {
		return wrapperContext{}, false
	}

	maxOffset := len(data) - 4
	if limit := int(class.Ctor-fn.StartAddr) + 64*4; limit >= 0 && limit < maxOffset {
		maxOffset = limit
	}
	plan := buildMicroPlan(fn.StartAddr, data, nil, maxOffset)
	state := newMicroState(owner, fn.StartAddr)
	s.stats.engineCreations++

	resolveX2 := func(x2 uint64) uint64 {
		if state.regLoadAddr[2] != 0 {
			if resolved, ok := s.resolvePointerAtReason(owner, state.regLoadAddr[2], pointerReasonX2LoadRecovery); ok && validMetaPointer(resolved) {
				return resolved
			}
		}
		if !validMetaPointer(x2) {
			x2 = s.normalizeLoadedPointer(owner, x2)
		}
		if !validMetaPointer(x2) {
			return 0
		}
		return x2
	}

	var recovered wrapperContext
	captured := false
	expectedMetaPtr := func() uint64 {
		if class.MetaPtr != 0 {
			return class.MetaPtr
		}
		if validKernelPointer(recovered.x0) {
			return recovered.x0
		}
		return state.GetX(0)
	}

	visited := make([]bool, len(plan.tags))
	for off := 0; off+4 <= len(data) && off <= plan.maxOffset; {
		pc := fn.StartAddr + uint64(off)
		raw := readUint32At(data, off)
		idx := off / 4
		if idx < len(visited) && visited[idx] {
			break
		}
		if idx < len(visited) {
			visited[idx] = true
		}
		nextOff := off + 4

		if plan.tags[idx]&microTagRET != 0 {
			break
		}

		if pc == class.Ctor && plan.tags[idx]&(microTagBL|microTagB) != 0 {
			recovered.x0 = recoveredTrackedValue(state, 0, true)
			recovered.x1 = recoveredTrackedValue(state, 1, true)
			recovered.x2 = resolveX2(recoveredTrackedValue(state, 2, true))
			recovered.x3 = recoveredTrackedValue(state, 3, false)
			recovered.callsite = pc
			captured = true
			if class.MetaPtr != 0 {
				state.SetX(0, class.MetaPtr)
			}
			off = nextOff
			continue
		}

		var inst disassemble.Inst
		instOK := s.decodeArm64Instruction(pc, raw, &inst) == nil
		if instOK && isConditionalBranchOperation(inst.Operation) {
			break
		}
		s.applyMicroInstruction(state, instPtr(instOK, &inst))

		if captured && recovered.metaVtab == 0 {
			expected := expectedMetaPtr()
			if expected == 0 {
				continue
			}
			if access, src, count, ok := state.classifyStore(instPtr(instOK, &inst)); ok && access.addr == expected {
				for i := range count {
					if src[i] != 16 {
						continue
					}
					switch {
					case validKernelPointer(state.x16Candidate):
						recovered.metaVtab = state.x16Candidate
					case validKernelPointer(state.GetX(16)):
						recovered.metaVtab = state.GetX(16)
					}
					if recovered.metaVtab != 0 {
						s.callsiteCtx[key] = recovered
						return recovered, true
					}
				}
			}
		}
		if plan.tags[idx]&microTagB != 0 {
			if branchOff, ok := localBranchOffset(fn.StartAddr, len(data), plan.maxOffset, plan.targets[idx]); ok {
				off = branchOff
				continue
			}
			break
		}
		if target, ok := branchTargetFromState(state, instPtr(instOK, &inst)); ok {
			if branchOff, ok := localBranchOffset(fn.StartAddr, len(data), plan.maxOffset, target); ok {
				off = branchOff
				continue
			}
			break
		}
		off = nextOff
	}

	if captured {
		s.callsiteCtx[key] = recovered
		return recovered, true
	}
	return wrapperContext{}, false
}

func (s *Scanner) recoverMetaVtableFromCtorPattern(m *macho.File, class *discoveredClass) uint64 {
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

	offset := int(class.Ctor - fn.StartAddr)
	if offset < 0 || offset >= len(data) {
		return 0
	}

	var x16Base uint64
	var candidate uint64
	limit := min(offset+32*4, len(data))

	for i := offset; i+4 <= limit; i += 4 {
		pc := fn.StartAddr + uint64(i)
		raw := readUint32At(data, i)

		if (raw & 0x9f00001f) == 0x90000010 {
			if addr, ok := decodeADRPImmediate(pc, raw); ok {
				x16Base = addr
				continue
			}
		}

		var ins disassemble.Inst
		if err := s.decodeArm64Instruction(pc, raw, &ins); err != nil {
			continue
		}

		if ins.Operation == disassemble.ARM64_ADD &&
			operandCount(&ins) >= 3 &&
			operandHasRegister(&ins.Operands[0], disassemble.REG_X16) &&
			operandHasRegister(&ins.Operands[1], disassemble.REG_X16) &&
			x16Base != 0 {
			x16Base += uint64(ins.Operands[2].Immediate)
			continue
		}

		if candidate == 0 &&
			isPACOperation(ins.Operation) &&
			operandCount(&ins) > 0 &&
			operandHasRegister(&ins.Operands[0], disassemble.REG_X16) &&
			validKernelPointer(x16Base) {
			candidate = x16Base
			continue
		}

		if candidate == 0 || !validKernelPointer(candidate) {
			continue
		}

		switch ins.Operation {
		case disassemble.ARM64_STR, disassemble.ARM64_STUR:
			if operandCount(&ins) >= 2 &&
				operandHasRegister(&ins.Operands[0], disassemble.REG_X16) &&
				ins.Operands[1].GetImmediate() == 0 {
				return candidate
			}
		case disassemble.ARM64_STP:
			if operandCount(&ins) >= 3 &&
				(operandHasRegister(&ins.Operands[0], disassemble.REG_X16) || operandHasRegister(&ins.Operands[1], disassemble.REG_X16)) &&
				ins.Operands[2].GetImmediate() == 0 {
				return candidate
			}
		}
	}

	return 0
}
