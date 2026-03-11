package cpp

func matchSeedLoadX1(start uint64, data []byte, offset int, refs uint64Set) (int, uint64, bool) {
	if offset+8 > len(data) {
		return 0, 0, false
	}
	pc := start + uint64(offset)
	raw0 := readUint32At(data, offset)
	raw1 := readUint32At(data, offset+4)

	if (raw0&0x9f00001f) == 0x10000001 && isArm64Nop(raw1) {
		immhi := int64((raw0 >> 5) & 0x7ffff)
		immlo := int64((raw0 >> 29) & 0x3)
		offsetImm := (immhi << 2) | immlo
		if offsetImm&(1<<20) != 0 {
			offsetImm |= ^int64((1 << 21) - 1)
		}
		addr := uint64(int64(pc) + offsetImm)
		if hasUint64Set(refs, addr) {
			return offset + 8, addr, true
		}
	}

	if (raw0 & 0x9f000000) == 0x90000000 {
		adrpRd := int(raw0 & 0x1f)
		isAdd := (raw1 & 0x1f800000) == 0x11000000
		addRn := int((raw1 >> 5) & 0x1f)
		addRd := int(raw1 & 0x1f)
		if isAdd && adrpRd == addRn && addRd == 1 {
			page, ok := decodeADRPImmediate(pc, raw0)
			if ok {
				addImm := uint64((raw1 >> 10) & 0xfff)
				if (raw1>>22)&1 == 1 {
					addImm <<= 12
				}
				addr := page + addImm
				if hasUint64Set(refs, addr) {
					return offset + 8, addr, true
				}
			}
		}
	}

	return 0, 0, false
}

func isBranchRegisterRaw(raw uint32) bool {
	return (raw&0xfffffc1f) == 0xd61f0000 ||
		(raw&0xfffff800) == 0xd71f0800 ||
		(raw&0xfffff800) == 0xd63f0800
}

func isConditionalBranchRaw(raw uint32) bool {
	switch {
	case (raw & 0xff000010) == 0x54000000: // b.cond
		return true
	case (raw & 0x7e000000) == 0x34000000: // cbz/cbnz
		return true
	case (raw & 0x7e000000) == 0x36000000: // tbz/tbnz
		return true
	default:
		return false
	}
}

func invalidatesX1Raw(raw uint32) bool {
	switch {
	case (raw & 0x9f000000) == 0x90000000:
		return int(raw&0x1f) == 1
	case (raw & 0x9f000000) == 0x10000000:
		return int(raw&0x1f) == 1
	case (raw & 0xff000000) == 0x91000000:
		return int(raw&0x1f) == 1
	case (raw & 0xff000000) == 0xd1000000:
		return int(raw&0x1f) == 1
	case (raw & 0xff200000) == 0xaa000000:
		rd := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		rm := int((raw >> 16) & 0x1f)
		imm6 := (raw >> 10) & 0x3f
		if rd != 1 {
			return false
		}
		return !((rn == 31 && imm6 == 0 && rm == 1) || (rm == 31 && imm6 == 0 && rn == 1))
	case (raw & 0x7f800000) == 0x52800000:
		return int(raw&0x1f) == 1
	case (raw & 0x7f800000) == 0x72800000:
		return int(raw&0x1f) == 1
	case (raw & 0xffc00000) == 0xf9400000:
		return int(raw&0x1f) == 1
	case (raw & 0xffc00000) == 0xb9400000:
		return int(raw&0x1f) == 1
	case (raw & 0xffe00c00) == 0xf8400000:
		return int(raw&0x1f) == 1
	case (raw & 0x7fc00000) == 0xa9400000:
		return int(raw&0x1f) == 1 || int((raw>>10)&0x1f) == 1
	default:
		return false
	}
}

func isPassThroughSafeRaw(raw uint32) bool {
	switch {
	case isArm64Nop(raw), isPacibsp(raw), isReturnInstruction(raw):
		return true
	case (raw & 0xfc4003e0) == 0xa80003e0: // stp Xt1, Xt2, [sp, ...]
		return true
	case (raw & 0x7fc003ff) == 0xa9407bfd: // ldp x29, x30, [sp, ...]
		return true
	case (raw & 0xff0003ff) == 0x910003fd, // add x29, sp, #imm
		(raw & 0xff0003ff) == 0x910003ff, // add sp, sp, #imm
		(raw & 0xff0003ff) == 0xd10003ff: // sub sp, sp, #imm
		return true
	default:
		return false
	}
}

func isRawTrackable(raw uint32) bool {
	switch {
	case (raw & 0x9f000000) == 0x90000000,
		(raw & 0x9f000000) == 0x10000000,
		(raw & 0xff000000) == 0x91000000,
		(raw & 0xff000000) == 0xd1000000,
		(raw & 0xff200000) == 0xaa000000,
		(raw & 0x7f800000) == 0x52800000,
		(raw & 0x7f800000) == 0x72800000,
		(raw & 0xffc00000) == 0xf9400000,
		(raw & 0xffc00000) == 0xb9400000,
		(raw & 0xffe00c00) == 0xf8400000,
		(raw & 0x7fc00000) == 0xa9400000:
		return true
	default:
		return false
	}
}

func seedLoadStillInX1(data []byte, nextOff int, callOff int) bool {
	for off := nextOff; off < callOff && off+4 <= len(data); off += 4 {
		raw := readUint32At(data, off)
		if isPassThroughSafeRaw(raw) {
			continue
		}
		if invalidatesX1Raw(raw) {
			return false
		}
		if !isRawTrackable(raw) {
			return false
		}
	}
	return true
}

func collectConstructorTargetsForStringRefs(start uint64, data []byte, refs uint64Set, prev uint64Set) uint64Set {
	out := make(uint64Set)
	for off := 0; off+8 <= len(data); off += 4 {
		nextOff, _, ok := matchSeedLoadX1(start, data, off, refs)
		if !ok {
			continue
		}
		for scan := nextOff; scan+4 <= len(data) && scan <= nextOff+64*4; scan += 4 {
			pc := start + uint64(scan)
			raw := readUint32At(data, scan)
			if target, ok := decodeBLTarget(pc, raw); ok {
				if (prev == nil || hasUint64Set(prev, target)) && seedLoadStillInX1(data, nextOff, scan) {
					out[target] = struct{}{}
				}
				break
			}
			if invalidatesX1Raw(raw) || isReturnInstruction(raw) || isConditionalBranchRaw(raw) || isBranchRegisterRaw(raw) || isCallRegisterRaw(raw) {
				break
			}
		}
	}
	return out
}

func importStubReferenceTarget(start uint64, data []byte, refSlots uint64Set) (uint64, bool) {
	if len(data) < 12 {
		return 0, false
	}
	raw0 := readUint32At(data, 0)
	if (raw0 & 0x9f000000) != 0x90000000 {
		return 0, false
	}
	page, ok := decodeADRPImmediate(start, raw0)
	if !ok {
		return 0, false
	}

	raw1 := readUint32At(data, 4)
	raw2 := readUint32At(data, 8)
	rd := int(raw0 & 0x1f)

	if (raw1 & 0xffc00000) == 0xf9400000 {
		rt := int(raw1 & 0x1f)
		rn := int((raw1 >> 5) & 0x1f)
		imm12 := uint64((raw1>>10)&0xfff) * 8
		if rn == rd && branchRegisterUses(raw2, rt) {
			target := page + imm12
			return target, hasUint64Set(refSlots, target)
		}
	}

	if len(data) >= 16 {
		raw3 := readUint32At(data, 12)
		if (raw1&0x1f800000) == 0x11000000 && (raw2&0xffc00000) == 0xf9400000 {
			addRn := int((raw1 >> 5) & 0x1f)
			addRd := int(raw1 & 0x1f)
			ldrRn := int((raw2 >> 5) & 0x1f)
			ldrRt := int(raw2 & 0x1f)
			ldrImm12 := uint64((raw2 >> 10) & 0xfff)
			if addRn == rd && ldrRn == addRd && ldrImm12 == 0 && branchRegisterUses(raw3, ldrRt) {
				addImm := uint64((raw1 >> 10) & 0xfff)
				if (raw1>>22)&1 == 1 {
					addImm <<= 12
				}
				target := page + addImm
				return target, hasUint64Set(refSlots, target)
			}
		}
	}

	return 0, false
}

func branchRegisterUses(raw uint32, reg int) bool {
	if reg < 0 || reg > 31 {
		return false
	}
	rawReg := int((raw >> 5) & 0x1f)
	return rawReg == reg && ((raw&0xfffffc1f) == 0xd61f0000 ||
		(raw&0xfffff800) == 0xd71f0800)
}

func findPassThroughConstructorTarget(start uint64, data []byte, targets uint64Set) (uint64, bool) {
	preserved := [7]bool{true, true, true, true, true, true, true}
	branches := 0
	for off := 0; off+4 <= len(data) && off <= 64*4; off += 4 {
		pc := start + uint64(off)
		raw := readUint32At(data, off)
		if target, ok := decodeBLTarget(pc, raw); ok {
			branches++
			if hasUint64Set(targets, target) && branches == 1 &&
				preserved[0] && preserved[1] && preserved[2] && preserved[3] &&
				preserved[4] && preserved[5] && preserved[6] {
				return target, true
			}
			return 0, false
		}
		if isReturnInstruction(raw) || isConditionalBranchRaw(raw) || isBranchRegisterRaw(raw) || isCallRegisterRaw(raw) {
			return 0, false
		}
		if isPassThroughSafeRaw(raw) {
			continue
		}
		if !isRawTrackable(raw) {
			return 0, false
		}
		invalidatePassThroughRegs(raw, &preserved)
	}
	return 0, false
}

func invalidatePassThroughRegs(raw uint32, x *[7]bool) {
	mark := func(reg int, preserved bool) {
		if reg >= 0 && reg < len(x) && !preserved {
			x[reg] = false
		}
	}
	switch {
	case (raw & 0x9f000000) == 0x90000000:
		mark(int(raw&0x1f), false)
	case (raw & 0x9f000000) == 0x10000000:
		mark(int(raw&0x1f), false)
	case (raw & 0xff000000) == 0x91000000:
		mark(int(raw&0x1f), false)
	case (raw & 0xff000000) == 0xd1000000:
		mark(int(raw&0x1f), false)
	case (raw & 0xff200000) == 0xaa000000:
		rd := int(raw & 0x1f)
		rn := int((raw >> 5) & 0x1f)
		rm := int((raw >> 16) & 0x1f)
		imm6 := (raw >> 10) & 0x3f
		preserved := (rn == 31 && imm6 == 0 && rm == rd) || (rm == 31 && imm6 == 0 && rn == rd)
		mark(rd, preserved)
	case (raw & 0x7f800000) == 0x52800000:
		mark(int(raw&0x1f), false)
	case (raw & 0x7f800000) == 0x72800000:
		mark(int(raw&0x1f), false)
	case (raw & 0xffc00000) == 0xf9400000:
		mark(int(raw&0x1f), false)
	case (raw & 0xffc00000) == 0xb9400000:
		mark(int(raw&0x1f), false)
	case (raw & 0xffe00c00) == 0xf8400000:
		mark(int(raw&0x1f), false)
	case (raw & 0x7fc00000) == 0xa9400000:
		mark(int(raw&0x1f), false)
		mark(int((raw>>10)&0x1f), false)
	}
}
