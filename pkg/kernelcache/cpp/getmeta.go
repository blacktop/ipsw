package cpp

import (
	"encoding/binary"
	"slices"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

func getMetaHasBoundedTail(data []byte, start int) bool {
	if start < 0 || start+4 > len(data) {
		return false
	}
	limit := min(start+5*4, len(data))
	sawCall := false
	for off := start; off+4 <= limit; off += 4 {
		raw := binary.LittleEndian.Uint32(data[off : off+4])
		switch {
		case raw == 0xd65f03c0 || raw == 0xd65f0fff:
			return true
		case (raw & 0xfc000000) == 0x14000000:
			return true
		case (raw & 0xfc000000) == 0x94000000:
			if sawCall {
				return false
			}
			sawCall = true
		}
	}
	return false
}

func (s *Scanner) findClassGetMetaClass(m *macho.File, metaPtr uint64) uint64 {
	candidates := s.findClassGetMetaClassCandidates(m, metaPtr)
	if len(candidates) == 0 {
		return 0
	}
	return candidates[0]
}

func (s *Scanner) findClassGetMetaClassCandidates(m *macho.File, metaPtr uint64) []uint64 {
	if metaPtr == 0 {
		return nil
	}
	key := fileAddrKey{file: m, addr: metaPtr}
	if cached, ok := s.getMetaCands[key]; ok {
		return cached
	}
	seen := make(map[uint64]struct{})
	out := make([]uint64, 0, 2)
	addResults := func(results map[uint64][]uint64) {
		for _, addr := range results[metaPtr] {
			if addr == 0 {
				continue
			}
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	if m != nil {
		addResults(s.scanForGetMetaClassFunctions(m))
	}
	if s.root != nil && s.root != m {
		addResults(s.scanForGetMetaClassFunctions(s.root))
	}
	s.getMetaCands[key] = out
	return out
}

func (s *Scanner) scanForGetMetaClassFunctions(m *macho.File) map[uint64][]uint64 {
	if results, ok := s.getMetaMap[m]; ok {
		return results
	}

	results := make(map[uint64][]uint64)
	addCandidate := func(metaAddr uint64, funcAddr uint64) {
		if !validKernelPointer(metaAddr) || funcAddr == 0 {
			return
		}
		list := results[metaAddr]
		if slices.Contains(list, funcAddr) {
			return
		}
		results[metaAddr] = append(list, funcAddr)
	}

	for _, sec := range m.Sections {
		if sec.Name != "__text" {
			continue
		}
		if sec.Seg != "__TEXT_EXEC" && sec.Seg != "__TEXT" {
			continue
		}
		data, err := s.readSectionData(m, sec)
		if err != nil {
			continue
		}

		base := sec.Addr
		for i := 0; i+12 <= len(data); i += 4 {
			instrAddr := base + uint64(i)
			raw0 := binary.LittleEndian.Uint32(data[i : i+4])
			raw1 := binary.LittleEndian.Uint32(data[i+4 : i+8])
			raw2 := binary.LittleEndian.Uint32(data[i+8 : i+12])

			var metaclassAddr uint64
			funcAddr := instrAddr
			if i >= 4 {
				rawPrev := binary.LittleEndian.Uint32(data[i-4 : i])
				if (rawPrev & 0xfffff01f) == 0xd503201f {
					funcAddr = instrAddr - 4
				}
			}

			isADRP := (raw0 & 0x9f000000) == 0x90000000
			isADR := (raw0 & 0x9f000000) == 0x10000000
			isLDR := (raw0&0x3f000000) == 0x18000000 || (raw0&0x3f000000) == 0x58000000

			if isADRP {
				isADD := (raw1 & 0x1f800000) == 0x11000000
				if isADD && getMetaHasBoundedTail(data, i+8) {
					adrpRd := raw0 & 0x1f
					addRn := (raw1 >> 5) & 0x1f
					addRd := raw1 & 0x1f
					if adrpRd == addRn && addRd == 0 {
						immhi := int64((raw0 >> 5) & 0x7ffff)
						immlo := int64((raw0 >> 29) & 0x3)
						offset := (immhi << 2) | immlo
						if offset&(1<<20) != 0 {
							offset |= ^int64((1 << 21) - 1)
						}
						pc := instrAddr &^ 0xfff
						addImm := uint64((raw1 >> 10) & 0xfff)
						metaclassAddr = uint64(int64(pc)+(offset<<12)) + addImm
					}
				}
			}

			if metaclassAddr == 0 && isADR {
				adrRd := raw0 & 0x1f
				isRET1 := raw1 == 0xd65f03c0 || raw1 == 0xd65f0fff
				isNOP := raw1 == 0xd503201f
				isRET2 := raw2 == 0xd65f03c0 || raw2 == 0xd65f0fff
				if adrRd == 0 && (isRET1 || (isNOP && isRET2) || getMetaHasBoundedTail(data, i+4)) {
					immhi := int64((raw0 >> 5) & 0x7ffff)
					immlo := int64((raw0 >> 29) & 0x3)
					offset := (immhi << 2) | immlo
					if offset&(1<<20) != 0 {
						offset |= ^int64((1 << 21) - 1)
					}
					metaclassAddr = uint64(int64(instrAddr) + offset)
				}
			}

			if metaclassAddr == 0 && isLDR {
				ldrRd := raw0 & 0x1f
				isRET := raw1 == 0xd65f03c0
				isBR := (raw1 & 0xfffffc1f) == 0xd61f0000
				if ldrRd == 0 && (isRET || isBR) {
					imm19 := int64((raw0 >> 5) & 0x7ffff)
					if imm19&(1<<18) != 0 {
						imm19 |= ^int64((1 << 19) - 1)
					}
					literalAddr := uint64(int64(instrAddr) + (imm19 << 2))
					if ptr, ok := s.resolvePointerAt(m, literalAddr); ok {
						metaclassAddr = ptr
					}
				}
			}

			addCandidate(metaclassAddr, funcAddr)
		}
	}

	s.getMetaMap[m] = results
	for _, sec := range m.Sections {
		if sec.Name == "__text" {
			delete(s.sectionData, sectionKey{file: m, addr: sec.Addr})
		}
	}
	return results
}

func (s *Scanner) buildPointerIndex(m *macho.File) map[uint64][]uint64 {
	if index, ok := s.pointerIndex[m]; ok {
		return index
	}

	index := make(map[uint64][]uint64)
	fwd := make(map[uint64]uint64)
	addSectionPointers := func(sec *types.Section) {
		if sec == nil || sec.Size < 8 {
			return
		}
		data, err := s.readSectionData(m, sec)
		if err != nil {
			return
		}

		ownerDecoder := newSectionPointerDecoder(m, sec, sec)

		for off := 0; off+8 <= len(data); off += 8 {
			raw := binary.LittleEndian.Uint64(data[off : off+8])
			if raw == 0 {
				continue
			}
			addr := sec.Addr + uint64(off)
			if ptr, ok := ownerDecoder.decode(raw, off); ok && ptr != 0 {
				index[ptr] = append(index[ptr], addr)
				fwd[addr] = ptr
			}
		}
	}

	for _, sec := range m.Sections {
		if sec == nil || sec.Size < 8 {
			continue
		}
		if sec.Seg == "__TEXT" || sec.Seg == "__TEXT_EXEC" {
			continue
		}
		if sec.Name == "__bss" || sec.Name == "__common" {
			continue
		}
		addSectionPointers(sec)
	}

	s.pointerIndex[m] = index
	s.forwardPointers[m] = fwd
	s.stats.pointerIndexEntries += len(index)
	return index
}

type sectionPointerDecoder struct {
	file       *macho.File
	dcf        *fixupchains.DyldChainedFixups
	offsetBase uint64
	base       uint64
	preferred  uint64
}

func newSectionPointerDecoder(file *macho.File, targetSec, mappedSec *types.Section) sectionPointerDecoder {
	if file == nil || targetSec == nil || mappedSec == nil {
		return sectionPointerDecoder{}
	}
	offsetBase := uint64(mappedSec.Offset)
	if mappedSec != targetSec {
		offsetBase += targetSec.Addr - mappedSec.Addr
	}
	decoder := sectionPointerDecoder{
		file:       file,
		offsetBase: offsetBase,
		base:       file.GetBaseAddress(),
	}
	if text := file.Segment("__TEXT"); text != nil {
		decoder.preferred = text.Addr
	}
	if file.HasDyldChainedFixups() {
		if dcf, err := file.DyldChainedFixups(); err == nil {
			decoder.dcf = dcf
		}
	}
	return decoder
}

func (d sectionPointerDecoder) decode(raw uint64, relOff int) (uint64, bool) {
	if d.file == nil || raw == 0 {
		return 0, false
	}
	if d.dcf != nil {
		fileOffset := d.offsetBase + uint64(relOff)
		if target, err := d.dcf.RebaseRaw(fileOffset, raw, d.base); err == nil {
			ptr := target + d.preferred
			if validKernelPointer(ptr) {
				return ptr, true
			}
		}
	}
	ptr := d.file.SlidePointer(raw)
	if validKernelPointer(ptr) {
		return ptr, true
	}
	return 0, false
}

func (s *Scanner) inferVtableFromPointer(m *macho.File, ptrLoc uint64) (uint64, int, bool) {
	if ptrLoc < 16 {
		return 0, 0, false
	}
	sec := m.FindSectionForVMAddr(ptrLoc)
	if sec == nil || ptrLoc < sec.Addr+16 {
		return 0, 0, false
	}
	data, err := s.readSectionData(m, sec)
	if err != nil {
		return 0, 0, false
	}
	if ptrLoc >= sec.Addr+uint64(len(data)) {
		return 0, 0, false
	}

	zerosSeen := 0
	var headerAddr uint64
	for step := 1; step <= 256; step++ {
		addr := ptrLoc - uint64(step*8)
		if addr < sec.Addr {
			break
		}
		off := int(addr - sec.Addr)
		if off < 0 || off+8 > len(data) {
			break
		}
		val := binary.LittleEndian.Uint64(data[off : off+8])
		if val == 0 {
			zerosSeen++
			if zerosSeen == 2 {
				headerAddr = addr
				break
			}
			continue
		}
		zerosSeen = 0
	}
	if headerAddr == 0 {
		return 0, 0, false
	}

	vtableAddr := headerAddr + 16
	if ptrLoc < vtableAddr {
		return 0, 0, false
	}
	offset := ptrLoc - vtableAddr
	if offset%8 != 0 {
		return 0, 0, false
	}
	return vtableAddr, int(offset / 8), true
}

func (s *Scanner) findVtableViaGetMetaClass(m *macho.File, metaVtableAddr uint64, getMetaClassAddr uint64) uint64 {
	index := s.buildPointerIndex(m)
	locs := index[getMetaClassAddr]
	if len(locs) == 0 {
		if fn, err := s.functionForAddr(m, getMetaClassAddr); err == nil {
			locs = index[fn.StartAddr]
		}
	}

	var best uint64
	ambiguous := false
	for _, loc := range locs {
		vtableAddr, slot, ok := s.inferVtableFromPointer(m, loc)
		if !ok || slot != s.getMetaClassIndex {
			continue
		}
		if vtableAddr == metaVtableAddr || vtableAddr == metaVtableAddr+16 {
			continue
		}
		if !s.validateVtableCandidate(m, vtableAddr, getMetaClassAddr) {
			continue
		}
		if best == 0 {
			best = vtableAddr
			continue
		}
		if vtableAddr != best {
			ambiguous = true
		}
	}
	if ambiguous {
		return 0
	}
	return best
}

func (s *Scanner) validateVtableCandidate(m *macho.File, vtableAddr uint64, getMetaClassAddr uint64) bool {
	ptr, ok := s.resolvePointerAt(m, vtableAddr+uint64(s.getMetaClassIndex*8))
	if !ok {
		return false
	}
	if ptr == getMetaClassAddr {
		return true
	}
	if fn, err := s.functionForAddr(m, getMetaClassAddr); err == nil && ptr == fn.StartAddr {
		return true
	}
	return false
}

func (s *Scanner) recoverVtableNearMeta(m *macho.File, metaVtableAddr uint64, getMetaCandidates []uint64) uint64 {
	if m == nil || metaVtableAddr == 0 || len(getMetaCandidates) == 0 {
		return 0
	}
	sec := m.FindSectionForVMAddr(metaVtableAddr)
	if sec == nil {
		return 0
	}
	start := max(metaVtableAddr, sec.Addr+16)
	lowerBound := sec.Addr + 16
	upperBound := sec.Addr + sec.Size
	const maxRadius = 0x2000

	check := func(addr uint64) uint64 {
		if addr < lowerBound || addr+8 > upperBound {
			return 0
		}
		if addr == metaVtableAddr || addr == metaVtableAddr+16 {
			return 0
		}
		if !s.looksLikeVtableStart(m, addr) {
			return 0
		}
		for _, cand := range getMetaCandidates {
			if s.validateVtableCandidate(m, addr, cand) {
				return addr
			}
		}
		return 0
	}

	for delta := uint64(8); delta <= maxRadius; delta += 8 {
		if start >= lowerBound+delta {
			if vt := check(start - delta); vt != 0 {
				return vt
			}
		}
		if start+delta < upperBound {
			if vt := check(start + delta); vt != 0 {
				return vt
			}
		}
	}
	return 0
}
