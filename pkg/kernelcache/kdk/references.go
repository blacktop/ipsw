package kdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/arm64-cgo/emulate"
	dwf "github.com/blacktop/go-dwarf"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/disass"
)

// unwindSectionHeader is the header of __TEXT,__unwind_info (unwind_info_section_header).
type unwindSectionHeader struct {
	Version uint32

	CommonEncodingsOffset uint32
	CommonEncodingsCount  uint32

	PersonalityOffset uint32
	PersonalityCount  uint32

	IndexOffset uint32
	IndexCount  uint32
}

// recovery holds the state shared by the reference recovery of all entries.
type recovery struct {
	branchTargets map[uint64]struct{} // see collectBranchTargets
	foreign       *foreignCodeContext // code of all entries, for calls leaving an entry
	returns       *cfgReturnContext   // per code section, see recoverOff12References
}

// sortFixups returns the rebase targets of the collection's chained fixups per
// fileset entry (location -> target).
func sortFixups(m *macho.File, entries map[string]*macho.File) (map[string]map[uint64]uint64, error) {
	if !m.HasDyldChainedFixups() {
		return nil, nil
	}

	dcf, err := m.DyldChainedFixups()
	if err != nil {
		return nil, fmt.Errorf("failed to read the chained fixups: %w", err)
	}
	if _, err := dcf.Parse(); err != nil {
		return nil, fmt.Errorf("failed to parse the chained fixups: %w", err)
	}

	result := make(map[string]map[uint64]uint64)
	binds := 0
	for _, start := range dcf.Starts {
		if start.PageStarts != nil {
			for _, fixup := range start.Fixups {
				switch f := fixup.(type) {
				case fixupchains.Bind:
					binds++
				case fixupchains.Rebase:
					source := uint64(f.Offset()) + m.GetBaseAddress()

					for bundleID, mfe := range entries {
						if sec := mfe.FindSectionForVMAddr(source); sec == nil {
							continue
						}

						target := f.Target() + m.GetBaseAddress()
						if _, ok := result[bundleID]; !ok {
							result[bundleID] = make(map[uint64]uint64)
						}
						result[bundleID][source] = target
						break
					}
				}
			}
		}
	}
	if binds > 0 {
		log.Warnf("Ignoring %d unexpected bind fixups in the kernelcache", binds)
	}
	return result, nil
}

// recoverSplitSegmentReferences recreates the split-segment references of an
// entry. fixups are its rebases from sortFixups; they are its pointers.
func (rc *recovery) recoverSplitSegmentReferences(msfe *macho.File, fixups map[uint64]uint64) ([]*types.SplitInfoEntry, error) {
	result := make([]*types.SplitInfoEntry, 0)
	for source, target := range fixups {
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_POINTER_64,
			SourceVmAddr: source,
			TargetVmAddr: target,
		})
	}
	deltas, err := recoverDeltaReferences(msfe)
	if err != nil {
		return nil, err
	}
	result = slices.Concat(result, deltas)
	adrpRefs, err := recoverADRPReferences(msfe)
	if err != nil {
		return nil, err
	}
	for source, target := range adrpRefs {
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_ARM64_ADRP,
			SourceVmAddr: source,
			TargetVmAddr: target,
		})
	}
	off12, err := rc.recoverOff12References(msfe, adrpRefs)
	if err != nil {
		return nil, err
	}
	result = slices.Concat(result, off12)
	branches, err := rc.recoverBr26References(msfe)
	if err != nil {
		return nil, err
	}
	for source, target := range branches {
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_ARM64_BR26,
			SourceVmAddr: source,
			TargetVmAddr: target,
		})
	}
	imageOffsets, err := recoverImageOff32References(msfe)
	if err != nil {
		return nil, err
	}
	for source, target := range imageOffsets {
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_IMAGE_OFF_32,
			SourceVmAddr: source,
			TargetVmAddr: target,
		})
	}

	return result, nil
}

func recoverDeltaReferences(msfe *macho.File) ([]*types.SplitInfoEntry, error) {
	result := make([]*types.SplitInfoEntry, 0)
	staticIf, err := recoverReferencesBootdataStaticIf(msfe)
	if err != nil {
		return nil, err
	}
	for source, target := range staticIf {
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_DELTA_32,
			SourceVmAddr: source,
			TargetVmAddr: target,
		})
	}
	copyio, err := recoverReferencesTextCopyioVectors(msfe)
	if err != nil {
		return nil, err
	}
	for source, target := range copyio {
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_DELTA_64,
			SourceVmAddr: source,
			TargetVmAddr: target,
		})
	}
	ehFrame, err := recoverReferencesTextEhFrame(msfe)
	if err != nil {
		return nil, err
	}
	return slices.Concat(result, ehFrame), nil
}

// recoverADRPReferences returns the ADRPs that target a page of the entry's
// segments (ADRP location -> target page).
func recoverADRPReferences(msfe *macho.File) (map[uint64]uint64, error) {
	result := make(map[uint64]uint64)
	for _, section := range codeSections(msfe) {
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read %s.%s: %w", section.Seg, section.Name, err)
		}

		r := bytes.NewReader(data)
		var instrValue uint32
		for address := section.Addr; ; address += uint64(binary.Size(uint32(0))) {
			err := binary.Read(r, binary.LittleEndian, &instrValue)
			if err == io.EOF {
				break
			}

			var decoder disassemble.Decoder
			var adrpInstr disassemble.Inst
			if err := decoder.DecomposeInto(address, instrValue, &adrpInstr); err != nil {
				continue
			}
			if adrpInstr.Operation != disassemble.ARM64_ADRP {
				continue
			}

			target := emulate.ExtractADRPTarget(adrpInstr.Raw, adrpInstr.Address)
			// ADRP targets a page, while cache segments may begin and end within
			// that page. Test the complete intervals: checking only the page's
			// endpoints misses packed segments contained by a single page.
			if !pageOverlapsMachoSegment(msfe, target) {
				continue
			}

			result[adrpInstr.Address] = target
		}
	}
	return result, nil
}

// codeSections returns the sections holding instructions whose references
// must be recovered: __TEXT_EXEC.__text and __KLD.__text, but also e.g.
// __TEXT_EXEC.__hib_text and the kernel's __TEXT_BOOT_EXEC.__bootcode, whose
// references a collection builder relocates as well. Stubs are regenerated by
// the export and skipped.
func codeSections(f *macho.File) []*types.Section {
	var sections []*types.Section
	for _, sec := range f.Sections {
		if sec.Size == 0 || strings.Contains(sec.Name, "stubs") {
			continue
		}
		if sec.Flags.IsPureInstructions() || sec.Flags.IsSomeInstructions() {
			sections = append(sections, sec)
		}
	}
	return sections
}

func rangesOverlap(start, end, otherStart, otherEnd uint64) bool {
	return start < otherEnd && otherStart < end
}

func pageOverlapsMachoSegment(file *macho.File, address uint64) bool {
	pageStart := address &^ uint64(0xfff)
	pageEnd := pageStart + 0x1000
	for _, segment := range file.Segments() {
		if rangesOverlap(pageStart, pageEnd, segment.Addr, segment.Addr+segment.Memsz) {
			return true
		}
	}
	return false
}

// recoverOff12References follows the register of every ADRP to the
// instructions that complete its address (ADD, LDR, STR), across branches,
// jump tables and calls that preserve the register.
func (rc *recovery) recoverOff12References(msfe *macho.File, adrpRefs map[uint64]uint64) ([]*types.SplitInfoEntry, error) {
	result := make([]*types.SplitInfoEntry, 0)
	for _, section := range codeSections(msfe) {
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read %s.%s: %w", section.Seg, section.Name, err)
		}
		// The disassembler's symbol map tells which callees are _panic.
		engine, err := newSectionEngine(msfe, section, data)
		if err != nil {
			return nil, err
		}

		rc.returns = newCfgReturnContext(msfe, section, data)
		r := bytes.NewReader(data)
		// The noreturn analysis memoizes per query order: keep it stable.
		for _, source := range slices.Sorted(maps.Keys(adrpRefs)) {
			target := adrpRefs[source]
			adrpSource := source
			if msfe.FindSectionForVMAddr(source) != section {
				continue
			}
			sectionOffset := int64(source - section.Addr)
			r.Seek(sectionOffset, io.SeekStart)

			var instrValue uint32
			if err := binary.Read(r, binary.LittleEndian, &instrValue); err != nil {
				continue
			}

			adrpTargetRegister := emulate.ExtractRegister(instrValue, 0)
			rc.returns.viaReturn = make(map[uint64]bool)
			rc.returns.adrpFunc, _ = rc.returns.functionStart(source)
			pos := readerPos(r)
			cfgFunctionReturns := make(map[uint64]bool)
			cfgVisited := make(map[uint64][]uint8)
			relatedInstructionAddresses := rc.findUsagesOfRegister(r, engine, source+uint64(binary.Size(uint32(0))), adrpTargetRegister, target, cfgFunctionReturns, cfgVisited)
			r.Seek(pos, io.SeekStart)
			// Function starts survive in the kernel collection. They are an
			// important upper bound here: a callee-saved register can retain the
			// same number in the following function while containing an unrelated
			// value. Following that apparent dataflow across a function boundary
			// invents OFF12 adjustments and corrupts otherwise ordinary field
			// accesses when the KEXT is exported.
			function, functionErr := msfe.GetFunctionForVMAddr(adrpSource)

			for source, target := range relatedInstructionAddresses {
				if functionErr == nil && !addressInFunction(source, function) && !rc.returns.viaReturn[source] {
					continue
				}
				result = append(result, &types.SplitInfoEntry{
					Kind:         types.DYLD_CACHE_ADJ_V2_ARM64_OFF12,
					SourceVmAddr: source,
					TargetVmAddr: target,
					ExtraVmAddr:  adrpSource,
				})
			}
		}
	}
	rc.returns = nil
	return result, nil
}

// newSectionEngine sets up the disassembler for one code section. Its symbol
// cache lives in a temporary file that is removed again.
func newSectionEngine(msfe *macho.File, section *types.Section, data []byte) (*disass.MachoDisass, error) {
	engine := disass.NewMachoDisass(msfe, &disass.Config{
		Data:         data,
		StartAddress: section.Addr,
	})
	cache, err := os.CreateTemp("", "ipsw-kdk-*.a2s")
	if err != nil {
		return nil, err
	}
	cacheFileName := cache.Name()
	cache.Close()
	os.Remove(cacheFileName)
	defer os.Remove(cacheFileName)
	// The entry only exists inside the kernelcache: identify the symbol cache
	// by the section's contents instead of a file on disk.
	segment := section.Seg + "." + section.Name
	source := disass.NewMachoSymbolSourceFromDigest("", sha256.Sum256(append([]byte(segment+"\x00"), data...)))
	if err := engine.OpenOrCreateSymMapFromSource(&cacheFileName, source); err != nil {
		return nil, fmt.Errorf("failed to create the symbol map of %s: %w", segment, err)
	}
	if err := engine.Triage(); err != nil {
		return nil, fmt.Errorf("failed to triage %s: %w", segment, err)
	}
	if engine.EmptySymMap() {
		if err := engine.Analyze(); err != nil {
			log.Debugf("Analysis of %s failed: %v", segment, err)
		}
	}
	return engine, nil
}

func addressInFunction(address uint64, function types.Function) bool {
	return function.StartAddr <= address && address < function.EndAddr
}

// collectBranchTargets returns the addresses a recovered B/BL may target:
// function starts and defined symbols of every fileset entry.
func collectBranchTargets(entries map[string]*macho.File) map[uint64]struct{} {
	targets := make(map[uint64]struct{})
	for _, mfse := range entries {
		for _, fn := range mfse.GetFunctions() {
			targets[fn.StartAddr] = struct{}{}
		}
		if mfse.Symtab != nil {
			for _, sym := range mfse.Symtab.Syms {
				if !sym.Type.IsUndefinedSym() && sym.Value != 0 {
					targets[sym.Value] = struct{}{}
				}
			}
		}
	}
	return targets
}

// recoverBr26References returns the B/BL that leave their section.
func (rc *recovery) recoverBr26References(msfe *macho.File) (map[uint64]uint64, error) {
	result := make(map[uint64]uint64)
	for _, section := range codeSections(msfe) {
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read %s.%s: %w", section.Seg, section.Name, err)
		}

		r := bytes.NewReader(data)
		var instrValue uint32
		for address := section.Addr; ; address += uint64(binary.Size(uint32(0))) {
			err := binary.Read(r, binary.LittleEndian, &instrValue)
			if err == io.EOF {
				break
			}

			var decoder disassemble.Decoder
			var branchInstr disassemble.Inst
			if err := decoder.DecomposeInto(address, instrValue, &branchInstr); err != nil {
				continue
			}
			if branchInstr.Operation != disassemble.ARM64_B && branchInstr.Operation != disassemble.ARM64_BL {
				continue
			}
			if branchInstr.NumOps != 1 {
				continue
			}
			target := branchInstr.Operands[0].Immediate
			targetSection := msfe.FindSectionForVMAddr(target)
			if targetSection == section {
				continue
			}
			// Code sections can embed data (e.g. Libm's constant tables) that
			// decodes as a branch. Real cross-section branches reach a known
			// function or symbol, or another code section of this image.
			if _, ok := rc.branchTargets[target]; !ok {
				if targetSection == nil || !targetSection.Flags.IsSomeInstructions() && !targetSection.Flags.IsPureInstructions() {
					continue
				}
			}
			result[branchInstr.Address] = target
		}
	}
	return result, nil
}

// recoverImageOff32References returns the image offsets in __unwind_info:
// personalities, the first-level index and the LSDA index.
func recoverImageOff32References(msfe *macho.File) (map[uint64]uint64, error) {
	section := msfe.Section("__TEXT", "__unwind_info")
	if section == nil {
		return nil, nil
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __unwind_info: %w", err)
	}
	header, err := decodeUnwindHeader(data)
	if err != nil {
		return nil, err
	}
	word := func(pos uint64) (uint32, error) {
		if pos+4 > uint64(len(data)) {
			return 0, fmt.Errorf("__unwind_info is truncated at %#x", pos)
		}
		return binary.LittleEndian.Uint32(data[pos:]), nil
	}

	result := make(map[uint64]uint64)
	base := msfe.GetBaseAddress()
	// Personalities
	for i := range uint64(header.PersonalityCount) {
		pos := uint64(header.PersonalityOffset) + i*4
		offset, err := word(pos)
		if err != nil {
			return nil, err
		}
		result[section.Addr+pos] = base + uint64(offset)
	}

	// First-level index: function offset, second-level page offset, LSDA index offset.
	const indexEntrySize = 12
	var firstLSDA, lastLSDA uint32
	for i := range uint64(header.IndexCount) {
		pos := uint64(header.IndexOffset) + i*indexEntrySize
		offset, err := word(pos)
		if err != nil {
			return nil, err
		}
		target := base + uint64(offset)
		if i == uint64(header.IndexCount)-1 {
			target++ // the sentinel entry points one past the last function
		}
		result[section.Addr+pos] = target
		lsda, err := word(pos + 8)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			firstLSDA = lsda
		}
		lastLSDA = lsda
	}

	// The LSDA index runs from the first entry's LSDA offset to the sentinel's.
	const lsdaEntrySize = 4
	for pos := uint64(firstLSDA); pos < uint64(lastLSDA); pos += lsdaEntrySize {
		offset, err := word(pos)
		if err != nil {
			return nil, err
		}
		result[section.Addr+pos] = base + uint64(offset)
	}
	return result, nil
}

func decodeUnwindHeader(data []byte) (unwindSectionHeader, error) {
	var h unwindSectionHeader
	if len(data) < 28 {
		return h, fmt.Errorf("__unwind_info is too small (%d bytes)", len(data))
	}
	h.Version = binary.LittleEndian.Uint32(data[0:4])
	h.CommonEncodingsOffset = binary.LittleEndian.Uint32(data[4:8])
	h.CommonEncodingsCount = binary.LittleEndian.Uint32(data[8:12])
	h.PersonalityOffset = binary.LittleEndian.Uint32(data[12:16])
	h.PersonalityCount = binary.LittleEndian.Uint32(data[16:20])
	h.IndexOffset = binary.LittleEndian.Uint32(data[20:24])
	h.IndexCount = binary.LittleEndian.Uint32(data[24:28])
	return h, nil
}

// cfgReturnContext lets register tracking continue past a RET into the
// callers of the returning function. Machine outlining moves ADRPs into
// helpers like `adrp x24, page; cmp w8, #1; ret` whose callers then use x24.
type cfgReturnContext struct {
	functions   []types.Function    // sorted by start address
	returnSites map[uint64][]uint64 // callee start -> addresses after each BL
	viaReturn   map[uint64]bool     // consumers reached through a RET
	adrpFunc    uint64              // start of the function containing the ADRP
}

func newCfgReturnContext(msfe *macho.File, section *types.Section, data []byte) *cfgReturnContext {
	ctx := &cfgReturnContext{returnSites: make(map[uint64][]uint64), viaReturn: make(map[uint64]bool)}
	for _, fn := range msfe.GetFunctions() {
		if fn.StartAddr >= section.Addr && fn.StartAddr < section.Addr+section.Size {
			ctx.functions = append(ctx.functions, fn)
		}
	}
	sort.Slice(ctx.functions, func(i, j int) bool { return ctx.functions[i].StartAddr < ctx.functions[j].StartAddr })
	for off := 0; off+4 <= len(data); off += 4 {
		insn := binary.LittleEndian.Uint32(data[off:])
		if insn&0xFC000000 != 0x94000000 { // BL
			continue
		}
		pc := section.Addr + uint64(off)
		target, ok := branchTarget(insn, pc)
		if !ok || target < section.Addr || target >= section.Addr+section.Size {
			continue
		}
		ctx.returnSites[target] = append(ctx.returnSites[target], pc+4)
	}
	return ctx
}

func (ctx *cfgReturnContext) functionStart(address uint64) (uint64, bool) {
	i := sort.Search(len(ctx.functions), func(i int) bool { return ctx.functions[i].StartAddr > address }) - 1
	if i < 0 || !addressInFunction(address, ctx.functions[i]) {
		return 0, false
	}
	return ctx.functions[i].StartAddr, true
}

func (rc *recovery) findUsagesOfRegister(r *bytes.Reader, engine *disass.MachoDisass, address uint64, register uint8, adrpTarget uint64, returns map[uint64]bool, visited map[uint64][]uint8) map[uint64]uint64 {
	const maxTrackedInstructions = 10000

	startPos := readerPos(r)
	posToAddress := func(pos int64) uint64 { return uint64(pos-startPos) + address }
	addressToPos := func(offset uint64) int64 { return int64(offset-address) + startPos }

	result := make(map[uint64]uint64)
	for i := 0; i < maxTrackedInstructions; i++ {
		var subInstrValue uint32
		err := binary.Read(r, binary.LittleEndian, &subInstrValue)
		if err == io.EOF {
			return result
		}

		subAddress := address + uint64(i)*uint64(binary.Size(uint32(0)))
		visitedRegisters, ok := visited[subAddress]
		if ok {
			if slices.Contains(visitedRegisters, register) {
				return result
			}
			visited[subAddress] = append(visitedRegisters, register)
		} else {
			visited[subAddress] = []uint8{register}
		}

		if (subInstrValue&0xFFC00000) == 0x91000000 || (subInstrValue&0x3B000000) == 0x39000000 {
			// Add, LDR and STR Instructions
			if emulate.IsLDR(subInstrValue) || emulate.IsSTR(subInstrValue) || (!emulate.IsLDP(subInstrValue) && !emulate.IsSTP(subInstrValue)) {
				source := emulate.ExtractRegister(subInstrValue, 1)
				if source == register {
					offset := emulate.ExtractImmediate(subInstrValue)
					if offset >= 0 {
						result[subAddress] = adrpTarget + uint64(offset)
					} else {
						result[subAddress] = adrpTarget - uint64(-offset)
					}
				}
			}
		} else if (subInstrValue&0xFFFFFC1F) == 0xD65F0000 || subInstrValue == 0xD65F0BFF || subInstrValue == 0xD65F0FFF {
			if rc.returns != nil {
				// Only the ADRP's own function hands the register to its callers
				// (one level). Callers restore or clobber it per the ABI.
				if start, ok := rc.returns.functionStart(subAddress); ok && start == rc.returns.adrpFunc {
					pos := readerPos(r)
					for _, site := range rc.returns.returnSites[start] {
						r.Seek(addressToPos(site), io.SeekStart)
						for source, target := range rc.findUsagesOfRegister(r, engine, site, register, adrpTarget, returns, visited) {
							result[source] = target
							rc.returns.viaReturn[source] = true
						}
					}
					r.Seek(pos, io.SeekStart)
				}
			}
			break
		} else if (subInstrValue & 0xFFE0001F) == 0xD4200000 {
			break
		} else if emulate.IsBL(subInstrValue) || emulate.IsBLR(subInstrValue) || isAuthenticatedCall(subInstrValue) {
			if register < 8 {
				// We expect these to be parameters
				break
			}

			var decoder disassemble.Decoder
			var instruction disassemble.Inst
			if err := decoder.DecomposeInto(subAddress, subInstrValue, &instruction); err != nil {
				break
			}
			if instruction.Operation != disassemble.ARM64_BL && instruction.Operation != disassemble.ARM64_B {
				// Indirect calls (BLR, BLRAA, ...) cannot be followed, but
				// they preserve callee-saved registers like any call.
				if register >= 19 && register <= 28 {
					continue
				}
				break
			}
			if int(instruction.NumOps) < 1 {
				break
			}
			target := instruction.Operands[0].Immediate

			pos := readerPos(r)
			// Machine-outlined helpers ignore the calling convention: they can
			// redefine any register (`adrp x21, page; add x21, x21, #0x28; ret`).
			// Stop if a provable leaf callee writes the register; for other
			// callees only callee-saved registers (x19-x28) survive.
			if written, known := calleeWritesRegister(r, addressToPos, target, register); written || (!known && register <= 18) {
				r.Seek(pos, io.SeekStart)
				break
			}
			r.Seek(addressToPos(target), io.SeekStart)
			returnVisited := make(map[uint64]bool)
			funcReturns, err := rc.mayReturn(r, engine, target, addressToPos, returns, returnVisited)
			if err == nil && !funcReturns {
				break
			}
			r.Seek(pos, io.SeekStart)
			continue
		} else if (subInstrValue & 0xFFFFFC1F) == 0xD61F0000 {
			// BR instructions
			flowTerminated := rc.handleBr(subInstrValue, r, posToAddress, adrpTarget, addressToPos, result, engine, register, returns, visited)
			if flowTerminated {
				break
			}
		} else if isAuthenticatedJump(subInstrValue) {
			// BRAA and friends: the target is unknown and execution does
			// not continue with the next instruction.
			break
		} else if !emulate.IsLinearInst(subInstrValue) {
			flowTerminated := rc.handleBranch(subInstrValue, subAddress, r, result, engine, register, adrpTarget, returns, visited)
			if flowTerminated {
				break
			}
			continue
		} else if (subInstrValue & 0x7FE0FFE0) == 0x2A0003E0 {
			rc.handleMov(subInstrValue, register, r, result, engine, subAddress, adrpTarget, returns, visited)
		}

		// Stores and SIMD&FP instructions name the register without
		// writing it.
		if instructionWritesRegister(subInstrValue, register) {
			// Another value has been written into the register. Abort.
			break
		}
	}
	return result
}

// calleeWritesRegister scans a short leaf callee up to its RET and reports
// whether it writes register. known is false if the callee could not be
// followed (calls, branches, code outside the section, too long).
func calleeWritesRegister(r *bytes.Reader, addressToPos func(offset uint64) int64, target uint64, register uint8) (written, known bool) {
	pos := addressToPos(target)
	if pos < 0 || pos >= r.Size() {
		return false, false
	}
	if _, err := r.Seek(pos, io.SeekStart); err != nil {
		return false, false
	}
	for i := 0; i < 64; i++ {
		var insn uint32
		if err := binary.Read(r, binary.LittleEndian, &insn); err != nil {
			return false, false
		}
		if (insn&0xFFFFFC1F) == 0xD65F0000 || insn == 0xD65F0BFF || insn == 0xD65F0FFF {
			return false, true // RET
		}
		if !emulate.IsLinearInst(insn) || isAuthenticatedJump(insn) || isAuthenticatedCall(insn) {
			return false, false
		}
		isLoadStore := insn&0x0a000000 == 0x08000000
		baseSP := isLoadStore && (insn>>5)&0x1f == 31
		// A callee that saves the register on the stack follows the calling
		// convention and restores it before returning.
		if baseSP && (emulate.IsSTR(insn) || emulate.IsSTP(insn)) &&
			(uint8(insn&0x1f) == register || (emulate.IsSTP(insn) && uint8((insn>>10)&0x1f) == register)) {
			return false, false
		}
		if instructionWritesRegister(insn, register) && !baseSP {
			return true, true
		}
	}
	return false, false
}

// isAuthenticatedJump reports BRAA, BRAB, BRAAZ and BRABZ, which
// emulate.IsLinearInst does not recognize as branches.
func isAuthenticatedJump(insn uint32) bool {
	return insn&0xFEFFF000 == 0xD61F0000 && insn&0xFFFFFC1F != 0xD61F0000
}

// isAuthenticatedCall reports BLRAA, BLRAB, BLRAAZ and BLRABZ.
func isAuthenticatedCall(insn uint32) bool {
	return insn&0xFEFFF000 == 0xD63F0000 && insn&0xFFFFFC1F != 0xD63F0000
}

// instructionWritesRegister reports whether a linear AArch64 instruction writes
// general purpose register reg.
func instructionWritesRegister(insn uint32, reg uint8) bool {
	rt := uint8(insn & 0x1f)
	rn := uint8((insn >> 5) & 0x1f)
	rt2 := uint8((insn >> 10) & 0x1f)
	if insn&0x0a000000 == 0x08000000 { // loads and stores
		simd := insn&0x04000000 != 0
		switch {
		case insn&0x3a000000 == 0x28000000: // pairs
			load := insn&0x00400000 != 0
			writeback := (insn>>23)&3 == 1 || (insn>>23)&3 == 3
			return (writeback && rn == reg) || (load && !simd && (rt == reg || rt2 == reg))
		case insn&0x3b000000 == 0x18000000: // load literal
			return !simd && rt == reg
		case insn&0x3b000000 == 0x39000000: // unsigned immediate
			return !simd && (insn>>22)&3 != 0 && rt == reg
		case insn&0x3b200000 == 0x38000000: // unscaled/pre/post-indexed immediate
			writeback := (insn>>10)&3 == 1 || (insn>>10)&3 == 3
			return (writeback && rn == reg) || (!simd && (insn>>22)&3 != 0 && rt == reg)
		case insn&0x3b200c00 == 0x38200800: // register offset
			return !simd && (insn>>22)&3 != 0 && rt == reg
		default: // exclusives, atomics, ...: be conservative
			return rt == reg || uint8((insn>>16)&0x1f) == reg
		}
	}
	if insn&0x0e000000 == 0x0e000000 { // SIMD and floating-point data processing
		switch {
		case insn&0x5f20fc00 == 0x1e200000: // conversions between FP and integer
			return rt == reg
		case insn&0xbfe08400 == 0x0e000400: // SIMD copy: only SMOV and UMOV write a GPR
			imm4 := (insn >> 11) & 0xf
			return insn&0x20000000 == 0 && (imm4 == 5 || imm4 == 7) && rt == reg
		default: // writes a SIMD&FP register
			return false
		}
	}
	return rt == reg // data processing: Rd
}

func (rc *recovery) handleBr(subInstrValue uint32, r *bytes.Reader, posToAddress func(pos int64) uint64, adrpTarget uint64, addressToPos func(offset uint64) int64, result map[uint64]uint64, engine *disass.MachoDisass, register uint8, returns map[uint64]bool, visited map[uint64][]uint8) bool {
	// We aim to recover jump tables and all branches
	brTargetRegister := emulate.ExtractRegister(subInstrValue, 1)
	// back moves the reader n instructions back; it fails at the section start.
	back := func(n int64) bool {
		_, err := r.Seek(-n*int64(binary.Size(uint32(0))), io.SeekCurrent)
		return err == nil
	}

	if !back(2) {
		return false
	}
	err := binary.Read(r, binary.LittleEndian, &subInstrValue)
	if err == io.EOF {
		return false
	}
	if !emulate.IsADD(subInstrValue) || brTargetRegister != emulate.ExtractRegister(subInstrValue, 0) {
		return false
	}
	addSourceRegister := emulate.ExtractRegister(subInstrValue, 2)

	if !back(2) {
		return false
	}
	adrAddr := posToAddress(readerPos(r))
	// We skip the adr instruction

	if !back(1) {
		return false
	}
	err = binary.Read(r, binary.LittleEndian, &subInstrValue)
	if err == io.EOF {
		return false
	}
	if (subInstrValue&0xFFE0FC00) != 0xB8A07800 || addSourceRegister != emulate.ExtractRegister(subInstrValue, 0) {
		return false
	}
	ldrswSourceRegister := emulate.ExtractRegister(subInstrValue, 1)
	ldrswSecondSourceRegister := emulate.ExtractRegister(subInstrValue, 2)

	if !back(2) {
		return false
	}
	err = binary.Read(r, binary.LittleEndian, &subInstrValue)
	if err == io.EOF {
		return false
	}
	if !emulate.IsADD(subInstrValue) || ldrswSourceRegister != emulate.ExtractRegister(subInstrValue, 0) {
		return false
	}
	addSourceRegister = emulate.ExtractRegister(subInstrValue, 1)
	addImmediate := emulate.ExtractImmediate(subInstrValue)

	if !back(2) {
		return false
	}
	err = binary.Read(r, binary.LittleEndian, &subInstrValue)
	if err == io.EOF {
		return false
	}
	if !emulate.IsADRP(subInstrValue) || addSourceRegister != emulate.ExtractRegister(subInstrValue, 0) {
		return false
	}
	instrAddr := posToAddress(readerPos(r))
	// The jump table has its own ADRP. Keep adrpTarget: the cases continue to
	// track the register loaded by the original ADRP.
	jumpTablePage := emulate.ExtractADRPTarget(subInstrValue, instrAddr)

	jumpTableAddr := jumpTablePage + uint64(addImmediate)

	// We need to recover the jump table size
	// We skip the csneg instruction
	if !back(3) {
		return false
	}
	err = binary.Read(r, binary.LittleEndian, &subInstrValue)
	if err == io.EOF {
		return false
	}
	if (subInstrValue&0x7F80001F) != 0x7100001f || ldrswSecondSourceRegister != emulate.ExtractRegister(subInstrValue, 1) {
		return false
	}
	jumpTableCount := (subInstrValue >> 10) & 0xFFF
	if (subInstrValue>>22)&1 == 1 {
		jumpTableCount = jumpTableCount << 12
	}

	// We set the pointer to the jump table
	// The table holds signed 32-bit offsets (loaded with LDRSW) from the ADR.
	// A table outside the analysed section cannot be read.
	readPos := addressToPos(jumpTableAddr)
	if readPos < 0 || readPos >= r.Size() {
		return true
	}
	r.Seek(readPos, io.SeekStart)
	for range jumpTableCount {
		var jumpOffset int32
		err = binary.Read(r, binary.LittleEndian, &jumpOffset)
		if err == io.EOF {
			break
		}
		branchAddr := uint64(int64(adrAddr) + int64(jumpOffset))

		casePos := addressToPos(branchAddr)
		if casePos < 0 || casePos >= r.Size() {
			continue
		}
		pos := readerPos(r)
		r.Seek(casePos, io.SeekStart)
		maps.Copy(result, rc.findUsagesOfRegister(r, engine, branchAddr, register, adrpTarget, returns, visited))
		r.Seek(pos, io.SeekStart)
	}
	return true
}

func (rc *recovery) handleBranch(subInstrValue uint32, subAddress uint64, r *bytes.Reader, result map[uint64]uint64, engine *disass.MachoDisass, register uint8, adrpTarget uint64, returns map[uint64]bool, visited map[uint64][]uint8) bool {

	branchAddr, ok := branchTarget(subInstrValue, subAddress)
	if !ok {
		return false
	}

	pos := readerPos(r)
	readOffset := int64(branchAddr) - int64(subAddress) - int64(binary.Size(uint32(0)))
	// Branches leaving the analysed code (e.g. into another section) cannot
	// be followed; a failed Seek would analyse the wrong bytes.
	if target := pos + readOffset; target >= 0 && target < r.Size() {
		r.Seek(target, io.SeekStart)
		maps.Copy(result, rc.findUsagesOfRegister(r, engine, branchAddr, register, adrpTarget, returns, visited))
		r.Seek(pos, io.SeekStart)
	}

	if (subInstrValue & 0xFC000000) == 0x14000000 {
		// We stop the current branch in case of an unconditional branch
		return true
	}
	return false
}

func readerPos(r *bytes.Reader) int64 {
	return r.Size() - int64(r.Len())
}

func (rc *recovery) handleMov(subInstrValue uint32, register uint8, r *bytes.Reader, result map[uint64]uint64, engine *disass.MachoDisass, subAddress uint64, adrpTarget uint64, returns map[uint64]bool, visited map[uint64][]uint8) {
	source := emulate.ExtractRegister(subInstrValue, 2)

	if source == register {
		destinationRegister := emulate.ExtractRegister(subInstrValue, 0)

		pos := readerPos(r)
		maps.Copy(result, rc.findUsagesOfRegister(r, engine, subAddress+uint64(binary.Size(uint32(0))), destinationRegister, adrpTarget, returns, visited))
		r.Seek(pos, io.SeekStart)
	}
}

func (rc *recovery) mayReturn(r *bytes.Reader, engine *disass.MachoDisass, startAddr uint64, addressToPos func(offset uint64) int64, returns map[uint64]bool, visited map[uint64]bool) (bool, error) {
	funcReturns, ok := returns[startAddr]
	if ok {
		return funcReturns, nil
	}

	name, ok := engine.FindSymbol(startAddr)
	if ok && name == "_panic" {
		returns[startAddr] = false
		return false, nil
	}

	startPos := addressToPos(startAddr)
	// Functions outside the analysed section (e.g. kernel functions called by
	// a KEXT) are analysed in their own fileset entry. Seeking there would
	// fail silently (or hit EOF) and analyse unrelated bytes instead, which
	// made results depend on where the kernel lies in the collection.
	if startPos < 0 || startPos >= r.Size() {
		funcReturns := rc.foreign.mayReturn(startAddr, 0)
		returns[startAddr] = funcReturns
		return funcReturns, nil
	}
	if _, err := r.Seek(startPos, io.SeekStart); err != nil {
		return true, nil
	}
	posToAddress := func(pos int64) uint64 { return uint64(pos-startPos) + startAddr }
	for range 1000 {
		subAddress := posToAddress(readerPos(r))

		var subInstrValue uint32
		err := binary.Read(r, binary.LittleEndian, &subInstrValue)
		if err == io.EOF {
			break
		}

		hasVisited, ok := visited[subAddress]
		if ok && hasVisited {
			return false, nil
		} else {
			visited[subAddress] = true
		}

		if (subInstrValue&0xFFFFFC1F) == 0xD65F0000 || subInstrValue == 0xD65F0BFF || subInstrValue == 0xD65F0FFF || (subInstrValue&0xFFE0001F) == 0xD4200000 {
			// Return or BRK instruction
			returns[startAddr] = true
			return true, nil
		} else if isAuthenticatedJump(subInstrValue) {
			// Indirect jump (e.g. a tail call): assume it returns.
			returns[startAddr] = true
			return true, nil
		} else if emulate.IsBL(subInstrValue) || emulate.IsBLR(subInstrValue) {
			var decoder disassemble.Decoder
			var instruction disassemble.Inst
			if err := decoder.DecomposeInto(subAddress, subInstrValue, &instruction); err != nil {
				return true, err
			}
			if instruction.Operation != disassemble.ARM64_BL && instruction.Operation != disassemble.ARM64_B {
				return true, nil
			}
			if int(instruction.NumOps) < 1 {
				return true, nil
			}
			target := instruction.Operands[0].Immediate

			pos := readerPos(r)
			r.Seek(addressToPos(target), io.SeekStart)
			funcReturns, err := rc.mayReturn(r, engine, target, addressToPos, returns, visited)
			if err == nil && !funcReturns {
				returns[startAddr] = false
				return false, nil
			}
			r.Seek(pos, io.SeekStart)
		} else if !emulate.IsLinearInst(subInstrValue) {
			branchAddr, ok := branchTarget(subInstrValue, subAddress)
			if !ok {
				return true, fmt.Errorf("Could not identify branch target")
			}

			pos := readerPos(r)
			r.Seek(addressToPos(branchAddr), io.SeekStart)
			funcReturns, err := rc.mayReturn(r, engine, branchAddr, addressToPos, returns, visited)
			if err != nil || funcReturns {
				returns[startAddr] = true
				return true, err
			} else if (subInstrValue & 0xFC000000) == 0x14000000 {
				// Unconditional branch
				returns[startAddr] = false
				return false, nil
			}
			r.Seek(pos, io.SeekStart)
		}
	}
	return true, nil
}

func branchTarget(insn uint32, pc uint64) (uint64, bool) {
	switch {
	case insn&0x7C000000 == 0x14000000:
		imm26 := int64(insn & 0x03FFFFFF)
		return uint64(int64(pc) + signExtend(imm26<<2, 28)), true

	case insn&0xFF000010 == 0x54000000:
		imm19 := int64((insn >> 5) & 0x7FFFF)
		return uint64(int64(pc) + signExtend(imm19<<2, 21)), true

	case insn&0x7E000000 == 0x34000000:
		imm19 := int64((insn >> 5) & 0x7FFFF)
		return uint64(int64(pc) + signExtend(imm19<<2, 21)), true

	case insn&0x7E000000 == 0x36000000:
		imm14 := int64((insn >> 5) & 0x3FFF)
		return uint64(int64(pc) + signExtend(imm14<<2, 16)), true
	}

	return 0, false
}

func signExtend(value int64, bits uint) int64 {
	shift := 64 - bits
	return (value << shift) >> shift
}

// recoverReferencesBootdataStaticIf returns the 32-bit deltas of the kernel's
// __BOOTDATA,__static_if entries.
func recoverReferencesBootdataStaticIf(msfe *macho.File) (map[uint64]uint64, error) {
	staticifSection := msfe.Section("__BOOTDATA", "__static_if")
	if staticifSection == nil {
		return nil, nil
	}
	staticifSectionBytes, err := staticifSection.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __static_if: %w", err)
	}

	result := make(map[uint64]uint64)
	r := bytes.NewReader(staticifSectionBytes)
	for {
		currentAddress := staticifSection.Addr + uint64(r.Size()) - uint64(r.Len())

		var offset int32
		err := binary.Read(r, binary.LittleEndian, &offset)
		if err != nil {
			break
		}
		targetAddress := currentAddress
		if offset >= 0 {
			targetAddress += uint64(offset)
		} else {
			targetAddress -= uint64(-offset)
		}
		result[currentAddress] = targetAddress

		// We ignore the second 4-byte value
		r.Seek(4, io.SeekCurrent)
		// We ignore the last 8-byte value as it is an absolute pointer already handled
		r.Seek(8, io.SeekCurrent)
	}
	return result, nil
}

// recoverReferencesTextCopyioVectors returns the entries of the kernel's
// __TEXT,__copyio_vectors table: 64-bit offsets from the start of the table.
func recoverReferencesTextCopyioVectors(msfe *macho.File) (map[uint64]uint64, error) {
	copyioVectors := msfe.Section("__TEXT", "__copyio_vectors")
	if copyioVectors == nil {
		return nil, nil
	}
	copyioSectionBytes, err := copyioVectors.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __copyio_vectors: %w", err)
	}

	result := make(map[uint64]uint64)
	r := bytes.NewReader(copyioSectionBytes)
	for {
		currentAddress := copyioVectors.Addr + uint64(r.Size()) - uint64(r.Len())

		var offset int64
		err := binary.Read(r, binary.LittleEndian, &offset)
		if err != nil {
			break
		}

		// Entries are offsets from the start of the table.
		targetAddress := copyioVectors.Addr
		if offset > 0 {
			targetAddress += uint64(offset)
		} else {
			targetAddress -= uint64(-offset)
		}
		result[currentAddress] = targetAddress
	}
	return result, nil
}

// recoverReferencesTextEhFrame returns the CIE pointers and initial locations
// of the FDEs in __TEXT,__eh_frame, described like ld64 does.
func recoverReferencesTextEhFrame(msfe *macho.File) ([]*types.SplitInfoEntry, error) {
	ehSection := msfe.Section("__TEXT", "__eh_frame")
	if ehSection == nil {
		return nil, nil
	}
	ehSectionBytes, err := ehSection.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __eh_frame: %w", err)
	}
	frame, err := dwf.ParseFrame(ehSectionBytes, binary.LittleEndian, 8, ehSection.Addr, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse __eh_frame: %w", err)
	}

	result := make([]*types.SplitInfoEntry, 0)
	for _, entry := range frame.FDEs {
		// The CIE pointer is a 32-bit field; the pc-relative initial location
		// that follows it is 64 bits wide on arm64 (as described by ld64).
		idOffset := entry.Offset + 4
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_DELTA_32,
			SourceVmAddr: ehSection.Addr + uint64(idOffset),
			TargetVmAddr: ehSection.Addr + uint64(entry.CIE.Offset),
		})

		sourceOffset := entry.Offset + 8
		result = append(result, &types.SplitInfoEntry{
			Kind:         types.DYLD_CACHE_ADJ_V2_DELTA_64,
			SourceVmAddr: ehSection.Addr + uint64(sourceOffset),
			TargetVmAddr: entry.InitialLocation,
		})
	}
	return result, nil
}
