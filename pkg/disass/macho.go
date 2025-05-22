package disass

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

type MachoDisass struct {
	f         *macho.File
	cfg       *Config
	tr        *Triage
	a2s       map[uint64]string
	sinfo     map[uint64]uint64
	swiftstrs map[uint64]string
}

func NewMachoDisass(f *macho.File, cfg *Config) *MachoDisass {
	return &MachoDisass{f: f, cfg: cfg, a2s: make(map[uint64]string, 0), swiftstrs: make(map[uint64]string, 0)}
}

func (d MachoDisass) Demangle() bool {
	return d.cfg.Demangle
}
func (d MachoDisass) Quite() bool {
	return d.cfg.Quite
}
func (d MachoDisass) Color() bool {
	return d.cfg.Color
}
func (d MachoDisass) AsJSON() bool {
	return d.cfg.AsJSON
}
func (d MachoDisass) Data() []byte {
	return d.cfg.Data
}
func (d MachoDisass) StartAddr() uint64 {
	return d.cfg.StartAddress
}
func (d MachoDisass) Middle() uint64 {
	return d.cfg.Middle
}
func (d MachoDisass) ReadAddr(addr uint64) (uint64, error) {
	ptr, err := d.f.GetPointerAtAddress(addr)
	if err != nil {
		return 0, err
	}
	return d.f.SlidePointer(ptr), nil
}

// Triage walks a function and analyzes all immediates
func (d *MachoDisass) Triage() error {
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	d.tr = &Triage{
		Addresses: make(map[uint64]uint64),
		Locations: make(map[uint64][]uint64),
	}
	startAddr := d.StartAddr()
	r := bytes.NewReader(d.Data())

	// extract all immediates
	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}

		if strings.Contains(instruction.Encoding.String(), "branch") {
			for _, op := range instruction.Operands {
				if op.Class == disassemble.LABEL {
					d.tr.Addresses[instruction.Address] = uint64(op.Immediate)
				}
			}
		} else if strings.Contains(instruction.Encoding.String(), "loadlit") {
			d.tr.Addresses[instruction.Address] = uint64(instruction.Operands[1].Immediate)
		} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
			(instruction.Operation == disassemble.ARM64_ADD ||
				instruction.Operation == disassemble.ARM64_LDR ||
				instruction.Operation == disassemble.ARM64_LDRB ||
				instruction.Operation == disassemble.ARM64_LDRSW) {
			adrpRegister := prevInstr.Operands[0].Registers[0]
			adrpImm := prevInstr.Operands[1].Immediate
			if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			} else if instruction.Operation == disassemble.ARM64_LDRB && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[2].Immediate
			} else if instruction.Operation == disassemble.ARM64_LDRSW && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			}
			d.tr.Addresses[instruction.Address] = adrpImm
		}

		prevInstr = instruction
		startAddr += uint64(binary.Size(uint32(0)))
	}

	if !d.Quite() {
		d.tr.Details = make(map[uint64]AddrDetails)

		for addr, imm := range d.tr.Addresses {
			if fn, err := d.f.GetFunctionForVMAddr(addr); err == nil {
				d.tr.Function = &fn
				if d.tr.Function.StartAddr <= imm && imm < d.tr.Function.EndAddr {
					d.tr.Locations[imm] = append(d.tr.Locations[imm], addr)
					continue
				}
			}

			if c := d.f.FindSectionForVMAddr(imm); c != nil {
				d.tr.Details[imm] = AddrDetails{
					Segment: c.Seg,
					Section: c.Name,
				}
			} else {
				ptr, _ := d.f.GetPointerAtAddress(imm)
				ptr = d.f.SlidePointer(ptr)
				if c := d.f.FindSectionForVMAddr(ptr); c != nil {
					d.tr.Details[imm] = AddrDetails{
						Segment: c.Seg,
						Section: c.Name,
						Pointer: ptr,
					}
				}
			}
		}
	}

	return nil
}

// FindSwiftStrings walks a function extracts Swift StringObjects/String Structs/Compiler optimized strings
// ref - test/SILOptimizer/character_literals.swift
// ref - stdlib/public/core/StringObject.swift
func (d *MachoDisass) FindSwiftStrings() (out map[uint64]string, err error) {
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	d.tr = &Triage{
		Addresses: make(map[uint64]uint64),
		Locations: make(map[uint64][]uint64),
	}
	startAddr := d.StartAddr()
	r := bytes.NewReader(d.Data())

	out = make(map[uint64]string)

	ss := make([]byte, 16)
	buf := bytes.NewBuffer(ss)

	strAddr := uint64(0)
	reg := disassemble.REG_NONE
	regVal := uint64(0)
	next := disassemble.REG_NONE
	nextVal := uint64(0)

	// extract all Swift strings
	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)

		if err == io.EOF {
			break
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}

		if instruction.Operation == disassemble.ARM64_MOV {
			if reg == disassemble.REG_NONE {
				strAddr = instruction.Address
				reg = instruction.Operands[0].Registers[0]
				regVal = instruction.Operands[1].Immediate
			} else {
				if regVal > 0 {
					next = instruction.Operands[0].Registers[0]
					nextVal = instruction.Operands[1].Immediate
				} else {
					strAddr = instruction.Address
					reg = instruction.Operands[0].Registers[0]
					regVal = instruction.Operands[1].Immediate
				}
			}
		} else if prevInstr != nil &&
			((prevInstr.Operation == disassemble.ARM64_MOV && instruction.Operation == disassemble.ARM64_MOVK) ||
				(prevInstr.Operation == disassemble.ARM64_MOVK && instruction.Operation == disassemble.ARM64_MOVK)) {
			if reg == instruction.Operands[0].Registers[0] {
				regVal += instruction.Operands[1].Immediate << uint64(instruction.Operands[1].ShiftValue)
			} else if next == instruction.Operands[0].Registers[0] {
				nextVal += instruction.Operands[1].Immediate << uint64(instruction.Operands[1].ShiftValue)
			}
		} else {
			if regVal > 0 && nextVal > 0 {
				discriminator := (nextVal & 0xFF00_0000_0000_0000) >> 56
				count := discriminator & 0xF
				if count > 0 {
					nextVal = nextVal & 0x00FF_FFFF_FFFF_FFFF
					buf.Reset()
					binary.Write(buf, binary.LittleEndian, regVal)
					binary.Write(buf, binary.LittleEndian, nextVal)
					if (discriminator & 0xF0) == 0xE0 { // small ascii string
						if utils.IsASCII(string(ss[:count])) {
							out[strAddr] = string(ss[:count])
							ss = ss[:0]
						}
					} else if (discriminator & 0xF0) == 0xA0 { // small non-ascii string
						out[strAddr] = utils.UnicodeSanitize(string(ss[:count]))
						ss = ss[:0]
					} // TODO: add support for (discriminator & 0xF0) == 0x80 { // large string
				}
			}
			// RESET
			strAddr = uint64(0)
			reg = disassemble.REG_NONE
			regVal = uint64(0)
			next = disassemble.REG_NONE
			nextVal = uint64(0)
		}

		prevInstr = instruction
		startAddr += uint64(binary.Size(uint32(0)))
	}

	return out, nil
}

// IsFunctionStart checks if address is at a function start and returns symbol name
func (d MachoDisass) IsFunctionStart(addr uint64) (bool, string) {
	for _, fn := range d.f.GetFunctions() {
		if addr == fn.StartAddr {
			if symName, ok := d.a2s[addr]; ok {
				if d.Demangle() {
					if strings.HasPrefix(symName, "_$s") { // TODO: better detect swift symbols
						symName, _ = swift.Demangle(symName)
						return ok, symName
					}
					return ok, demangle.Do(symName, false, false)
				}
				return ok, symName
			}
			return true, fmt.Sprintf("sub_%x", addr)
		}
	}
	return false, ""
}

// IsLocation returns if given address is a local branch location within the disassembled function
func (d MachoDisass) IsLocation(imm uint64) bool {
	if _, ok := d.tr.Locations[imm]; ok {
		return true
	}
	return false
}

// IsBranchLocation returns if given address is branch to a location instruction
func (d MachoDisass) IsBranchLocation(addr uint64) (bool, uint64) {
	for loc, addrs := range d.tr.Locations {
		if slices.Contains(addrs, addr) {
			return true, loc
		}
	}
	return false, 0
}

// IsData returns if given address is a data variable address referenced in the disassembled function
func (d MachoDisass) IsData(addr uint64) (bool, *AddrDetails) {
	if detail, ok := d.tr.Details[addr]; ok {
		if strings.Contains(strings.ToLower(detail.Segment), "data") {
			return true, &detail
		}
	}
	return false, nil
}

// IsPointer returns if given address is a pointer to another address
func (d MachoDisass) IsPointer(imm uint64) (bool, *AddrDetails) {
	if deet, ok := d.tr.Details[imm]; ok {
		if deet.Pointer > 0 {
			return true, &deet
		}
	}
	return false, nil
}

// FindSymbol returns symbol from the addr2symbol map for a given virtual address
func (d MachoDisass) FindSymbol(addr uint64) (string, bool) {
	if symName, ok := d.a2s[addr]; ok {
		if d.cfg.Demangle {
			return demangle.Do(symName, false, false), true
		}
		return symName, true
	}
	return "", false
}

func (d MachoDisass) FindSwiftString(addr uint64) (string, bool) {
	if str, ok := d.swiftstrs[addr]; ok {
		return str, true
	}
	return "", false
}

// Contains returns true if Triage immediates contains a given address and will return the instruction address
func (d MachoDisass) Contains(address uint64) (bool, uint64) {
	for loc, addr := range d.tr.Addresses {
		if addr == address {
			return true, loc
		}
	}
	return false, 0
}

func (d MachoDisass) GetCString(addr uint64) (string, error) {
	return d.f.GetCString(addr)
}

func (d MachoDisass) Analyze() error {

	if err := d.parseSymbols(); err != nil {
		return fmt.Errorf("failed to parse symbols: %v", err)
	}

	if err := d.parseImports(); err != nil {
		return fmt.Errorf("failed to parse imports: %v", err)
	}

	if err := d.parseObjC(); err != nil {
		return fmt.Errorf("failed to parse objc runtime: %v", err)
	}

	if err := d.parseSwift(); err != nil {
		return fmt.Errorf("failed to parse swift: %v", err)
	}

	if err := d.parseRebaseInfo(); err != nil {
		if !errors.Is(err, macho.ErrMachODyldInfoNotFound) {
			return fmt.Errorf("failed to parse rebase info: %v", err)
		}
	}

	if err := d.parseHelpers(); err != nil {
		if !errors.Is(err, macho.ErrMachOSectionNotFound) {
			return fmt.Errorf("failed to parse stubs helpers: %v", err)
		}
	}

	if err := d.parseGOT(); err != nil {
		return fmt.Errorf("failed to parse GOT: %v", err)
	}

	if err := d.parseStubs(); err != nil {
		return fmt.Errorf("failed to parse symbol stubs: %v", err)
	}

	if a2s, err := d.FindSwiftStrings(); err == nil {
		maps.Copy(d.swiftstrs, a2s)
	} else {
		return fmt.Errorf("failed to find swift strings: %v", err)
	}

	return nil
}

func (d *MachoDisass) parseSymbols() error {
	for _, sym := range d.f.Symtab.Syms {
		if sym.Value > 0 && len(sym.Name) > 0 {
			if d.cfg.Demangle {
				if strings.HasPrefix(sym.Name, "_$s") { // TODO: better detect swift symbols
					sym.Name, _ = swift.Demangle(sym.Name)
					d.a2s[sym.Value] = sym.Name
				} else {
					d.a2s[sym.Value] = demangle.Do(sym.Name, false, false)
				}
			} else {
				d.a2s[sym.Value] = sym.Name
			}
		}
	}
	exports, err := d.f.GetExports()
	if err != nil {
		if err != macho.ErrMachODyldInfoNotFound {
			return fmt.Errorf("failed to get exports: %v", err)
		}
	}
	for _, sym := range exports {
		if sym.Address > 0 {
			if d.cfg.Demangle && len(sym.Name) > 0 {
				if strings.HasPrefix(sym.Name, "_$s") { // TODO: better detect swift symbols
					sym.Name, _ = swift.Demangle(sym.Name)
					d.a2s[sym.Address] = sym.Name
				} else {
					d.a2s[sym.Address] = demangle.Do(sym.Name, false, false)
				}
			} else {
				d.a2s[sym.Address] = sym.Name
			}
		}
	}
	return nil
}

func (d *MachoDisass) parseRebaseInfo() error {
	d.sinfo = make(map[uint64]uint64)

	if d.f.HasFixups() {
		dcf, err := d.f.DyldChainedFixups()
		if err != nil {
			return fmt.Errorf("failed to parse fixups: %v", err)
		}
		for _, start := range dcf.Starts {
			if start.PageStarts != nil {
				// var sec *macho.Section
				// var lastSec *macho.Section
				for _, fixup := range start.Fixups {
					addr, err := d.f.GetVMAddress(fixup.Offset())
					if err != nil {
						continue
					}
					switch fx := fixup.(type) {
					case fixupchains.Bind:
						// var addend string
						// addr := uint64(fx.Offset()) + d.f.GetBaseAddress()
						// if fullAddend := dcf.Imports[fx.Ordinal()].Addend() + fx.Addend(); fullAddend > 0 {
						// 	addend = fmt.Sprintf(" + %#x", fullAddend)
						// 	addr += fullAddend
						// }
						// sec = d.f.FindSectionForVMAddr(addr)
						// lib := d.f.LibraryOrdinalName(dcf.Imports[fx.Ordinal()].LibOrdinal())
						// if sec != nil && sec != lastSec {
						// 	fmt.Printf("%s.%s\n", sec.Seg, sec.Name)
						// }
						// fmt.Printf("%s\t%s/%s%s\n", fixupchains.Bind(fx).String(d.f.GetBaseAddress()), lib, fx.Name(), addend)
					case fixupchains.Rebase:
						d.sinfo[addr] = uint64(fx.Target()) + d.f.GetBaseAddress()
					}
					// lastSec = sec
				}
			}
		}
	} else {
		rbs, err := d.f.GetRebaseInfo()
		if err != nil {
			return err
		}
		for _, r := range rbs {
			d.sinfo[r.Start+r.Offset] = r.Value
		}
	}

	return nil
}

func (d *MachoDisass) parseObjC() error {
	if d.f.HasObjC() {
		if cfstrs, err := d.f.GetCFStrings(); err == nil {
			for _, cfstr := range cfstrs {
				d.a2s[cfstr.Address] = fmt.Sprintf("%#v", cfstr.Name)
			}
		}
		if selRefs, err := d.f.GetObjCSelectorReferences(); err == nil {
			for off, sel := range selRefs {
				d.a2s[off] = fmt.Sprintf("sel_%s", sel.Name)
				d.a2s[d.f.GetBaseAddress()+sel.VMAddr] = sel.Name
			}
		}
		if classes, err := d.f.GetObjCClasses(); err == nil {
			for _, class := range classes {
				d.a2s[class.ClassPtr] = fmt.Sprintf("class_%s", class.Name)
				d.a2s[class.IsaVMAddr] = fmt.Sprintf("objc_isa_%s", class.Isa)
				for _, meth := range class.ClassMethods {
					if len(meth.Name) > 0 {
						d.a2s[meth.ImpVMAddr] = fmt.Sprintf("+[%s %s]", class.Name, meth.Name)
					}
				}
				for _, imeth := range class.InstanceMethods {
					if len(imeth.Name) > 0 {
						d.a2s[imeth.ImpVMAddr] = fmt.Sprintf("-[%s %s]", class.Name, imeth.Name)
					}
				}
			}
		}
		if classRefs, err := d.f.GetObjCClassReferences(); err == nil {
			for off, class := range classRefs {
				d.a2s[off] = fmt.Sprintf("class_%s", class.Name)
				d.a2s[d.f.GetBaseAddress()+class.ClassPtr] = class.Name
			}
		}
		if superRefs, err := d.f.GetObjCSuperReferences(); err == nil {
			for off, class := range superRefs {
				d.a2s[off] = fmt.Sprintf("class_%s", class.Name)
				d.a2s[class.ClassPtr] = class.Name
				d.a2s[class.IsaVMAddr] = class.Isa
			}
		}
		if protoRefs, err := d.f.GetObjCProtoReferences(); err == nil {
			for off, proto := range protoRefs {
				d.a2s[off] = fmt.Sprintf("proto_%s", proto.Name)
				d.a2s[d.f.GetBaseAddress()+proto.Ptr] = proto.Name
			}
		}
		if objcStubs, err := d.f.GetObjCStubs(func(addr uint64, data []byte) (map[uint64]*objc.Stub, error) {
			stubs := make(map[uint64]*objc.Stub)
			addr2sel, err := ParseStubsASM(data, addr, func(u uint64) (uint64, error) {
				ptr, err := d.f.GetPointerAtAddress(u)
				if err != nil {
					return 0, err
				}
				if name, err := d.f.GetBindName(ptr); err == nil && name == "_objc_msgSend" {
					return 0, nil
				}
				ptr = d.f.SlidePointer(ptr)
				if ptr < d.f.GetBaseAddress() {
					return ptr + d.f.GetBaseAddress(), nil
				}
				return ptr, nil
			})
			if err != nil {
				return nil, err
			}
			for addr, sel := range addr2sel {
				if d.a2s[sel] != "_objc_msgSend" {
					stubs[addr] = &objc.Stub{
						Name:        d.a2s[sel],
						SelectorRef: sel,
					}
				}
			}
			return stubs, nil
		}); err == nil {
			for addr, stub := range objcStubs {
				if len(stub.Name) > 0 {
					d.a2s[addr] = fmt.Sprintf("j__objc_msgSend(x0, \"%s\")", stub.Name)
				}
			}
		}
	}

	return nil
}

func (d *MachoDisass) parseSwift() error {
	if d.f.HasSwift() {
		if types, err := d.f.GetSwiftTypes(); err == nil {
			for _, typ := range types {
				if typ.Name != "" {
					if d.cfg.Demangle {
						typ.Name, _ = swift.Demangle(typ.Name)
					}
					d.a2s[typ.Address] = fmt.Sprintf("type descriptor for %s", typ.Name)
				}
			}
		}
		if fields, err := d.f.GetSwiftFields(); err == nil {
			for _, field := range fields {
				if field.Type != "" {
					if d.cfg.Demangle {
						field.Type, _ = swift.Demangle(field.Type)
					}
					d.a2s[field.Address] = fmt.Sprintf("field descriptor for %s", field.Type)
				}
			}
		}
		if dtds, err := d.f.GetSwiftProtocolConformances(); err == nil {
			for _, dtd := range dtds {
				if dtd.TypeRef.Name != "" {
					if dtd.TypeRef.Parent != nil && dtd.TypeRef.Parent.Name != "" &&
						dtd.TypeRef.Parent.Parent != nil && dtd.TypeRef.Parent.Parent.Name != "" {
						dtd.TypeRef.Name = fmt.Sprintf("%s.%s", dtd.TypeRef.Parent, dtd.TypeRef.Name)
					}
					if d.cfg.Demangle {
						dtd.Protocol, _ = swift.DemangleSimple(dtd.Protocol)
					}
					// log.Debugf("nominal type descriptor for %s : %s", dtd.TypeRef.Name, dtd.Protocol)
					d.a2s[dtd.TypeRef.Address] = fmt.Sprintf("nominal type descriptor for %s : %s", dtd.TypeRef.Name, dtd.Protocol)
				}
			}
		}
	}
	return nil
}

func (d *MachoDisass) parseImports() error {
	if d.f.HasFixups() {
		var addr uint64

		dcf, err := d.f.DyldChainedFixups()
		if err != nil {
			return err
		}
		if dcf.Imports != nil {
			for _, start := range dcf.Starts {
				if start.PageStarts != nil {
					binds := start.Binds()
					if len(binds) > 0 {
						for _, bind := range binds {
							fullAddend := dcf.Imports[bind.Ordinal()].Addend() + bind.Addend()
							addr = d.f.GetBaseAddress() + bind.Offset() + fullAddend
							d.a2s[bind.Raw()] = bind.Name()
							d.a2s[addr] = bind.Name()
						}
					}
				}
			}
		}
	}

	return nil
}

func (d *MachoDisass) parseGOT() error {
	gots, err := ParseGotPtrs(d.f)
	if err != nil {
		return err
	}

	for entry, target := range gots {
		if slide, ok := d.sinfo[entry]; ok {
			target = slide
		}
		if symName, ok := d.a2s[target]; ok {
			d.a2s[entry] = fmt.Sprintf("__got.%s", symName)
		} else if laptr, ok := gots[target]; ok {
			if symName, ok := d.a2s[laptr]; ok {
				d.a2s[entry] = fmt.Sprintf("__got.%s", symName)
			}
		} else {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for GOT entry %#x => %#x", entry, target))
			d.a2s[entry] = fmt.Sprintf("__got_%x", target)
		}
	}

	return nil
}

func (d *MachoDisass) parseStubs() error {
	stubs, err := ParseStubsForMachO(d.f)
	if err != nil {
		return err
	}

	for stub, target := range stubs {
		if slide, ok := d.sinfo[stub]; ok {
			target = slide
		}
		if symName, ok := d.a2s[target]; ok {
			if !strings.HasPrefix(symName, "j_") {
				d.a2s[stub] = "j_" + strings.TrimPrefix(symName, "__stub_helper.")
			} else {
				d.a2s[stub] = symName
			}
		} else {
			if symName, ok := d.a2s[target]; ok {
				d.a2s[stub] = fmt.Sprintf("j_%s", symName)
			} else {
				utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for stub %#x => %#x", stub, target))
				d.a2s[stub] = fmt.Sprintf("__stub_%x", target)
			}
		}
	}

	return nil
}

func (d *MachoDisass) parseHelpers() error {
	helpers, err := ParseHelpersASM(d.f)
	if err != nil {
		return err
	}

	for start, target := range helpers {
		if slide, ok := d.sinfo[start]; ok {
			target = slide
		}
		if symName, ok := d.a2s[target]; ok {
			d.a2s[start] = fmt.Sprintf("__stub_helper.%s", symName)
		} else {
			d.a2s[start] = fmt.Sprintf("__stub_helper.%x", target)
		}
	}

	return nil
}

func (d *MachoDisass) EmptySymMap() bool {
	return len(d.a2s) == 0
}

func (d *MachoDisass) SetStartSym(addr uint64) {
	d.a2s[addr] = "start"
}

func (d *MachoDisass) loadDwarf(machoPath string) error {
	dsymPath := filepath.Join(machoPath+".dSYM", "Contents/Resources/DWARF", filepath.Base(machoPath))
	if _, statErr := os.Stat(dsymPath); statErr == nil {
		dm, err := macho.Open(dsymPath)
		if err != nil {
			return fmt.Errorf("failed to open dSYM file: %v", err)
		} else {
			foundDSYMSymbols := false
			for _, sym := range dm.Symtab.Syms {
				if sym.Name != "" {
					name := sym.Name
					if d.cfg.Demangle {
						if strings.HasPrefix(name, "_$s") {
							name, _ = swift.Demangle(name)
						} else {
							name = demangle.Do(name, false, false)
						}
					}
					d.a2s[sym.Value] = name
					foundDSYMSymbols = true
				}
			}
			dm.Close()
			if foundDSYMSymbols {
				utils.Indent(log.Info, 2)(fmt.Sprintf("Loaded %d symbols from .dSYM file", len(d.a2s)))
			} else {
				utils.Indent(log.Warn, 2)("No symbols found in dSYM file")
			}
		}
	}
	return nil
}

func (d *MachoDisass) getTempCachePath(cacheFile *string) string {
	var tmpfile string
	if d.f != nil {
		uuid := d.f.UUID()
		if uuid.UUID.IsNull() {
			tmpfile = filepath.Base(*cacheFile)
		} else {
			tmpfile = uuid.String() + ".a2s"
		}
	}
	return filepath.Join(os.TempDir(), tmpfile)
}

var ErrCorruptCache = errors.New("corrupt cache file")

func (d *MachoDisass) loadCache(cacheFile *string) error {
	f, err := os.Open(*cacheFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.ErrNotExist
		}
		return fmt.Errorf("failed to open cache file %s: %v", *cacheFile, err)
	}
	defer f.Close()

	a2s := make(map[uint64]string)
	if gobErr := gob.NewDecoder(f).Decode(&a2s); gobErr != nil {
		return ErrCorruptCache
	}

	maps.Copy(d.a2s, a2s)
	log.Infof("Loaded %d symbols from cache file: %s", len(d.a2s), *cacheFile)

	return nil
}

func (d *MachoDisass) OpenOrCreateSymMap(cacheFile *string, machoPath string) error {
	if err := d.loadCache(cacheFile); err == nil {
		return nil // cache file loaded successfully
	} else if errors.Is(err, os.ErrNotExist) {
		tmpcache := d.getTempCachePath(cacheFile)
		if err := d.loadCache(&tmpcache); err == nil {
			*cacheFile = tmpcache
			return nil // temp cache file loaded successfully
		} else if errors.Is(err, os.ErrNotExist) {
			// cache AND temp cache files do not exist (create new one)
		} else if errors.Is(err, ErrCorruptCache) {
			log.Warn("temp cache file is corrupt, recreating it")
			if err := os.Remove(tmpcache); err != nil {
				return fmt.Errorf("failed to remove temp cache file: %v", err)
			}
		} else {
			return fmt.Errorf("failed to load temp cache file: %v", err)
		}
	} else if errors.Is(err, ErrCorruptCache) {
		log.Warn("cache file is corrupt, recreating it")
		if err := os.Remove(*cacheFile); err != nil {
			return fmt.Errorf("failed to remove cache file: %v", err)
		}
	} else {
		return fmt.Errorf("failed to load cache file: %v", err)
	}
	// load the .dSYM file if it exists
	if err := d.loadDwarf(machoPath); err != nil {
		return fmt.Errorf("failed to load dSYM file: %v", err)
	}
	if _, err := os.Create(*cacheFile); err != nil {
		if errors.Is(err, os.ErrPermission) {
			var e *os.PathError
			if errors.As(err, &e) {
				log.Errorf("failed to create symbol cache file %s (most likely a read-only location): %v", filepath.Base(e.Path), e.Err)
			}
			tmpcache := d.getTempCachePath(cacheFile)
			if _, err := os.Create(tmpcache); err != nil {
				return fmt.Errorf("failed to create temp cache file: %v", err)
			}
			utils.Indent(log.Warn, 2)("creating in the temp folder")
			utils.Indent(log.Warn, 3)(fmt.Sprintf("to use in the future supply the flag: --cache %s ", tmpcache))
			*cacheFile = tmpcache
			return nil // Successfully created temp cache file
		}
		return fmt.Errorf("failed to create cache file: %v", err)
	}

	return nil
}

func (d *MachoDisass) SaveAddrToSymMap(dest string) (err error) {
	f, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open symbol cache file %s: %v", dest, err)
	}
	defer f.Close()

	buff := new(bytes.Buffer)

	// Encoding the map
	if err := gob.NewEncoder(buff).Encode(d.a2s); err != nil {
		return fmt.Errorf("failed to encode addr2sym map to binary: %v", err)
	}
	if _, err := buff.WriteTo(f); err != nil {
		return fmt.Errorf("failed to write addr2sym map to file: %v", err)
	}

	return nil
}
