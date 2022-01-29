package disass

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

type MachoDisass struct {
	f     *macho.File
	cfg   *Config
	tr    *Triage
	a2s   map[uint64]string
	sinfo map[uint64]uint64
}

func NewMachoDisass(f *macho.File, a2s *map[uint64]string, cfg *Config) *MachoDisass {
	return &MachoDisass{f: f, a2s: *a2s, cfg: cfg}
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
			}
		}
	}

	return nil
}

// IsFunctionStart checks if address is at a function start and returns symbol name
func (d MachoDisass) IsFunctionStart(addr uint64) (bool, string) {
	for _, fn := range d.f.GetFunctions() {
		if addr == fn.StartAddr {
			if symName, ok := d.a2s[addr]; ok {
				if d.Demangle() {
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
		for _, a := range addrs {
			if a == addr {
				return true, loc
			}
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

func (d MachoDisass) GetCString(addr uint64) (string, error) {
	return d.f.GetCString(addr)
}

func (d MachoDisass) Analyze() error {

	for _, fn := range d.f.GetFunctions() {
		d.a2s[fn.StartAddr] = fmt.Sprintf("sub_%x", fn.StartAddr)
	}

	for _, sym := range d.f.Symtab.Syms {
		d.a2s[sym.Value] = sym.Name
	}

	if err := d.parseImports(); err != nil {
		return fmt.Errorf("failed to parse imports: %v", err)
	}

	if err := d.parseObjC(); err != nil {
		return fmt.Errorf("failed to parse objc runtime: %v", err)
	}

	if err := d.parseRebaseInfo(); err != nil {
		return fmt.Errorf("failed to parse slide info: %v", err)
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
		if methods, err := d.f.GetObjCMethodNames(); err == nil {
			for method, vmaddr := range methods {
				d.a2s[vmaddr] = method
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
				d.a2s[d.f.GetBaseAddress()+class.ClassPtr] = class.Name
			}
		}
		if protoRefs, err := d.f.GetObjCProtoReferences(); err == nil {
			for off, proto := range protoRefs {
				d.a2s[off] = fmt.Sprintf("proto_%s", proto.Name)
				d.a2s[d.f.GetBaseAddress()+proto.Ptr] = proto.Name
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
	stubs, err := ParseStubsASM(d.f)
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
