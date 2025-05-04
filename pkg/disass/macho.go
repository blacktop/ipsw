package disass

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
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
	f     *macho.File
	cfg   *Config
	tr    *Triage
	a2s   map[uint64]string
	sinfo map[uint64]uint64
}

func NewMachoDisass(f *macho.File, cfg *Config) *MachoDisass {
	return &MachoDisass{f: f, cfg: cfg, a2s: make(map[uint64]string)}
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

	for _, fn := range d.f.GetFunctions() {
		d.a2s[fn.StartAddr] = fmt.Sprintf("sub_%x", fn.StartAddr)
	}

	if err := d.parseSymbols(); err != nil {
		return fmt.Errorf("failed to parse symbols: %v", err)
	}

	if err := d.parseImports(); err != nil {
		return fmt.Errorf("failed to parse imports: %v", err)
	}

	if err := d.parseObjC(); err != nil {
		return fmt.Errorf("failed to parse objc runtime: %v", err)
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

func (d *MachoDisass) OpenOrCreateSymMap(cacheFile, machoPath string, replace bool) error {
	if _, err := os.Stat(cacheFile); errors.Is(err, os.ErrNotExist) {
		// attempt to create the cache file, create in tmp if permission denied
		if _, err := os.Create(cacheFile); err != nil {
			if errors.Is(err, os.ErrPermission) {
				var e *os.PathError
				if errors.As(err, &e) {
					log.Errorf("failed to create address to symbol cache file %s (%v)", e.Path, e.Err)
				}
				tmpDir := os.TempDir()
				if runtime.GOOS == "darwin" {
					tmpDir = "/tmp"
				}
				cacheFile = filepath.Join(tmpDir, d.f.UUID().String()+".a2s")
				if _, err = os.Create(cacheFile); err != nil {
					return fmt.Errorf("failed to create address-to-symbol cache file %s: %v", cacheFile, err)
				}
				utils.Indent(log.Warn, 2)(fmt.Sprintf("creating in the temp folder: %s", cacheFile))
				utils.Indent(log.Warn, 2)(fmt.Sprintf("to use this symbol cache in the future you must supply the flag: --cache %s ", cacheFile))
			} else {
				return fmt.Errorf("failed to create address-to-symbol cache file %s: %v", cacheFile, err)
			}
		}
		// if dSYM file exists, load symbols from it
		dsym := filepath.Join(machoPath+".dSYM", "Contents/Resources/DWARF", filepath.Base(machoPath))
		if _, err := os.Stat(dsym); err == nil {
			log.Info("Detected dSYM file, using it for symbolication")
			dm, err := macho.Open(dsym)
			if err != nil {
				log.Errorf("failed to open dSYM file for symbolication: %v", err)
			} else {
				for _, sym := range dm.Symtab.Syms {
					if sym.Name != "" {
						d.a2s[sym.Value] = sym.Name
					}
				}
				// If the dSYM file has a symbol map, use it for the output
				if len(d.a2s) > 0 {
					utils.Indent(log.Info, 2)(fmt.Sprintf("Using dSYM symbol map with %d symbols", len(d.a2s)))
				} else {
					utils.Indent(log.Warn, 2)("No symbols found in dSYM file")
				}
			}
		}
	} else {
		log.Infof("Loading symbol cache file...")
		if f, err := os.Open(cacheFile); err != nil {
			return fmt.Errorf("failed to open address-to-symbol cache file %s: %v", cacheFile, err)
		} else {
			if err := gob.NewDecoder(f).Decode(&d.a2s); err != nil {
				yes := false
				if replace {
					yes = true
				} else {
					log.Errorf("address-to-symbol cache file is corrupt: %v", err)
					prompt := &survey.Confirm{
						Message: fmt.Sprintf("Recreate %s. Continue?", cacheFile),
						Default: true,
					}
					survey.AskOne(prompt, &yes)
				}
				if yes {
					f.Close()
					if err := os.Remove(cacheFile); err != nil {
						return fmt.Errorf("failed to remove address-to-symbol cache file %s: %v", cacheFile, err)
					}
					if _, err := os.Create(cacheFile); err != nil {
						return fmt.Errorf("failed to create address-to-symbol cache file %s: %v", cacheFile, err)
					}
				} else {
					return nil
				}
			}
			f.Close()
		}
	}
	return nil
}

func (d *MachoDisass) SaveAddrToSymMap(dest string) error {
	var err error
	var of *os.File

	buff := new(bytes.Buffer)

	of, err = os.Create(dest)
	if errors.Is(err, os.ErrPermission) {
		var e *os.PathError
		if errors.As(err, &e) {
			log.Errorf("failed to create address to symbol cache file %s (%v)", e.Path, e.Err)
		}
		tmpDir := os.TempDir()
		if runtime.GOOS == "darwin" {
			tmpDir = "/tmp"
		}
		tempa2sfile := filepath.Join(tmpDir, dest)
		of, err = os.Create(tempa2sfile)
		if err != nil {
			return err
		}
		utils.Indent(log.Warn, 2)("creating in the temp folder")
		utils.Indent(log.Warn, 3)(fmt.Sprintf("to use in the future you must supply the flag: --cache %s ", tempa2sfile))
	} else if err != nil {
		return fmt.Errorf("failed to open address to symbol cache file %s: %v", dest, err)
	}
	defer of.Close()

	e := gob.NewEncoder(buff)

	// Encoding the map
	err = e.Encode(d.a2s)
	if err != nil {
		return fmt.Errorf("failed to encode addr2sym map to binary: %v", err)
	}

	// gzw := gzip.NewWriter(of)
	// defer gzw.Close()

	// _, err = buff.WriteTo(gzw)
	_, err = buff.WriteTo(of)
	if err != nil {
		return fmt.Errorf("failed to write addr2sym map to gzip file: %v", err)
	}

	return nil
}
