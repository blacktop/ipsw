package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/disass"
)

type DyldDisass struct {
	f      *File
	cfg    *disass.Config
	tr     *disass.Triage
	dylibs []*CacheImage
}

func NewDyldDisass(f *File, cfg *disass.Config) *DyldDisass {
	return &DyldDisass{f: f, cfg: cfg}
}

func (d DyldDisass) Demangle() bool {
	return d.cfg.Demangle
}
func (d DyldDisass) Quite() bool {
	return d.cfg.Quite
}
func (d DyldDisass) Color() bool {
	return d.cfg.Color
}
func (d DyldDisass) AsJSON() bool {
	return d.cfg.AsJSON
}
func (d DyldDisass) Data() []byte {
	return d.cfg.Data
}
func (d DyldDisass) StartAddr() uint64 {
	return d.cfg.StartAddress
}
func (d DyldDisass) Middle() uint64 {
	return d.cfg.Middle
}

func (d DyldDisass) Dylibs() []*CacheImage {
	return d.dylibs
}

func (d DyldDisass) hasDep(img *CacheImage) bool {
	for _, i := range d.dylibs {
		if i == img {
			return true
		}
	}
	return false
}

// Contains returns true if Triage immediates contains a given address and will return the instruction address
func (d DyldDisass) Contains(address uint64) (bool, uint64) {
	for loc, addr := range d.tr.Addresses {
		if addr == address {
			return true, loc
		}
	}
	return false, 0
}

func (d DyldDisass) HasLoc(location uint64) (bool, uint64) {
	for loc, addr := range d.tr.Addresses {
		if loc == location {
			return true, addr
		}
	}
	return false, 0
}

// IsLocation returns if given address is a local branch location within the disassembled function
func (d DyldDisass) IsLocation(imm uint64) bool {
	if _, ok := d.tr.Locations[imm]; ok {
		return true
	}
	return false
}

// IsBranchLocation returns if given address is branch to a location instruction
func (d DyldDisass) IsBranchLocation(addr uint64) (bool, uint64) {
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
func (d DyldDisass) IsData(addr uint64) (bool, *disass.AddrDetails) {
	if detail, ok := d.tr.Details[addr]; ok {
		if strings.Contains(strings.ToLower(detail.Segment), "data") {
			return true, &detail
		}
	}
	return false, nil
}

// Triage walks a function and analyzes all immediates
func (d *DyldDisass) Triage() error {
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	d.tr = &disass.Triage{
		Addresses: make(map[uint64]uint64),
		Locations: make(map[uint64][]uint64),
	}
	startAddr := d.StartAddr()
	r := bytes.NewReader(d.Data())

	// instructions, err := disassemble.GetInstructions(d.startAddr(), d.data())
	// if err != nil {
	// 	return err
	// }

	// for _, block := range instructions.Blocks() {
	// 	for _, i := range block {
	// 		fmt.Printf("%#08x:  %s\t%s\n", uint64(i.Address), disassemble.GetOpCodeByteString(i.Raw), i)
	// 	}
	// 	fmt.Println()
	// }
	// fmt.Println("DONE")

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

		if strings.Contains(instruction.Encoding.String(), "branch") { // TODO: this could be slow?
			for _, op := range instruction.Operands {
				if op.Class == disassemble.LABEL {
					d.tr.Addresses[instruction.Address] = uint64(op.Immediate)
				}
			}
		} else if strings.Contains(instruction.Encoding.String(), "loadlit") { // TODO: this could be slow?
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

		// lookup adrp/ldr or add address as a cstring or symbol name
		// if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
		// 	if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
		// 		adrpRegister := prevInstruction.Operands()[0].Reg[0]
		// 		adrpImm := prevInstruction.Operands()[1].Immediate
		// 		if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
		// 			adrpImm += operands[1].Immediate
		// 		} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
		// 			adrpImm += operands[2].Immediate
		// 		}
		// 		d.tr.addresses[i.Instruction.Address()] = adrpImm
		// 	}

		// } else if i.Instruction.Group() == arm64.GROUP_BRANCH_EXCEPTION_SYSTEM { // check if branch location is a function
		// 	if operands := i.Instruction.Operands(); operands != nil {
		// 		for _, operand := range operands {
		// 			if operand.OpClass == arm64.LABEL {
		// 				d.tr.addresses[i.Instruction.Address()] = operand.Immediate
		// 			}
		// 		}
		// 	}
		// } else if i.Instruction.Group() == arm64.GROUP_DATA_PROCESSING_IMM || i.Instruction.Group() == arm64.GROUP_LOAD_STORE {
		// 	operation := i.Instruction.Operation()
		// 	if operation == arm64.ARM64_LDR || operation == arm64.ARM64_ADR {
		// 		if operands := i.Instruction.Operands(); operands != nil {
		// 			for _, operand := range operands {
		// 				if operand.OpClass == arm64.LABEL {
		// 					d.tr.addresses[i.Instruction.Address()] = operand.Immediate
		// 				}
		// 			}
		// 		}
		// 	}
		// }

		prevInstr = instruction
		startAddr += uint64(binary.Size(uint32(0)))
	}

	if !d.Quite() {
		d.tr.Details = make(map[uint64]disass.AddrDetails)

		for addr, imm := range d.tr.Addresses {
			image, err := d.f.GetImageContainingVMAddr(imm)
			if err != nil {
				log.Error(err.Error())
				continue
				// return err
			}

			if !d.hasDep(image) {
				d.dylibs = append(d.dylibs, image)
			}

			m, err := image.GetMacho()
			if err != nil {
				return err
			}
			defer m.Close()

			if fn, err := m.GetFunctionForVMAddr(addr); err == nil {
				d.tr.Function = &fn
				if d.tr.Function.StartAddr <= imm && imm < d.tr.Function.EndAddr {
					d.tr.Locations[imm] = append(d.tr.Locations[imm], addr)
					continue
				}
			}

			if c := m.FindSectionForVMAddr(imm); c != nil {
				d.tr.Details[imm] = disass.AddrDetails{
					Image:   filepath.Base(image.Name),
					Segment: c.Seg,
					Section: c.Name,
				}
			}
		}
	}

	return nil
}

// ImageDependencies recursively returns all the image's loaded dylibs and those dylibs' loaded dylibs etc
// func (f *File) ImageDependencies(imageName string) error {

// 	image, err := f.Image(imageName)
// 	if err != nil {
// 		return err
// 	}

// 	m, err := image.GetPartialMacho()
// 	if err != nil {
// 		return err
// 	}
// 	defer m.Close()

// 	imports := m.ImportedLibraries()
// 	if len(imports) == 0 {
// 		return nil
// 	}

// 	for _, imp := range imports {
// 		if !utils.StrSliceHas(image.Analysis.Dependencies, imp) {
// 			image.Analysis.Dependencies = append(image.Analysis.Dependencies, imp)
// 			if err := f.ImageDependencies(imp); err != nil {
// 				return err
// 			}
// 			image.Analysis.Dependencies = utils.Unique(image.Analysis.Dependencies)
// 		}
// 	}

// 	return nil
// }

// IsFunctionStart checks if address is at a function start and returns symbol name
func (d DyldDisass) IsFunctionStart(addr uint64) (bool, string) {
	image, err := d.f.Image(d.cfg.Image)
	if err != nil {
		return false, err.Error()
	}
	m, err := image.GetMacho()
	if err != nil {
		return false, err.Error()
	}
	for _, fn := range m.GetFunctions() {
		if addr == fn.StartAddr {
			if symName, ok := d.f.AddressToSymbol[addr]; ok {
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

// FindSymbol returns symbol from the addr2symbol map for a given virtual address
func (d DyldDisass) FindSymbol(addr uint64) (string, bool) {
	if symName, ok := d.f.AddressToSymbol[addr]; ok {
		if d.cfg.Demangle {
			return demangle.Do(symName, false, false), true
		}
		return symName, true
	}
	return "", false
}

func (d DyldDisass) GetCString(addr uint64) (string, error) {
	return d.f.GetCString(addr)
}
