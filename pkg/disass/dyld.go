package disass

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/dyld"
)

type DyldDisass struct {
	f   *dyld.File
	cfg *Config
	tr  *Triage
}

func NewDyldDisass(f *dyld.File, cfg *Config) *DyldDisass {
	return &DyldDisass{f: f, cfg: cfg}
}

func (d DyldDisass) isMiddle() bool {
	return d.cfg.Middle
}
func (d DyldDisass) demangle() bool {
	return d.cfg.Demangle
}
func (d DyldDisass) quite() bool {
	return d.cfg.Quite
}
func (d DyldDisass) asJSON() bool {
	return d.cfg.AsJSON
}
func (d DyldDisass) data() []byte {
	return d.cfg.Data
}
func (d DyldDisass) startAddr() uint64 {
	return d.cfg.StartAddress
}

type dylibArray []*dyld.CacheImage

func (arr dylibArray) contains(img *dyld.CacheImage) bool {
	for _, i := range arr {
		if i == img {
			return true
		}
	}
	return false
}

type addrDetails struct {
	Image   string
	Segment string
	Section string
}

func (d addrDetails) String() string {
	return fmt.Sprintf("%s/%s.%s", d.Image, d.Segment, d.Section)
}

type Triage struct {
	dylibs    dylibArray
	Details   map[uint64]addrDetails
	function  *types.Function
	addresses map[uint64]uint64
	locations map[uint64][]uint64
}

func (d DyldDisass) Dylibs() []*dyld.CacheImage {
	return d.tr.dylibs
}

// Contains returns true if Triage immediates contains a given address and will return the instruction address
func (d DyldDisass) Contains(address uint64) (bool, uint64) {
	for loc, addr := range d.tr.addresses {
		if addr == address {
			return true, loc
		}
	}
	return false, 0
}

func (d DyldDisass) HasLoc(location uint64) (bool, uint64) {
	for loc, addr := range d.tr.addresses {
		if loc == location {
			return true, addr
		}
	}
	return false, 0
}

// IsLocation returns if given address is a local branch location within the disassembled function
func (d DyldDisass) IsBranchLocation(imm uint64) bool {
	if _, ok := d.tr.locations[imm]; ok {
		return true
	}
	return false
}

// IsData returns if given address is a data variable address referenced in the disassembled function
func (d DyldDisass) IsData(addr uint64) bool {
	if detail, ok := d.tr.Details[addr]; ok {
		if strings.Contains(strings.ToLower(detail.Segment), "data") {
			return true
		}
	}
	return false
}

// Triage walks a function and analyzes all immediates
func (d *DyldDisass) Triage() error {
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	d.tr = &Triage{
		addresses: make(map[uint64]uint64),
		locations: make(map[uint64][]uint64),
	}
	startAddr := d.startAddr()
	r := bytes.NewReader(d.data())

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
			continue
		}

		if strings.Contains(instruction.Encoding.String(), "branch") {
			for _, op := range instruction.Operands {
				if op.Class == disassemble.LABEL {
					d.tr.addresses[instruction.Address] = uint64(op.Immediate)
				}
			}
		} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
			(instruction.Operation == disassemble.ARM64_ADD || instruction.Operation == disassemble.ARM64_LDR) {
			adrpRegister := prevInstr.Operands[0].Registers[0]
			adrpImm := prevInstr.Operands[1].Immediate
			if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[2].Immediate
			}
			d.tr.addresses[instruction.Address] = adrpImm
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

	if !d.quite() {
		d.tr.Details = make(map[uint64]addrDetails)

		for addr, imm := range d.tr.addresses {
			image, err := d.f.GetImageContainingVMAddr(imm)
			if err != nil {
				return err
			}

			if !d.tr.dylibs.contains(image) {
				d.tr.dylibs = append(d.tr.dylibs, image)
			}

			m, err := image.GetMacho()
			if err != nil {
				return err
			}
			defer m.Close()

			if fn, err := m.GetFunctionForVMAddr(d.startAddr()); err == nil {
				d.tr.function = &fn
				if d.tr.function.StartAddr <= imm && imm < d.tr.function.EndAddr {
					d.tr.locations[imm] = append(d.tr.locations[imm], addr)
					continue
				}
			}

			if c := m.FindSectionForVMAddr(imm); c != nil {
				d.tr.Details[imm] = addrDetails{
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
// 		if !utils.StrSliceContains(image.Analysis.Dependencies, imp) {
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
// func (f *File) IsFunctionStart(funcs []types.Function, addr uint64, shouldDemangle bool) (bool, string) {
// 	for _, fn := range funcs {
// 		if addr == fn.StartAddr {
// 			if symName, ok := f.AddressToSymbol[addr]; ok {
// 				if shouldDemangle {
// 					return ok, demangle.Do(symName, false, false)
// 				}
// 				return ok, symName
// 			}
// 			return true, ""
// 		}
// 	}
// 	return false, ""
// }

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
