package disass

import (
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

type DyldDisass struct {
	f   *dyld.File
	cfg *Config
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

func (d addrDetails) String() string {
	return fmt.Sprintf("%s/%s.%s", d.Image, d.Segment, d.Section)
}

type Triage struct {
	Dylibs    dylibArray
	Details   map[uint64]addrDetails
	function  *types.Function
	addresses map[uint64]uint64
	locations []uint64
}

// Contains returns true if Triage immediates contains a given address and will return the instruction address
func (t *Triage) Contains(address uint64) (bool, uint64) {
	for loc, addr := range t.addresses {
		if addr == address {
			return true, loc
		}
	}
	return false, 0
}

func (t *Triage) HasLoc(location uint64) (bool, uint64) {
	for loc, addr := range t.addresses {
		if loc == location {
			return true, addr
		}
	}
	return false, 0
}

// IsLocation returns if given address is a local branch location within the disassembled function
func (t *Triage) IsBranchLocation(addr uint64) bool {
	for _, loc := range t.locations {
		if addr == loc {
			return true
		}
	}
	return false
}

// IsData returns if given address is a data variable address referenced in the disassembled function
func (t *Triage) IsData(addr uint64) bool {
	if detail, ok := t.Details[addr]; ok {
		if strings.Contains(strings.ToLower(detail.Segment), "data") {
			return true
		}
	}
	return false
}

// FirstPassTriage walks a function and analyzes all immediates
func FirstPassTriage(f *dyld.File, fn *types.Function, r io.ReadSeeker, details bool) (*Triage, error) {
	var triage Triage
	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	triage.function = fn
	triage.addresses = make(map[uint64]uint64)
	startAddr := fn.StartAddr

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

		if instruction.Encoding == disassemble.ENC_BL_ONLY_BRANCH_IMM || instruction.Encoding == disassemble.ENC_B_ONLY_BRANCH_IMM {
			triage.addresses[instruction.Address] = uint64(instruction.Operands[0].Immediate)
		} else if instruction.Encoding == disassemble.ENC_CBZ_64_COMPBRANCH {
			triage.addresses[instruction.Address] = uint64(instruction.Operands[1].Immediate)
		} else if instruction.Operation == disassemble.ARM64_ADR || instruction.Operation == disassemble.ARM64_LDR {
			triage.addresses[instruction.Address] = instruction.Operands[1].Immediate
		} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
			(instruction.Operation == disassemble.ARM64_ADD || instruction.Operation == disassemble.ARM64_LDR) {
			adrpRegister := prevInstr.Operands[0].Registers[0]
			adrpImm := prevInstr.Operands[1].Immediate
			if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[2].Immediate
			}
			triage.addresses[instruction.Address] = adrpImm
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
		// 		triage.addresses[i.Instruction.Address()] = adrpImm
		// 	}

		// } else if i.Instruction.Group() == arm64.GROUP_BRANCH_EXCEPTION_SYSTEM { // check if branch location is a function
		// 	if operands := i.Instruction.Operands(); operands != nil {
		// 		for _, operand := range operands {
		// 			if operand.OpClass == arm64.LABEL {
		// 				triage.addresses[i.Instruction.Address()] = operand.Immediate
		// 			}
		// 		}
		// 	}
		// } else if i.Instruction.Group() == arm64.GROUP_DATA_PROCESSING_IMM || i.Instruction.Group() == arm64.GROUP_LOAD_STORE {
		// 	operation := i.Instruction.Operation()
		// 	if operation == arm64.ARM64_LDR || operation == arm64.ARM64_ADR {
		// 		if operands := i.Instruction.Operands(); operands != nil {
		// 			for _, operand := range operands {
		// 				if operand.OpClass == arm64.LABEL {
		// 					triage.addresses[i.Instruction.Address()] = operand.Immediate
		// 				}
		// 			}
		// 		}
		// 	}
		// }

		prevInstr = instruction
		startAddr += uint64(binary.Size(uint32(0)))
	}

	if details {
		triage.Details = make(map[uint64]addrDetails)

		for _, addr := range triage.addresses {
			image, err := f.GetImageContainingVMAddr(addr)
			if err != nil {
				return nil, err
			}

			if !triage.Dylibs.contains(image) {
				triage.Dylibs = append(triage.Dylibs, image)
			}

			if triage.function != nil {
				if triage.function.StartAddr <= addr && addr < triage.function.EndAddr {
					triage.locations = append(triage.locations, addr)
					continue
				}
			}

			m, err := image.GetPartialMacho()
			if err != nil {
				return nil, err
			}
			defer m.Close()

			if c := m.FindSectionForVMAddr(addr); c != nil {
				triage.Details[addr] = addrDetails{
					Image:   filepath.Base(image.Name),
					Segment: c.Seg,
					Section: c.Name,
				}
			}
		}
	}

	return &triage, nil
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

// AnalyzeImage analyzes an image by parsing it's symbols, stubs and GOT
// func (f *File) AnalyzeImage(image *CacheImage) error {

// 	if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
// 		log.Errorf("failed to parse exported symbols for %s", image.Name)
// 	}

// 	if err := f.GetLocalSymbolsForImage(image); err != nil {
// 		if !errors.Is(err, ErrNoLocals) {
// 			return err
// 		}
// 	}

// 	if !f.IsArm64() {
// 		utils.Indent(log.Warn, 2)("image analysis of stubs and GOT only works on arm64 architectures")
// 	}

// 	if !image.Analysis.State.IsStubHelpersDone() && f.IsArm64() {
// 		log.Debugf("parsing %s symbol stub helpers", image.Name)
// 		if err := f.ParseSymbolStubHelpers(image); err != nil {
// 			if !errors.Is(err, ErrMachOSectionNotFound) {
// 				return err
// 			}
// 		}
// 	}

// 	if !image.Analysis.State.IsGotDone() && f.IsArm64() {
// 		log.Debugf("parsing %s global offset table", image.Name)
// 		if err := f.ParseGOT(image); err != nil {
// 			return err
// 		}

// 		for entry, target := range image.Analysis.GotPointers {
// 			if symName, ok := f.AddressToSymbol[target]; ok {
// 				f.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
// 			} else {
// 				if img, err := f.GetImageContainingTextAddr(target); err == nil {
// 					if err := f.AnalyzeImage(img); err != nil {
// 						return err
// 					}
// 					if symName, ok := f.AddressToSymbol[target]; ok {
// 						f.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
// 					} else if laptr, ok := image.Analysis.GotPointers[target]; ok {
// 						if symName, ok := f.AddressToSymbol[laptr]; ok {
// 							f.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
// 						}
// 					} else {
// 						utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for GOT entry %#x => %#x in %s", entry, target, img.Name))
// 						f.AddressToSymbol[entry] = fmt.Sprintf("__got_%x ; %s", target, filepath.Base(img.Name))
// 					}
// 				} else {
// 					f.AddressToSymbol[entry] = fmt.Sprintf("__got_%x", target)
// 				}

// 			}
// 		}
// 	}

// 	if !image.Analysis.State.IsStubsDone() && f.IsArm64() {
// 		log.Debugf("parsing %s symbol stubs", image.Name)
// 		if err := f.ParseSymbolStubs(image); err != nil {
// 			return err
// 		}

// 		for stub, target := range image.Analysis.SymbolStubs {
// 			if symName, ok := f.AddressToSymbol[target]; ok {
// 				f.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
// 			} else {
// 				img, err := f.GetImageContainingTextAddr(target)
// 				if err != nil {
// 					return err
// 				}
// 				if err := f.AnalyzeImage(img); err != nil {
// 					return err
// 				}
// 				if symName, ok := f.AddressToSymbol[target]; ok {
// 					f.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
// 				} else if laptr, ok := image.Analysis.GotPointers[target]; ok {
// 					if symName, ok := f.AddressToSymbol[laptr]; ok {
// 						f.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
// 					}
// 				} else {
// 					utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for stub %#x => %#x in %s", stub, target, img.Name))
// 					f.AddressToSymbol[stub] = fmt.Sprintf("__stub_%x ; %s", target, filepath.Base(img.Name))
// 				}
// 			}
// 		}
// 	}

// 	return nil
// }
