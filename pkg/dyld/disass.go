package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

type dylibArray []*CacheImage

func (arr dylibArray) contains(img *CacheImage) bool {
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
func (f *File) FirstPassTriage(m *macho.File, fn *types.Function, r io.ReadSeeker, options arm64.Options, details bool) (*Triage, error) {
	var triage Triage
	var prevInstruction arm64.Instruction

	triage.function = fn
	triage.addresses = make(map[uint64]uint64)

	// extract all immediates
	for i := range arm64.Disassemble(r, options) {

		if i.Error != nil {
			continue
		}

		operation := i.Instruction.Operation().String()

		// lookup adrp/ldr or add address as a cstring or symbol name
		if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
			if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
				adrpRegister := prevInstruction.Operands()[0].Reg[0]
				adrpImm := prevInstruction.Operands()[1].Immediate
				if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
					adrpImm += operands[1].Immediate
				} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
					adrpImm += operands[2].Immediate
				}
				triage.addresses[i.Instruction.Address()] = adrpImm
			}

		} else if i.Instruction.Group() == arm64.GROUP_BRANCH_EXCEPTION_SYSTEM { // check if branch location is a function
			if operands := i.Instruction.Operands(); operands != nil {
				for _, operand := range operands {
					if operand.OpClass == arm64.LABEL {
						triage.addresses[i.Instruction.Address()] = operand.Immediate
					}
				}
			}
		} else if i.Instruction.Group() == arm64.GROUP_DATA_PROCESSING_IMM || i.Instruction.Group() == arm64.GROUP_LOAD_STORE {
			operation := i.Instruction.Operation()
			if operation == arm64.ARM64_LDR || operation == arm64.ARM64_ADR {
				if operands := i.Instruction.Operands(); operands != nil {
					for _, operand := range operands {
						if operand.OpClass == arm64.LABEL {
							triage.addresses[i.Instruction.Address()] = operand.Immediate
						}
					}
				}
			}
		}

		prevInstruction = *i.Instruction
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

			if c := m.FindSectionForVMAddr(addr); c != nil {
				triage.Details[addr] = addrDetails{
					Image:   filepath.Base(image.Name),
					Segment: c.Seg,
					Section: c.Name,
				}
			}

			m.Close()
		}
	}

	return &triage, nil
}

// ImageDependencies recursively returns all the image's loaded dylibs and those dylibs' loaded dylibs etc
func (f *File) ImageDependencies(imageName string) error {

	image := f.Image(imageName)

	m, err := image.GetPartialMacho()
	if err != nil {
		return err
	}
	defer m.Close()

	imports := m.ImportedLibraries()
	if len(imports) == 0 {
		return nil
	}

	for _, imp := range imports {
		if !utils.StrSliceContains(image.Analysis.Dependencies, imp) {
			image.Analysis.Dependencies = append(image.Analysis.Dependencies, imp)
			if err := f.ImageDependencies(imp); err != nil {
				return err
			}
			image.Analysis.Dependencies = utils.Unique(image.Analysis.Dependencies)
		}
	}

	return nil
}

// IsFunctionStart checks if address is at a function start and returns symbol name
func (f *File) IsFunctionStart(funcs []types.Function, addr uint64, shouldDemangle bool) (bool, string) {
	for _, fn := range funcs {
		if addr == fn.StartAddr {
			if symName, ok := f.AddressToSymbol[addr]; ok {
				if shouldDemangle {
					return ok, demangle.Do(symName, false, false)
				}
				return ok, symName
			}
			return true, ""
		}
	}
	return false, ""
}

// GetSymbolAddress returns the virtual address and possibly the dylib containing a given symbol
func (f *File) GetSymbolAddress(symbol, imageName string) (uint64, *CacheImage, error) {
	if len(imageName) > 0 {
		if sym, _ := f.FindExportedSymbolInImage(imageName, symbol); sym != nil {
			return sym.Address, f.Image(imageName), nil
		}
	} else {
		// Search ALL dylibs for the symbol
		for _, image := range f.Images {
			if sym, _ := f.FindExportedSymbolInImage(image.Name, symbol); sym != nil {
				return sym.Address, image, nil
			}
		}
	}

	// Search addr2sym map
	for addr, sym := range f.AddressToSymbol {
		if strings.EqualFold(sym, symbol) {
			return addr, nil, nil
		}
	}

	return 0, nil, fmt.Errorf("failed to find symbol %s", symbol)
}

// FindSymbol returns symbol from the addr2symbol map for a given virtual address
func (f *File) FindSymbol(addr uint64, shouldDemangle bool) string {
	if symName, ok := f.AddressToSymbol[addr]; ok {
		if shouldDemangle {
			return demangle.Do(symName, false, false)
		}
		return symName
	}

	return ""
}

// IsCString returns cstring at given virtual address if is in a CstringLiterals section
func (f *File) IsCString(m *macho.File, addr uint64) (string, error) {
	for _, sec := range m.Sections {
		if sec.Flags.IsCstringLiterals() {
			if sec.Addr <= addr && addr < sec.Addr+sec.Size {
				return f.GetCString(addr)
			}
		}
	}
	return "", fmt.Errorf("not a cstring address")
}

// AnalyzeImage analyzes an image by parsing it's symbols, stubs and GOT
func (f *File) AnalyzeImage(image *CacheImage) error {

	if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
		log.Errorf("failed to parse exported symbols for %s", image.Name)
	}

	if err := f.GetLocalSymbolsForImage(image); err != nil {
		if !errors.Is(err, ErrNoLocals) {
			return err
		}
	}

	if !f.IsArm64() {
		utils.Indent(log.Warn, 2)("image analysis of stubs and GOT only works on arm64 architectures")
	}

	if !image.Analysis.State.IsStubsDone() && f.IsArm64() {
		log.Debugf("parsing %s symbol stubs", image.Name)
		if err := f.ParseSymbolStubs(image); err != nil {
			return err
		}

		for stub, target := range image.Analysis.SymbolStubs {
			if symName, ok := f.AddressToSymbol[target]; ok {
				f.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
			} else {
				img, err := f.GetImageContainingTextAddr(target)
				if err != nil {
					return err
				}
				if err := f.AnalyzeImage(img); err != nil {
					return err
				}
				if symName, ok := f.AddressToSymbol[target]; ok {
					f.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
				} else {
					f.AddressToSymbol[stub] = fmt.Sprintf("__stub_%x ; %s", target, filepath.Base(img.Name))
					log.Errorf("no sym found for __stub: %#x; found in %s", stub, img.Name)
				}
			}
		}
	}

	if !image.Analysis.State.IsGotDone() && f.IsArm64() {
		log.Debugf("parsing %s global offset table", image.Name)
		if err := f.ParseGOT(image); err != nil {
			return err
		}

		for entry, target := range image.Analysis.GotPointers {
			if symName, ok := f.AddressToSymbol[target]; ok {
				f.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
			} else {
				if img, err := f.GetImageContainingTextAddr(target); err == nil {
					if err := f.AnalyzeImage(img); err != nil {
						return err
					}
					if symName, ok := f.AddressToSymbol[target]; ok {
						f.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
					} else {
						// log.Errorf("no sym found for __got: %#x; found in %s", entry, img.Name)
						f.AddressToSymbol[entry] = fmt.Sprintf("__got_%x ; %s", target, filepath.Base(img.Name))
					}
				} else {
					f.AddressToSymbol[entry] = fmt.Sprintf("__got_%x", target)
				}

			}
		}
	}

	return nil
}

// ParseSymbolStubs parse symbol stubs in MachO
func (f *File) ParseSymbolStubs(image *CacheImage) error {

	m, err := image.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", image.Name, err)
	}
	defer m.Close()

	image.Analysis.SymbolStubs = make(map[uint64]uint64)

	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {

			var adrpImm uint64
			var adrpAddr uint64
			var prevInst arm64.Instruction

			uuid, offset, err := f.GetOffset(sec.Addr)
			if err != nil {
				return err
			}

			r := io.NewSectionReader(f.r[uuid], int64(offset), int64(sec.Size))

			for i := range arm64.Disassemble(r, arm64.Options{StartAddress: int64(sec.Addr)}) {
				if i.Instruction.Operation() == arm64.ARM64_ADD && prevInst.Operation() == arm64.ARM64_ADRP {
					if i.Instruction.Operands() != nil && prevInst.Operands() != nil {
						// adrp      	x17, #0x1e3be9000
						adrpRegister := prevInst.Operands()[0].Reg[0] // x17
						adrpImm = prevInst.Operands()[1].Immediate    // #0x1e3be9000
						// add       	x17, x17, #0x1c0
						if adrpRegister == i.Instruction.Operands()[0].Reg[0] {
							adrpImm += i.Instruction.Operands()[2].Immediate
							adrpAddr = prevInst.Address()
						}
					}
				} else if i.Instruction.Operation() == arm64.ARM64_LDR && prevInst.Operation() == arm64.ARM64_ADD {
					// add       	x17, x17, #0x1c0
					addRegister := prevInst.Operands()[0].Reg[0] // x17
					// ldr       	x16, [x17]
					if addRegister == i.Instruction.Operands()[1].Reg[0] {
						addr, err := f.ReadPointerAtAddress(adrpImm)
						if err != nil {
							return fmt.Errorf("failed to read pointer at %#x: %v", adrpImm, err)
						}
						image.Analysis.SymbolStubs[adrpAddr] = f.SlideInfo.SlidePointer(addr)
					}
				} else if i.Instruction.Operation() == arm64.ARM64_BR && prevInst.Operation() == arm64.ARM64_ADD {
					// add       	x16, x16, #0x828
					addRegister := prevInst.Operands()[0].Reg[0] // x16
					// br        	x16
					if addRegister == i.Instruction.Operands()[0].Reg[0] {
						image.Analysis.SymbolStubs[adrpAddr] = adrpImm
					}
				}

				// fmt.Printf("%#08x:  %s\t%-10v%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), i.Instruction.OpStr())
				prevInst = *i.Instruction
			}
		}
	}

	image.Analysis.State.SetStubs(true)

	return nil
}

// ParseGOT parse global offset table in MachO
func (f *File) ParseGOT(image *CacheImage) error {

	m, err := image.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", image.Name, err)
	}
	defer m.Close()

	image.Analysis.GotPointers = make(map[uint64]uint64)

	if authPtr := m.Section("__AUTH_CONST", "__auth_ptr"); authPtr != nil {
		dat, err := authPtr.Data()
		if err != nil {
			return fmt.Errorf("failed to get %s.%s section data: %v", authPtr.Seg, authPtr.Name, err)
		}

		ptrs := make([]uint64, authPtr.Size/8)
		if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
			return fmt.Errorf("failed to read __AUTH_CONST.__auth_ptr ptrs; %v", err)
		}

		for idx, ptr := range ptrs {
			image.Analysis.GotPointers[authPtr.Addr+uint64(idx*8)] = f.SlideInfo.SlidePointer(ptr)
		}
	}

	for _, sec := range m.Sections {
		if sec.Flags.IsNonLazySymbolPointers() || sec.Flags.IsLazySymbolPointers() { // TODO: make sure this doesn't break things
			dat, err := sec.Data()
			if err != nil {
				return fmt.Errorf("failed to get %s.%s section data: %v", sec.Seg, sec.Name, err)
			}

			ptrs := make([]uint64, sec.Size/8)
			if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
				return fmt.Errorf("failed to read %s.%s NonLazySymbol pointers; %v", sec.Seg, sec.Name, err)
			}

			for idx, ptr := range ptrs {
				image.Analysis.GotPointers[sec.Addr+uint64(idx*8)] = f.SlideInfo.SlidePointer(ptr)
			}
		}
	}

	image.Analysis.State.SetGot(true)

	return nil
}
