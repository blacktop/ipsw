package dyld

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
)

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

func (f *File) FunctionSize(funcs []types.Function, addr uint64) int64 {
	i := sort.Search(len(funcs), func(i int) bool { return funcs[i].StartAddr >= addr })
	if i+1 == len(funcs) && funcs[i].StartAddr == addr {
		return -1
	} else if i < len(funcs) && funcs[i].StartAddr == addr {
		return int64(funcs[i+1].StartAddr - addr)
	}
	return 0
}

// IsFunctionStart checks if address is at a function start and returns symbol name
func (f *File) IsFunctionStart(funcs []types.Function, addr uint64, shouldDemangle bool) (bool, string) {
	if f.FunctionSize(funcs, addr) != 0 {
		if symName, ok := f.AddressToSymbol[addr]; ok {
			if shouldDemangle {
				return ok, demangle.Do(symName)
			}
			return ok, symName
		}
		return true, ""
	}
	return false, ""
}

// FindSymbol returns symbol from the addr2symbol map for a given virtual address
func (f *File) FindSymbol(addr uint64, shouldDemangle bool) string {
	if symName, ok := f.AddressToSymbol[addr]; ok {
		if shouldDemangle {
			return demangle.Do(symName)
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

// ParseSymbolStubs parse symbol stubs in MachO
func (f *File) ParseSymbolStubs(m *macho.File) error {
	var targetValue uint64

	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {

			r := io.NewSectionReader(f.r, int64(sec.Offset), int64(sec.Size))

			var prevInstruction arm64.Instruction
			for i := range arm64.Disassemble(r, arm64.Options{StartAddress: int64(sec.Addr)}) {
				// TODO: remove duplicate code (refactor into IL)
				operation := i.Instruction.Operation().String()
				if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
					operands := i.Instruction.Operands()
					if operands != nil && prevInstruction.Operands() != nil {
						adrpRegister := prevInstruction.Operands()[0].Reg[0]
						adrpImm := prevInstruction.Operands()[1].Immediate
						if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
							adrpImm += operands[1].Immediate
						} else if operation == "add" && adrpRegister == operands[0].Reg[0] {
							adrpImm += operands[2].Immediate
						}

						addr, err := f.ReadPointerAtAddress(adrpImm)
						if err != nil {
							return err
						}

						targetValue = convertToVMAddr(addr)

						// fmt.Printf("%#x: %#x => %s\n", adrpImm, targetValue, f.AddressToSymbol[targetValue])
						if symName, ok := f.AddressToSymbol[targetValue]; ok {
							f.AddressToSymbol[prevInstruction.Address()] = symName
						}
					}
				}
				// fmt.Printf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), i.Instruction.OpStr())
				prevInstruction = *i.Instruction
			}
		}
	}

	return nil
}

// ParseGOT parse global offset table in MachO
func (f *File) ParseGOT(m *macho.File) error {

	authPtr := m.Section("__AUTH_CONST", "__auth_ptr")
	if authPtr != nil {
		r := io.NewSectionReader(f.r, int64(authPtr.Offset), int64(authPtr.Size))
		ptrs := make([]uint64, authPtr.Size/8)
		if err := binary.Read(r, binary.LittleEndian, &ptrs); err != nil {
			return err
		}

		var targetValue uint64
		for idx, ptr := range ptrs {
			targetValue = convertToVMAddr(ptr)
			// fmt.Printf("%#x: %#x => %s\n", authPtr.Addr+uint64(idx*8), targetValue, f.AddressToSymbol[targetValue])
			if symName, ok := f.AddressToSymbol[targetValue]; ok {
				f.AddressToSymbol[authPtr.Addr+uint64(idx*8)] = symName
			}
		}
	}

	for _, sec := range m.Sections {
		if sec.Flags.IsNonLazySymbolPointers() {

			r := io.NewSectionReader(f.r, int64(sec.Offset), int64(sec.Size))

			ptrs := make([]uint64, sec.Size/8)

			if err := binary.Read(r, binary.LittleEndian, &ptrs); err != nil {
				return err
			}
			// imports, err := m.ImportedSymbolNames()
			// if err != nil {
			// 	return err
			// }
			// for name := range imports {
			// 	fmt.Println(name)
			// }
			for idx, ptr := range ptrs {
				gotPtr := sec.Addr + uint64(idx*8)
				// fmt.Printf("gotPtr: %#x\n", gotPtr)
				targetValue := convertToVMAddr(ptr)
				// fmt.Printf("ptr: %#x\n", ptr)
				// fmt.Printf("newPtr: %#x, %s\n", targetValue, symbolMap[targetValue])
				// fmt.Println(lookupSymbol(m, targetValue))
				if _, ok := f.AddressToSymbol[gotPtr]; ok {
					// continue
					f.AddressToSymbol[gotPtr] = "__got." + f.AddressToSymbol[gotPtr]
				} else {
					if _, ok := f.AddressToSymbol[targetValue]; ok {
						f.AddressToSymbol[gotPtr] = "__got." + f.AddressToSymbol[targetValue]
					} else {
						f.AddressToSymbol[gotPtr] = fmt.Sprintf("__got_ptr_%#x", targetValue)
					}
				}
			}
		}
	}

	return nil
}
