/*
Copyright © 2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package macho

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/symbols"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoA2sCmd)
	machoA2sCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	viper.BindPFlag("macho.a2s.arch", machoA2sCmd.Flags().Lookup("arch"))
}

// findNearestSymbol searches for the closest symbol at or before addr.
// It returns the symbol name, symbol address, and whether one was found.
func findNearestSymbol(m *macho.File, addr uint64) (name string, symAddr uint64, found bool) {
	type entry struct {
		addr uint64
		name string
	}
	var entries []entry

	// collect from symtab
	if m.Symtab != nil {
		for _, sym := range m.Symtab.Syms {
			if sym.Value != 0 && !sym.Type.IsDebugSym() {
				entries = append(entries, entry{addr: sym.Value, name: sym.Name})
			}
		}
	}

	// collect from export trie
	if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
		if exports, err := m.DyldExports(); err == nil {
			for _, exp := range exports {
				entries = append(entries, entry{addr: exp.Address, name: exp.Name})
			}
		}
	}

	if len(entries) == 0 {
		return "", 0, false
	}

	// sort by address
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].addr < entries[j].addr
	})

	// binary search for the nearest symbol at or before addr
	idx := sort.Search(len(entries), func(i int) bool {
		return entries[i].addr > addr
	})
	if idx == 0 {
		return "", 0, false
	}
	best := entries[idx-1]
	return best.name, best.addr, true
}

// resolveGOTEntry resolves an address in a GOT, stub, or symbol-pointer section
// to the name of the imported symbol it references. It tries three methods:
//  1. Indirect symbol table (LC_DYSYMTAB)
//  2. Chained fixups / dyld info bind name
//  3. LC_DYLD_INFO bind table address matching
func resolveGOTEntry(m *macho.File, addr uint64, sec *types.Section) (string, bool) {
	secType := sec.Flags & types.SectionType
	if secType != types.NonLazySymbolPointers &&
		secType != types.LazySymbolPointers &&
		secType != types.SymbolStubs &&
		secType != types.LazyDylibSymbolPointers {
		return "", false
	}

	// Method 1: indirect symbol table
	if m.Dysymtab != nil && m.Symtab != nil {
		var entrySize uint64
		switch secType {
		case types.SymbolStubs:
			entrySize = uint64(sec.Reserved2)
		default: // symbol pointer sections
			entrySize = 8
			if m.FileTOC.FileHeader.Magic != types.Magic64 {
				entrySize = 4
			}
		}
		if entrySize > 0 && addr >= sec.Addr && addr < sec.Addr+sec.Size {
			entryIdx := (addr - sec.Addr) / entrySize
			indIdx := sec.Reserved1 + uint32(entryIdx)
			if int(indIdx) < len(m.Dysymtab.IndirectSyms) {
				symIdx := m.Dysymtab.IndirectSyms[indIdx]
				// skip sentinel values for stripped/absolute symbols
				if symIdx&types.INDIRECT_SYMBOL_LOCAL != 0 || symIdx&types.INDIRECT_SYMBOL_ABS != 0 {
					// fall through to other resolution methods
				} else if int(symIdx) < len(m.Symtab.Syms) {
					return m.Symtab.Syms[symIdx].Name, true
				}
			}
		}
	}

	// Method 2: chained fixups — read raw pointer at address, resolve via GetBindName
	if m.HasFixups() {
		if ptr, err := m.GetPointerAtAddress(addr); err == nil {
			if name, err := m.GetBindName(ptr); err == nil {
				return name, true
			}
		}
	}

	// Method 3: LC_DYLD_INFO bind info — match by address
	if binds, err := m.GetBindInfo(); err == nil {
		for _, bind := range binds {
			if (bind.Start + bind.SegOffset) == addr {
				return bind.Name, true
			}
		}
	}

	return "", false
}

// resolveObjCMetadata resolves an address within an ObjC metadata section
// to a human-readable name (e.g., class name, selector, protocol).
func resolveObjCMetadata(m *macho.File, addr uint64, sec *types.Section) (string, bool) {
	if !m.HasObjC() {
		return "", false
	}
	switch sec.Name {
	case "__objc_data":
		// address is at a class struct (ObjcClass64 / SwiftClassMetadata64)
		if cls, err := m.GetObjCClass2(addr); err == nil {
			return "_OBJC_CLASS_$_" + cls.Name, true
		}
	case "__objc_classrefs":
		if refs, err := m.GetObjCClassReferences(); err == nil {
			if cls, ok := refs[addr]; ok {
				return "_OBJC_CLASS_$_" + cls.Name, true
			}
		}
	case "__objc_selrefs":
		if refs, err := m.GetObjCSelectorReferences(); err == nil {
			if sel, ok := refs[addr]; ok {
				return "@selector(" + sel.Name + ")", true
			}
		}
	case "__objc_superrefs":
		if refs, err := m.GetObjCSuperReferences(); err == nil {
			if cls, ok := refs[addr]; ok {
				return "_OBJC_CLASS_$_" + cls.Name, true
			}
		}
	case "__objc_protolist", "__objc_protorefs":
		if refs, err := m.GetObjCProtoReferences(); err == nil {
			if proto, ok := refs[addr]; ok {
				return "_OBJC_PROTOCOL_$_" + proto.Name, true
			}
		}
	case "__cfstring":
		if cfstrings, err := m.GetCFStrings(); err == nil {
			for _, cfs := range cfstrings {
				if cfs.Address == addr {
					return fmt.Sprintf("@%#v", cfs.Name), true
				}
			}
		}
	}
	return "", false
}

// machoA2sCmd represents the a2s command
var machoA2sCmd = &cobra.Command{
	Use:           "a2s",
	Short:         "Lookup symbol at unslid address",
	Args:          cobra.ExactArgs(2),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		// flags
		selectedArch := viper.GetString("macho.a2s.arch")

		secondAttempt := false

		machoPath := filepath.Clean(args[0])

		if ok, err := magic.IsMachO(machoPath); !ok {
			return err
		}

		// Use the helper to handle fat/universal files
		mr, err := mcmd.OpenMachO(machoPath, selectedArch)
		if err != nil {
			return err
		}
		defer mr.Close()
		m = mr.File

		addr, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
		}

	retry:
		if m.FileTOC.FileHeader.Type == types.MH_FILESET {
			s2a := make(map[uint64]string)

			for _, fse := range m.FileSets() {
				mfse, err := m.GetFileSetFileByName(fse.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse kext %s: %v", fse.EntryID, err)
				}
				if s := mfse.FindSegmentForVMAddr(addr); s != nil {
					if s.Nsect > 0 {
						if c := mfse.FindSectionForVMAddr(addr); c != nil {
							log.WithFields(log.Fields{"entry": fse.EntryID, "section": fmt.Sprintf("%s.%s", c.Seg, c.Name)}).Info("Address location")
						}
					} else {
						log.WithFields(log.Fields{"entry": fse.EntryID, "segment": s.Name}).Info("Address location")
					}
				}
				// build symbol map
				if mfse.Symtab != nil {
					for _, sym := range mfse.Symtab.Syms {
						s2a[sym.Value] = sym.Name
					}
				}
				// check if it's a cstring
				if cstr, ok := mfse.IsCString(addr); ok {
					if secondAttempt {
						fmt.Printf("\n%#x: %s%#v\n", addr, symbols.PrefixPointer, cstr)
					} else {
						fmt.Printf("\n%#x: %#v\n", addr, cstr)
					}
					return nil
				}
			}
			// search for symbols
			if sym, ok := s2a[addr]; ok {
				fmt.Printf("\n%#x: %s\n", addr, sym)
				return nil
			}

		} else {
			// check if it's a cstring
			if cstr, ok := m.IsCString(addr); ok {
				if secondAttempt {
					fmt.Printf("\n%#x: %s%#v\n", addr, symbols.PrefixPointer, cstr)
				} else {
					fmt.Printf("\n%#x: %#v\n", addr, cstr)
				}
				return nil
			}
			// search for exact symbol match
			syms, err := m.FindAddressSymbols(addr)
			if err == nil {
				for _, sym := range syms {
					if secondAttempt {
						sym.Name = symbols.PrefixPointer + sym.Name
					}
					fmt.Printf("\n%#x: %s\n", addr, sym.Name)
				}
				return nil
			}

			// --- fallback: no exact symbol found ---

			// find segment/section for the address
			var sec *types.Section
			if seg := m.FindSegmentForVMAddr(addr); seg != nil {
				sec = m.FindSectionForVMAddr(addr)
				if sec != nil {
					log.WithFields(log.Fields{"section": fmt.Sprintf("%s.%s", sec.Seg, sec.Name)}).Info("Address location")
				} else {
					log.WithFields(log.Fields{"segment": seg.Name}).Info("Address location")
				}
			}

			// try to resolve GOT/stub/symbol-pointer entries
			if sec != nil {
				if name, ok := resolveGOTEntry(m, addr, sec); ok {
					if secondAttempt {
						name = symbols.PrefixPointer + name
					}
					fmt.Printf("\n%#x: %s\n", addr, name)
					return nil
				}
			}

			// try to resolve ObjC metadata (classes, selectors, protocols, etc.)
			if sec != nil {
				if name, ok := resolveObjCMetadata(m, addr, sec); ok {
					if secondAttempt {
						name = symbols.PrefixPointer + name
					}
					fmt.Printf("\n%#x: %s\n", addr, name)
					return nil
				}
			}

			// try to find the nearest symbol
			if name, symAddr, ok := findNearestSymbol(m, addr); ok {
				offset := addr - symAddr
				if secondAttempt {
					name = symbols.PrefixPointer + name
				}
				if offset == 0 {
					fmt.Printf("\n%#x: %s\n", addr, name)
				} else {
					fmt.Printf("\n%#x: %s + %d\n", addr, name, offset)
				}
			}
			// also try to find the containing function via LC_FUNCTION_STARTS
			if fn, err := m.GetFunctionForVMAddr(addr); err == nil {
				fnOffset := addr - fn.StartAddr
				// try to name the function
				fnName := ""
				if exactSyms, err := m.FindAddressSymbols(fn.StartAddr); err == nil && len(exactSyms) > 0 {
					fnName = exactSyms[0].Name
				}
				if fnName != "" {
					if fnOffset == 0 {
						fmt.Printf("   func: %s (start: %#x, end: %#x)\n", fnName, fn.StartAddr, fn.EndAddr)
					} else {
						fmt.Printf("   func: %s + %d (start: %#x, end: %#x)\n", fnName, fnOffset, fn.StartAddr, fn.EndAddr)
					}
				} else {
					fmt.Printf("   func: func_%x + %d (start: %#x, end: %#x)\n", fn.StartAddr, fnOffset, fn.StartAddr, fn.EndAddr)
				}
			}
			return nil
		}

		if secondAttempt {
			log.Error("no symbol found")
			return nil
		}

		ptr, err := m.GetPointerAtAddress(addr)
		if err != nil {
			return err
		}

		utils.Indent(log.Error, 2)(fmt.Sprintf("no symbol found (trying again with %#x as a pointer to %#x)", addr, m.SlidePointer(ptr)))

		addr = m.SlidePointer(ptr)

		secondAttempt = true

		goto retry
	},
}
