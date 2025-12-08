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
		selectedArch := viper.GetString("macho.a2o.arch")

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
				for _, sym := range mfse.Symtab.Syms {
					s2a[sym.Value] = sym.Name
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
			// search for symbols
			syms, err := m.FindAddressSymbols(addr)
			if err != nil {
				return err
			}
			for _, sym := range syms {
				if secondAttempt {
					sym.Name = symbols.PrefixPointer + sym.Name
				}
				fmt.Printf("\n%#x: %s\n", addr, sym.Name)
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
