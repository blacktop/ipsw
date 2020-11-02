/*
Copyright © 2020 blacktop

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
package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDisassCmd)

	// dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	// dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().Uint64P("count", "c", 30, "Number of instructions to disassemble")
	// dyldDisassCmd.Flags().BoolP("demangle", "d", false, "Demandle symbol names")
	dyldDisassCmd.Flags().StringP("sym-file", "s", "", "Companion symbol map file")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")

	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

func functionSize(starts []uint64, addr uint64) int64 {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] >= addr })
	if i+1 == len(starts) && starts[i] == addr {
		return -1
	} else if i < len(starts) && starts[i] == addr {
		return int64(starts[i+1] - addr)
	}
	return 0
}

func functionStart(starts []uint64, addr uint64) {
	if functionSize(starts, addr) != 0 {
		fmt.Printf("\nfunc_%x:\n", addr)
	}
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:    "disass",
	Short:  "🚧 [WIP] Disassemble dyld_shared_cache symbol in an image",
	Hidden: true,
	Args:   cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var image *dyld.CacheImage
		var symAddr uint64

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		instructions, _ := cmd.Flags().GetUint64("count")
		// symbolName, _ := cmd.Flags().GetString("symbol")
		// doDemangle, _ := cmd.Flags().GetBool("demangle")

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		if len(args) > 1 {
			found := false
			if len(imageName) > 0 { // Search for symbol inside dylib
				image = f.Image(imageName)
				if sym, _ := f.FindExportedSymbolInImage(imageName, args[1]); sym != nil {
					symAddr = sym.Address
					found = true
				} else if lSym, _ := f.FindLocalSymbolInImage(args[1], imageName); lSym != nil {
					symAddr = lSym.Value
					found = true
				}
			} else {
				// Search ALL dylibs for a symbol
				for _, img := range f.Images {
					if sym, _ := f.FindExportedSymbolInImage(img.Name, args[1]); sym != nil {
						image = img
						symAddr = sym.Address
						found = true
						break
					}
				}
				if !found {
					if lSym, _ := f.FindLocalSymbol(args[1]); lSym != nil {
						symAddr = lSym.Value
					} else {
						return fmt.Errorf("symbol %s not found", args[1])
					}
				}

				m, err := image.GetPartialMacho()
				if err != nil {
					return err
				}

				var starts []uint64
				if fs := m.FunctionStarts(); fs != nil {
					data, err := f.ReadBytes(int64(fs.Offset), uint64(fs.Size))
					if err != nil {
						return err
					}
					starts = m.FunctionStartAddrs(data...)
				}

				// fmt.Println(m.FileTOC.String())

				if image != nil {
					fmt.Println(image.Name)
				} else {
					if image, err := f.GetImageContainingTextAddr(symAddr); err == nil {
						fmt.Println(image.Name)
					}
				}

				off, _ := f.GetOffset(symAddr)
				data, err := f.ReadBytes(int64(off), instructions*4)
				if err != nil {
					return err
				}

				for i := range arm64.Disassemble(bytes.NewReader(data), arm64.Options{StartAddress: int64(symAddr)}) {

					if i.Error != nil {
						fmt.Println(i.StrRepr)
						continue
					}

					// check for start of a new function
					functionStart(starts, i.Instruction.Address())

					fmt.Printf("%#08x:  %s\t%s%s%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), pad(10-len(i.Instruction.Operation().String())), i.Instruction.OpStr())
				}
			}
		} else {
			return fmt.Errorf("you must supply a cache and a symbol to disassemble")
		}

		return nil
	},
}
