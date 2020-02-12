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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var imageName string

func init() {
	dyldCmd.AddCommand(symaddrCmd)

	symaddrCmd.Flags().StringVarP(&imageName, "image", "i", "", "dylib image to search")
	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// symaddrCmd represents the symaddr command
var symaddrCmd = &cobra.Command{
	Use:   "symaddr",
	Short: "Find exported symbol",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

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
			if len(imageName) > 0 { // Search for symbol inside dylib
				if sym, _ := f.GetExportedSymbolAddressInImage(imageName, args[1]); sym != nil {
					fmt.Println(sym)
					// return nil
				}
				if lSym, _ := f.FindLocalSymbolInImage(args[1], imageName); lSym != nil {
					fmt.Println(lSym)
				}
				return nil
			}
			// Search ALL dylibs for a symbol
			found := false
			for _, image := range f.Images {
				if sym, _ := f.GetExportedSymbolAddressInImage(image.Name, args[1]); sym != nil {
					fmt.Println(sym)
					found = true
				}
			}
			if !found {
				if lSym, _ := f.FindLocalSymbol(args[1]); lSym != nil {
					fmt.Println(lSym)
				}
			}
		} else { // Dump ALL symbols
			err := f.GetAllExportedSymbols()
			if err != nil {
				return errors.Wrap(err, "failed to get all exported symbols")
			}
			log.Warn("parsing local symbols...")
			err = f.ParseLocalSyms()
			if err != nil {
				return errors.Wrap(err, "failed to parse private symbols")
			}
			for _, image := range f.Images {
				fmt.Printf("\n%s\n", image.Name)
				for _, sym := range image.LocalSymbols {
					fmt.Printf("0x%8x: %s\n", sym.Value, sym.Name)
				}
			}
		}

		// if false {
		// 	index, found, err := f.HasImagePath("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore")
		// 	if err != nil {
		// 		return err
		// 	}
		// 	if found {
		// 		fmt.Println("index:", index, "image:", f.Images[index].Name)
		// 	}
		// 	// err = f.FindClosure("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore")
		// 	// if err != nil {
		// 	// 	return err
		// 	// }
		// 	err = f.FindDlopenOtherImage("/Applications/FindMy.app/Frameworks/FMSiriIntents.framework/FMSiriIntents")
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		return nil
	},
}
