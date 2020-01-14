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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
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
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		f, err := dyld.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()

		// err = f.GetAllExportedSymbols()
		// if err != nil {
		// 	return err
		// }

		if len(imageName) > 0 {
			sym, err := f.GetExportedSymbolAddressInImage(imageName, args[1])
			// if err != nil {
			// 	return err
			// }
			if sym != nil {
				fmt.Println(sym)
			} else {
				err = f.GetLocalSymbolsForImage(imageName)
				if err != nil {
					return err
				}
				lSym := f.GetLocalSymbolInImage(imageName, args[1])
				if lSym != nil {
					fmt.Println(lSym)
					return nil
				}
				return fmt.Errorf("symbol not found")
			}
		}

		if false {
			index, found, err := f.HasImagePath("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore")
			if err != nil {
				return err
			}
			if found {
				fmt.Println("index:", index, "image:", f.Images[index].Name)
			}
			// err = f.FindClosure("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore")
			// if err != nil {
			// 	return err
			// }
			err = f.FindDlopenOtherImage("/Applications/FindMy.app/Frameworks/FMSiriIntents.framework/FMSiriIntents")
			if err != nil {
				return err
			}
		}

		sym, err := f.GetExportedSymbolAddress(args[1])
		// if err != nil {
		// 	return err
		// }
		if sym != nil {
			fmt.Println(sym)
		} else {
			log.Warn("symbol not found in exports (fast)")
			log.Info("searching private symbols (slow)...")
			err = f.ParseLocalSyms()
			if err != nil {
				return err
			}

			lSym := f.GetLocalSymbol(args[1])
			if lSym == nil {
				return fmt.Errorf("symbol not found in private symbols")
			}
			fmt.Println(lSym)
		}
		return nil
	},
}
