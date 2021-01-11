/*
Copyright © 2021 blacktop

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

// dyldMachoCmd represents the macho command
var dyldMachoCmd = &cobra.Command{
	Use:   "macho <dyld_shared_cache> <dylib>",
	Short: "Parse a dylib file",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// showObjC, _ := cmd.Flags().GetBool("objc")

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
			if i := f.Image(args[1]); i != nil {
				m, err := i.GetPartialMacho()
				if err != nil {
					return err
				}

				fmt.Println(m.FileTOC.String())

				// if showObjC {
				// 	fmt.Println("Objective-C")
				// 	fmt.Println("===========")
				// 	if m.HasObjC() {
				// 		// fmt.Println("HasPlusLoadMethod: ", m.HasPlusLoadMethod())
				// 		// fmt.Printf("GetObjCInfo: %#v\n", m.GetObjCInfo())

				// 		// info, _ := m.GetObjCImageInfo()
				// 		// fmt.Println(info.Flags)
				// 		// fmt.Println(info.Flags.SwiftVersion())

				// 		if protos, err := m.GetObjCProtocols(); err == nil {
				// 			for _, proto := range protos {
				// 				fmt.Println(proto.String())
				// 			}
				// 		}
				// 		if classes, err := m.GetObjCClasses(); err == nil {
				// 			for _, class := range classes {
				// 				fmt.Println(class.String())
				// 			}
				// 		}
				// 		if nlclasses, err := m.GetObjCPlusLoadClasses(); err == nil {
				// 			for _, class := range nlclasses {
				// 				fmt.Println(class.String())
				// 			}
				// 		}
				// 		if cats, err := m.GetObjCCategories(); err == nil {
				// 			for _, cat := range cats {
				// 				fmt.Println(cat.String())
				// 			}
				// 		}
				// 		if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
				// 			fmt.Println("@selectors refs")
				// 			for off, sel := range selRefs {
				// 				fmt.Printf("0x%011x => 0x%011x: %s\n", off, sel.VMAddr, sel.Name)
				// 			}
				// 		}
				// 		if methods, err := m.GetObjCMethodNames(); err == nil {
				// 			fmt.Printf("\n@methods\n")
				// 			for method, vmaddr := range methods {
				// 				fmt.Printf("0x%011x: %s\n", vmaddr, method)
				// 			}
				// 		}
				// 	} else {
				// 		fmt.Println("  - no objc")
				// 	}
				// 	fmt.Println()
				// }
			} else {
				log.Errorf("dylib %s not found in %s", args[1], dscPath)
			}
		} else {
			log.Error("you must supply a dylib MachO to parse")
		}

		return nil
	},
}

func init() {
	dyldCmd.AddCommand(dyldMachoCmd)

	// dyldMachoCmd.Flags().BoolP("header", "d", false, "Print the mach header")
	// dyldMachoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	// dyldMachoCmd.Flags().BoolP("sig", "s", false, "Print code signature")
	// dyldMachoCmd.Flags().BoolP("ent", "e", false, "Print entitlements")
	dyldMachoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	dyldMachoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	dyldMachoCmd.Flags().BoolP("starts", "f", false, "Print function starts")

	dyldMachoCmd.MarkZshCompPositionalArgumentFile(1)
}
