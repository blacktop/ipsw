/*
Copyright © 2019 blacktop

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
	"math"
	"os"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(machoCmd)

	machoCmd.Flags().BoolP("header", "d", false, "Print the mach header")
	machoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	machoCmd.Flags().BoolP("sig", "s", false, "Print code signature")
	machoCmd.Flags().BoolP("ent", "e", false, "Print entitlements")
	machoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	machoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	machoCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoCmd represents the macho command
var machoCmd = &cobra.Command{
	Use:   "macho <macho_file>",
	Short: "Parse a MachO file",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		showHeader, _ := cmd.Flags().GetBool("header")
		showLoadCommands, _ := cmd.Flags().GetBool("loads")
		showSignature, _ := cmd.Flags().GetBool("sig")
		showEntitlements, _ := cmd.Flags().GetBool("ent")
		showObjC, _ := cmd.Flags().GetBool("objc")
		symbols, _ := cmd.Flags().GetBool("symbols")

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return err
		}

		if showHeader && !showLoadCommands {
			fmt.Println(m.FileHeader.String())
		}
		if showLoadCommands || (!showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC) {
			fmt.Println(m.FileTOC.String())
		}

		if showSignature {
			if m.CodeSignature() != nil {
				cd := m.CodeSignature().CodeDirectory
				fmt.Println("Code Signature")
				fmt.Println("==============")
				fmt.Printf("Code Directory (%d bytes)\n", cd.Length)
				fmt.Printf("\tVersion:     %x\n"+
					"\tFlags:       0x%x\n"+
					"\tCodeLimit:   0x%x\n"+
					"\tIdentifier:  %s (@0x%x)\n"+
					"\t# of hashes: %d code (%d pages) + %d special\n"+
					"\tHashes @%d size: %d Type: %s\n",
					cd.Version,
					cd.Flags,
					cd.CodeLimit,
					m.CodeSignature().ID,
					cd.IdentOffset,
					cd.NCodeSlots,
					int(math.Pow(2, float64(cd.PageSize))),
					cd.NSpecialSlots,
					cd.HashOffset,
					cd.HashSize,
					cd.HashType)
				if len(m.CodeSignature().Requirements) > 0 {
					fmt.Printf("Requirement Set (%d bytes) with %d requirement\n",
						m.CodeSignature().Requirements[0].Length,
						len(m.CodeSignature().Requirements))
					for _, req := range m.CodeSignature().Requirements {
						fmt.Printf("\t%s (@%d, %d bytes): %s\n",
							req.Type,
							req.Offset,
							req.Length,
							req.Detail)
					}
				}
			} else {
				fmt.Println("Code Signature")
				fmt.Println("==============")
				fmt.Println("  - no code signature data")
			}
		}

		if showEntitlements {
			if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
				fmt.Println("Entitlements")
				fmt.Println("============")
				fmt.Println(m.CodeSignature().Entitlements)
			} else {
				fmt.Println("ENTITLEMENTS")
				fmt.Println("============")
				fmt.Println("  - no entitlements")
			}
		}

		if showObjC {
			if m.HasObjC() {
				fmt.Println("Objective-C")
				fmt.Println("===========")
				// fmt.Println("HasPlusLoadMethod: ", m.HasPlusLoadMethod())
				// fmt.Printf("GetObjCInfo: %#v\n", m.GetObjCInfo())

				// info, _ := m.GetObjCImageInfo()
				// fmt.Println(info.Flags)
				// fmt.Println(info.Flags.SwiftVersion())

				if protos, err := m.GetObjCProtocols(); err == nil {
					for _, proto := range protos {
						fmt.Println(proto.String())
					}
				}
				if classes, err := m.GetObjCClasses(); err == nil {
					for _, class := range classes {
						fmt.Println(class.String())
					}
				}
				if nlclasses, err := m.GetObjCPlusLoadClasses(); err == nil {
					for _, class := range nlclasses {
						fmt.Println(class.String())
					}
				}
				if cats, err := m.GetObjCCategories(); err == nil {
					fmt.Printf("Categories: %#v\n", cats)
				}
				if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
					fmt.Println("@selectors")
					for vmaddr, name := range selRefs {
						fmt.Printf("0x%011x: %s\n", vmaddr, name)
					}
				}
				if methods, err := m.GetObjCMethodNames(); err == nil {
					fmt.Printf("\n@methods\n")
					for method, vmaddr := range methods {
						fmt.Printf("0x%011x: %s\n", vmaddr, method)
					}
				}
			} else {
				fmt.Println("Objective-C")
				fmt.Println("===========")
				fmt.Println("  - no objc")
			}
		}

		// fmt.Println("HEADER")
		// fmt.Println("======")
		// fmt.Println(m.FileHeader)

		// fmt.Println("SECTIONS")
		// fmt.Println("========")
		// var secFlags string
		// // var prevSeg string
		// w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		// for _, sec := range m.Sections {
		// 	secFlags = ""
		// 	if !sec.Flags.IsRegular() {
		// 		secFlags = fmt.Sprintf("(%s)", sec.Flags)
		// 	}
		// 	// if !strings.EqualFold(sec.Seg, prevSeg) && len(prevSeg) > 0 {
		// 	// 	fmt.Fprintf(w, "\n")
		// 	// }
		// 	fmt.Fprintf(w, "Mem: 0x%x-0x%x \t Off: 0x%x-0x%x \t %s.%s \t %s \t %s\n", sec.Addr, sec.Addr+sec.Size, sec.Offset, uint64(sec.Offset)+sec.Size, sec.Seg, sec.Name, secFlags, sec.Flags.AttributesString())
		// 	// prevSeg = sec.Seg
		// }
		// w.Flush()

		// if m.DylibID() != nil {
		// 	fmt.Printf("Dyld ID: %s (%s)\n", m.DylibID().Name, m.DylibID().CurrentVersion)
		// }
		// if m.SourceVersion() != nil {
		// 	fmt.Println("SourceVersion:", m.SourceVersion().Version)
		// }

		if symbols {
			fmt.Println("SYMBOLS")
			fmt.Println("=======")
			var sec string
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
			for _, sym := range m.Symtab.Syms {
				if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
					sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
				}
				fmt.Fprintf(w, "0x%016X \t <%s> \t %s\n", sym.Value, sym.Type.String(sec), sym.Name)
				// fmt.Printf("0x%016X <%s> %s\n", sym.Value, sym.Type.String(sec), sym.Name)
			}
			w.Flush()
		}
		return nil
	},
}
