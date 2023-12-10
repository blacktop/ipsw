/*
Copyright © 2023 blacktop

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
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(swiftDumpCmd)

	swiftDumpCmd.Flags().Bool("demangle", false, "Demangle symbol names")
	// swiftDumpCmd.Flags().StringP("class", "c", "", "Dump class")
	// swiftDumpCmd.Flags().StringP("proto", "p", "", "Dump protocol")
	// swiftDumpCmd.Flags().StringP("cat", "t", "", "Dump category")
	viper.BindPFlag("swift-dump.demangle", swiftDumpCmd.Flags().Lookup("demangle"))
	// viper.BindPFlag("swift-dump.class", swiftDumpCmd.Flags().Lookup("class"))
	// viper.BindPFlag("swift-dump.proto", swiftDumpCmd.Flags().Lookup("proto"))
	// viper.BindPFlag("swift-dump.cat", swiftDumpCmd.Flags().Lookup("cat"))
	// swiftDumpCmd.MarkFlagsMutuallyExclusive("class", "proto", "cat")
}

// swiftDumpCmd represents the swiftDump command
var swiftDumpCmd = &cobra.Command{
	Use:     "swift-dump [<DSC> <DYLIB>|<MACHO>]",
	Aliases: []string{"sd"},
	Short:   "Swift class-dump a dylib from a DSC or MachO",
	Args:    cobra.MinimumNArgs(1),
	Hidden:  true,
	// ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// 	if len(args) == 1 {
	// 		return getImages(args[0]), cobra.ShellCompDirectiveDefault
	// 	}
	// 	return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	// },
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		// var header, footer string

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		doDemangle := viper.GetBool("swift-dump.demangle")
		// dumpClass := viper.GetString("swift-dump.class")
		// dumpProto := viper.GetString("swift-dump.proto")
		// dumpCat := viper.GetString("swift-dump.cat")

		if ok, _ := magic.IsMachO(args[0]); ok {
			m, err := macho.Open(args[0])
			if err != nil {
				return err
			}
			defer m.Close()
		} else {
			f, err := dyld.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()

			image, err := f.Image(args[1])
			if err != nil {
				return err
			}

			m, err = image.GetMacho()
			if err != nil {
				return err
			}

			image.ParseLocalSymbols(false) // parse local symbols for swift demangling
			if m.Symtab != nil {
				for idx, sym := range m.Symtab.Syms {
					if sym.Value != 0 {
						if sym.Name == "<redacted>" {
							if name, ok := f.AddressToSymbol[sym.Value]; ok {
								m.Symtab.Syms[idx].Name = name
							}
						}
					}
					if doDemangle {
						if strings.HasPrefix(sym.Name, "_$s") || strings.HasPrefix(sym.Name, "$s") {
							m.Symtab.Syms[idx].Name, _ = swift.Demangle(sym.Name)
						} else if strings.HasPrefix(sym.Name, "__Z") || strings.HasPrefix(sym.Name, "_Z") {
							m.Symtab.Syms[idx].Name = demangle.Do(sym.Name, false, false)
						}
					}
				}
			}
		}

		if m.HasSwift() {
			toc := m.GetSwiftTOC()
			if err := m.PreCache(); err != nil { // cache fields and types
				log.Errorf("failed to precache swift fields/types: %v", err)
			}
			var sout string
			if typs, err := m.GetSwiftTypes(); err == nil {
				if Verbose {
					if Color {
						quick.Highlight(os.Stdout, "/********\n* TYPES *\n********/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println("TYPES")
						fmt.Print("-----\n\n")
					}
				}
				for i, typ := range typs {
					if Verbose {
						sout = typ.Verbose()
						if doDemangle {
							sout = swift.DemangleBlob(sout)
						}
					} else {
						sout = typ.String()
						if doDemangle {
							sout = swift.DemangleSimpleBlob(typ.String())
						}
					}
					if Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
						if i < (toc.Types-1) && (toc.Protocols > 0 || toc.ProtocolConformances > 0) { // skip last type if others follow
							quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
						} else {
							fmt.Println()
						}
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift types: %v", err)
			}
			if protos, err := m.GetSwiftProtocols(); err == nil {
				if Verbose {
					if Color {
						quick.Highlight(os.Stdout, "/************\n* PROTOCOLS *\n************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println("PROTOCOLS")
						fmt.Print("---------\n\n")
					}
				}
				for i, proto := range protos {
					if Verbose {
						sout = proto.Verbose()
						if doDemangle {
							sout = swift.DemangleBlob(sout)
						}
					} else {
						sout = proto.String()
						if doDemangle {
							sout = swift.DemangleSimpleBlob(proto.String())
						}
					}
					if Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
						if i < (toc.Protocols-1) && toc.ProtocolConformances > 0 { // skip last type if others follow
							quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
						} else {
							fmt.Println()
						}
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift protocols: %v", err)
			}
			if protos, err := m.GetSwiftProtocolConformances(); err == nil {
				if Verbose {
					if Color {
						quick.Highlight(os.Stdout, "/************************\n* PROTOCOL CONFORMANCES *\n************************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println("PROTOCOL CONFORMANCES")
						fmt.Print("---------------------\n\n")
					}
				}
				for i, proto := range protos {
					if Verbose {
						sout = proto.Verbose()
						if doDemangle {
							sout = swift.DemangleBlob(sout)
						}
					} else {
						sout = proto.String()
						if doDemangle {
							sout = swift.DemangleSimpleBlob(proto.String())
						}
					}
					if Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
						if i < (toc.ProtocolConformances - 1) { // skip last type if others follow
							quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
						} else {
							fmt.Println()
						}
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift protocol conformances: %v", err)
			}
			if asstyps, err := m.GetSwiftAssociatedTypes(); err == nil {
				if Verbose {
					if Color {
						quick.Highlight(os.Stdout, "/*******************\n* ASSOCIATED TYPES *\n*******************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println("ASSOCIATED TYPES")
						fmt.Print("---------------------\n\n")
					}
				}
				for _, at := range asstyps {
					if Verbose {
						sout = at.Verbose()
						if doDemangle {
							sout = swift.DemangleBlob(sout)
						}
					} else {
						sout = at.String()
						if doDemangle {
							sout = swift.DemangleSimpleBlob(at.String())
						}
					}
					if Color {
						quick.Highlight(os.Stdout, sout+"\n", "swift", "terminal256", "nord")
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "swift", "terminal256", "nord")
					} else {
						fmt.Println(sout + "\n")
					}
				}
			} else if !errors.Is(err, macho.ErrSwiftSectionError) {
				log.Errorf("failed to parse swift associated types: %v", err)
			}
		} else {
			log.Warn("no swift")
		}

		return nil
	},
}
