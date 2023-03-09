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
package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var symAddrColor = color.New(color.Faint).SprintfFunc()
var symImageColor = color.New(color.Faint, color.FgBlue).SprintfFunc()
var symTypeColor = color.New(color.Faint, color.FgCyan).SprintfFunc()
var symLibColor = color.New(color.Faint, color.FgCyan).SprintfFunc()
var symNameColor = color.New(color.Bold).SprintFunc()

func init() {
	KernelcacheCmd.AddCommand(kernelInfoCmd)

	kernelInfoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	viper.BindPFlag("kernel.info.symbols", kernelInfoCmd.Flags().Lookup("symbols"))
}

// kernelInfoCmd represents the info command
var kernelInfoCmd = &cobra.Command{
	Use:           "info <kernelcache>",
	Aliases:       []string{"i"},
	Short:         "Explore a kernelcache file",
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		kernelPath := filepath.Clean(args[0])

		if ok, err := magic.IsMachO(kernelPath); !ok {
			return err
		}

		kern, err := macho.Open(kernelPath)
		if err != nil {
			return err
		}

		if kern.FileTOC.FileHeader.Type == types.MH_FILESET {
			for _, fe := range kern.FileSets() {
				entry, err := kern.GetFileSetFileByName(fe.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse file-set entry %s: %v", fe.EntryID, err)
				}
				if viper.GetBool("kernel.info.symbols") {
					var sec string
					var label string
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					if entry.Symtab != nil {
						label = fmt.Sprintf("%s Symtab", fe.EntryID)
						fmt.Printf("\n%s\n", label)
						fmt.Println(strings.Repeat("-", len(label)))
						for _, sym := range entry.Symtab.Syms {
							if sym.Sect > 0 && int(sym.Sect) <= len(entry.Sections) {
								sec = fmt.Sprintf("%s.%s", entry.Sections[sym.Sect-1].Seg, entry.Sections[sym.Sect-1].Name)
							}
							var lib string
							if sym.Desc.GetLibraryOrdinal() != types.SELF_LIBRARY_ORDINAL && sym.Desc.GetLibraryOrdinal() < types.MAX_LIBRARY_ORDINAL {
								lib = fmt.Sprintf("\t(%s)", filepath.Base(entry.ImportedLibraries()[sym.Desc.GetLibraryOrdinal()-1]))
							}
							if sym.Value == 0 {
								fmt.Fprintf(w, "                    %s\t<%s> [%s]\t%s%s\n", symImageColor(fe.EntryID), symTypeColor(sym.Type.String(sec)), symTypeColor(sym.Desc.String()), symNameColor(sym.Name), lib)
							} else {
								fmt.Fprintf(w, "%s: %s\t<%s> [%s]\t%s%s\n", symAddrColor("%#x", sym.Value), symImageColor(fe.EntryID), symTypeColor(sym.Type.String(sec)), symTypeColor(sym.Desc.String()), symNameColor(sym.Name), lib)
							}
						}
						w.Flush()
					} else {
						fmt.Println("  - no symbol table")
					}
				}
			}
		}

		return nil
	},
}
