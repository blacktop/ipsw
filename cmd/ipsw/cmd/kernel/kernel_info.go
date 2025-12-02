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
package kernel

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var symAddrColor = colors.Faint().SprintfFunc()
var symImageColor = colors.FaintBlue().SprintfFunc()
var symTypeColor = colors.FaintCyan().SprintfFunc()
var symLibColor = colors.FaintMagenta().SprintfFunc()
var symNameColor = colors.Bold().SprintFunc()

func init() {
	KernelcacheCmd.AddCommand(kernelInfoCmd)

	kernelInfoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	kernelInfoCmd.Flags().BoolP("strings", "c", false, "Print cstrings")
	kernelInfoCmd.Flags().StringP("filter", "f", "", "Filter symbols by name")
	kernelInfoCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	viper.BindPFlag("kernel.info.symbols", kernelInfoCmd.Flags().Lookup("symbols"))
	viper.BindPFlag("kernel.info.strings", kernelInfoCmd.Flags().Lookup("strings"))
	viper.BindPFlag("kernel.info.filter", kernelInfoCmd.Flags().Lookup("filter"))
	viper.BindPFlag("kernel.info.arch", kernelInfoCmd.Flags().Lookup("arch"))
}

// kernelInfoCmd represents the info command
var kernelInfoCmd = &cobra.Command{
	Use:           "info <kernelcache>",
	Aliases:       []string{"i"},
	Short:         "Explore a kernelcache file",
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var re *regexp.Regexp

		filter := viper.GetString("kernel.info.filter")
		selectedArch := viper.GetString("kernel.info.arch")

		if filter != "" {
			var err error
			re, err = regexp.Compile(filter)
			if err != nil {
				return err
			}
		}

		kernelPath := filepath.Clean(args[0])

		if ok, err := magic.IsMachoOrImg4(kernelPath); !ok {
			return err
		}

		kr, err := mcmd.OpenMachO(kernelPath, selectedArch)
		if err != nil {
			return err
		}
		defer kr.Close()
		kern := kr.File

		if kern.FileTOC.FileHeader.Type == types.MH_FILESET {
			var label string
			for _, fe := range kern.FileSets() {
				entry, err := kern.GetFileSetFileByName(fe.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse file-set entry %s: %v", fe.EntryID, err)
				}
				if viper.GetBool("kernel.info.symbols") {
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					if entry.Symtab != nil {
						if re == nil {
							label = fmt.Sprintf("[%s] Symtab", fe.EntryID)
							fmt.Printf("\n%s\n", label)
							fmt.Println(strings.Repeat("-", len(label)))
						}
						for _, sym := range entry.Symtab.Syms {
							if re != nil && !re.MatchString(sym.Name) {
								continue
							}
							if sym.Value == 0 {
								fmt.Fprintf(w, "                    %s\n", strings.Join([]string{symImageColor(fe.EntryID), symTypeColor(sym.GetType(entry)), symNameColor(sym.Name), symLibColor(sym.GetLib(entry))}, "\t"))
							} else {
								fmt.Fprintf(w, "%s: %s\n", symAddrColor("%#x", sym.Value), strings.Join([]string{symImageColor(fe.EntryID), symTypeColor(sym.GetType(entry)), symNameColor(sym.Name), symLibColor(sym.GetLib(entry))}, "\t"))
							}
						}
						w.Flush()
					} else {
						fmt.Println("  - no symbol table")
					}
				}
				if viper.GetBool("kernel.info.strings") {
					if re == nil {
						label = fmt.Sprintf("[%s] Strings", fe.EntryID)
						fmt.Printf("\n%s\n", label)
						fmt.Println(strings.Repeat("-", len(label)))
					}
					for _, sec := range entry.Sections {
						if sec.Flags.IsCstringLiterals() || sec.Seg == "__TEXT" && sec.Name == "__const" {
							off, err := entry.GetOffset(sec.Addr)
							if err != nil {
								return fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
							}
							dat := make([]byte, sec.Size)
							if _, err = entry.ReadAt(dat, int64(off)); err != nil {
								return fmt.Errorf("failed to read cstring data in %s.%s: %v", sec.Seg, sec.Name, err)
							}

							csr := bytes.NewBuffer(dat)

							for {
								pos := sec.Addr + uint64(csr.Cap()-csr.Len())

								s, err := csr.ReadString('\x00')

								if err == io.EOF {
									break
								}

								if err != nil {
									return fmt.Errorf("failed to read string: %v", err)
								}

								s = strings.Trim(s, "\x00")

								if len(s) > 0 {
									if (sec.Seg == "__TEXT" && sec.Name == "__const") && !utils.IsASCII(s) {
										continue // skip non-ascii strings when dumping __TEXT.__const
									}
									if re != nil && !re.MatchString(s) {
										continue
									}
									fmt.Printf("%s: %s\t%#v\n", symAddrColor("%#x", pos), symImageColor(fe.EntryID), s)
								}
							}
						}
					}
				}
			}
		} else {
			log.Warn("file is NOT a MH_FILESET: `ipsw kernel info` is intended for use on kernelcaches that are a MH_FILESET, you should use `ipsw macho info` instead")
		}

		return nil
	},
}
