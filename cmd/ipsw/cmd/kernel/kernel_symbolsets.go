/*
Copyright © 2018-2024 blacktop

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
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(symbolsetsCmd)
	kextsCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

type symbolsSets struct {
	SymbolsSetsDictionary []cFBundle `plist:"SymbolsSets,omitempty"`
}

type cFBundle struct {
	ID                string   `plist:"CFBundleIdentifier,omitempty"`
	CompatibleVersion string   `plist:"OSBundleCompatibleVersion,omitempty"`
	Version           string   `plist:"CFBundleVersion,omitempty"`
	Symbols           []symbol `plist:"Symbols,omitempty"`
}

type symbol struct {
	Name   string `plist:"SymbolName,omitempty"`
	Prefix string `plist:"SymbolPrefix,omitempty"`
}

// symbolsetsCmd represents the symbolsets command
var symbolsetsCmd = &cobra.Command{
	Use:     "symbolsets <kernelcache>",
	Aliases: []string{"ss"},
	Short:   "Dump kernel symbolsets",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "%s appears to not be a valid MachO", args[0])
		}

		if m.FileTOC.FileHeader.Type == types.MH_FILESET {
			m, err = m.GetFileSetFileByName("com.apple.kernel")
			if err != nil {
				return fmt.Errorf("failed to parse entry com.apple.kernel; %v", err)
			}
		}

		symbolsets := m.Section("__LINKINFO", "__symbolsets")
		if symbolsets == nil {
			log.Error("kernelcache does NOT contain __LINKINFO.__symbolsets")
			return nil
		}

		dat := make([]byte, symbolsets.Size)
		m.ReadAt(dat, int64(symbolsets.Offset))

		var blist symbolsSets

		dec := plist.NewDecoder(bytes.NewReader(dat))

		err = dec.Decode(&blist)
		if err != nil {
			return errors.Wrapf(err, "failed to parse __symbolsets bplist data")
		}

		fmt.Println("Symbol Sets")
		fmt.Println("===========")
		for _, sset := range blist.SymbolsSetsDictionary {
			head := fmt.Sprintf("%s: (%s)", sset.ID, sset.Version)
			fmt.Printf("\n%s\n", head)
			fmt.Println(strings.Repeat("-", len(head)))
			for _, sym := range sset.Symbols {
				fmt.Printf("%s%s\n", sym.Prefix, sym.Name)
			}
		}

		return nil
	},
}
