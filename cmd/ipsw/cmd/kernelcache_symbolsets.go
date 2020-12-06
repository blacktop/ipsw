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

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"howett.net/plist"
)

func init() {
	kernelcacheCmd.AddCommand(symbolsetsCmd)
	kextsCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// symbolsetsCmd represents the symbolsets command
var symbolsetsCmd = &cobra.Command{
	Use:   "symbolsets",
	Short: "Dump kernel symbolsets",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return errors.Wrapf(err, "%s appears to not be a valid MachO", args[0])
		}

		symbolsets := m.Section("__LINKINFO", "__symbolsets")
		if symbolsets == nil {
			log.Error("kernelcache does NOT contain __LINKINFO.__symbolsets")
			return nil
		}

		dat, err := symbolsets.Data()
		if err != nil {
			return errors.Wrapf(err, "failed to read section __LINKINFO.__symbolsets data")
		}

		var blist interface{} // TODO: flesh out this struct

		dec := plist.NewDecoder(bytes.NewReader(dat))

		err = dec.Decode(&blist)
		if err != nil {
			return errors.Wrapf(err, "failed to parse __symbolsets bplist data")
		}

		fmt.Printf("%#v\n", blist)

		return nil
	},
}
