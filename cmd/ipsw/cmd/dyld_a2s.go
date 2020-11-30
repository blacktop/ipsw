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
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(a2sCmd)
	a2sCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// a2sCmd represents the a2s command
var a2sCmd = &cobra.Command{
	Use:   "a2s",
	Short: "Lookup symbol at unslid address",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		var addr uint64
		var numberStr string

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if strings.HasPrefix(strings.ToLower(args[1]), "0x") {
			numberStr = strings.Replace(args[1], "0x", "", -1)
			numberStr = strings.Replace(numberStr, "0X", "", -1)
		}

		addr, err := strconv.ParseUint(numberStr, 16, 64)
		if err != nil {
			log.Warn("assuming given address is in decimal")
			addr, err = strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return errors.Wrapf(err, "failed to convert given address to int: %s", args[1])
			}
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

		if _, err := os.Stat(dscPath + ".a2s"); os.IsNotExist(err) {
			log.Warn("parsing public symbols...")
			err = f.GetAllExportedSymbols(false)
			if err != nil {
				return err
			}
			log.Warn("parsing private symbols...")
			err = f.ParseLocalSyms()
			if err != nil {
				return err
			}
			fmt.Printf("%#x: %s\n", addr, f.AddressToSymbol[addr])
			// save lookup map to disk to speed up subsequent requests
			return f.SaveAddrToSymMap(dscPath + ".a2s")
		}

		a2sFile, err := os.Open(dscPath + ".a2s")
		if err != nil {
			return err
		}
		defer a2sFile.Close()

		gzr, err := gzip.NewReader(a2sFile)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gzr.Close()

		// Decoding the serialized data
		err = gob.NewDecoder(gzr).Decode(&f.AddressToSymbol)
		if err != nil {
			return err
		}

		if symName, ok := f.AddressToSymbol[addr]; ok {
			fmt.Printf("%#x: %s\n", addr, symName)
		} else {
			log.Error("no symbol found")
		}

		return nil
	},
}
