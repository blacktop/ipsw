/*
Copyright © 2024 blacktop

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
	"path/filepath"

	"github.com/apex/log"
	"github.com/spf13/cobra"

	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/go-macho/pkg/xar"
	"github.com/blacktop/ipsw/internal/magic"
)

func init() {
	rootCmd.AddCommand(pkgCmd)
}

// pkgCmd represents the pkg command
var pkgCmd = &cobra.Command{
	Use:           "pkg",
	Short:         "List contents of a DMG/PKG file",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		infile := filepath.Clean(args[0])

		isDMG, err := magic.IsDMG(infile)
		if err != nil {
			return err
		}
		if !isDMG {
			if isXar, err := magic.IsXar(infile); err != nil {
				return err
			} else if !isXar {
				return fmt.Errorf("file is not a dmg OR pkg file")
			}
		}

		if isDMG {
			d, err := dmg.Open(infile, nil)
			if err != nil {
				return err
			}
			defer d.Close()
			if err := d.Load(); err != nil {
				return err
			}
		} else { // PKG/XAR
			xar, err := xar.OpenReader(infile)
			if err != nil {
				return err
			}
			// FIXME defer xar.Close()
			if !xar.ValidSignature() {
				log.Warn("PKG/XAR file signature is invalid, this may be a corrupted file")
			}
			for _, file := range xar.File {
				log.Info(file.Name)
			}
		}

		return nil
	},
}
