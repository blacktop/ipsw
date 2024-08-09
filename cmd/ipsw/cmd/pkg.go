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
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/spf13/cobra"

	xar "github.com/CyberhavenInc/goxar"
	"github.com/blacktop/go-apfs/pkg/disk/dmg"
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

		dmgPath := filepath.Clean(args[0])

		zr, er := xar.OpenReader(dmgPath)
		if er == nil {
			defer zr.Close()
			log.Infof("Contents of %s:", dmgPath)
			for _, f := range zr.File {
				log.Infof("  %s", f.Name)
				if strings.HasSuffix(f.Name, "Bom") {
					os.MkdirAll(filepath.Dir(f.Name), os.ModePerm)
					out, err := os.Create(f.Name)
					if err != nil {
						return err
					}
					defer out.Close()
					rc, err := f.Open()
					if err != nil {
						return err
					}
					defer rc.Close()
					_, err = io.Copy(out, rc)
					if err != nil {
						return err
					}
				}
			}
			return nil
		}

		f, err := os.Open(dmgPath)
		if err != nil {
			return err
		}
		defer f.Close()

		d, err := dmg.NewDMG(f)
		if err != nil {
			return err
		}
		defer d.Close()

		if err := d.Load(); err != nil {
			return err
		}

		return nil
	},
}
