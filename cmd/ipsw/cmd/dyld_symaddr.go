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
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(symaddrCmd)

	symaddrCmd.Flags().BoolP("all", "a", false, "Find all symbol matches")
	symaddrCmd.Flags().StringP("image", "i", "", "dylib image to search")
	// symaddrCmd.Flags().StringP("cache", "c", "", "path to addr to sym cache file")
	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// symaddrCmd represents the symaddr command
var symaddrCmd = &cobra.Command{
	Use:   "symaddr [options] <dyld_shared_cache>",
	Short: "Lookup or dump symbol(s)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		// cacheFile, _ := cmd.Flags().GetString("cache")
		allMatches, _ := cmd.Flags().GetBool("all")

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
			/**********************************
			 * Search for symbol inside dylib *
			 **********************************/
			if len(imageName) > 0 {
				m, err := f.Image(imageName).GetPartialMacho()
				if err != nil {
					return err
				}
				if sym, err := f.FindExportedSymbolInImage(imageName, args[1]); err != nil {
					log.Error(err.Error())
				} else {
					if sym.Flags.ReExport() {
						sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
						// lookup re-exported symbol
						if rexpSym, _ := f.FindExportedSymbolInImage(sym.FoundInDylib, sym.ReExport); rexpSym != nil {
							sym.Address = rexpSym.Address
						}
					}
					fmt.Println(sym)

					if !allMatches {
						return nil
					}
				}

				if sym, _ := f.FindLocalSymbolInImage(args[1], imageName); sym != nil {
					// sym.Sections = m.Sections
					fmt.Println(sym)
				}

				return nil
			}

			/**********************************
			 * Search ALL dylibs for a symbol *
			 **********************************/
			log.Warn("searching in local symbols...")
			if lSym, _ := f.FindLocalSymbol(args[1]); lSym != nil {
				fmt.Println(lSym)
			}
			log.Warn("searching in exported symbols...")
			for _, image := range f.Images {
				// utils.Indent(log.Debug, 2)("searching " + image.Name)
				m, err := f.Image(image.Name).GetPartialMacho()
				if err != nil {
					return err
				}

				if sym, err := f.FindExportedSymbolInImage(image.Name, args[1]); err != nil {
					if err != nil && !errors.Is(err, dyld.ErrSymbolNotInImage) {
						// return fmt.Errorf("failed to find symbol in image: %v", err)
						log.Errorf("failed to find symbol in image: %v", err)
					}
				} else {
					if sym.Flags.ReExport() {
						sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
						// lookup re-exported symbol
						if rexpSym, _ := f.FindExportedSymbolInImage(sym.FoundInDylib, sym.ReExport); rexpSym != nil {
							sym.Address = rexpSym.Address
						}
					}
					fmt.Println(sym)

					if !allMatches {
						return nil
					}
				}
			}

			return nil

			/*************************
			* Dump all dylib symbols *
			**************************/
		} else if len(imageName) > 0 {
			// Dump ALL private symbols for a dylib
			log.Warn("parsing local symbols for image...")
			if err := f.GetLocalSymbolsForImage(f.Image(imageName)); err != nil {
				if errors.Is(err, dyld.ErrNoLocals) {
					utils.Indent(log.Warn, 2)(err.Error())
				} else if err != nil {
					return err
				}
			}

			// m, err := f.Image(imageName).GetPartialMacho()
			// if err != nil {
			// 	return err
			// }
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, sym := range f.Image(imageName).LocalSymbols {
				// sym.Sections = m.Sections
				fmt.Fprintf(w, "%s\n", sym)
			}
			w.Flush()

			// Dump ALL public symbols for a dylib
			log.Warn("parsing exported symbols for image...")
			if err := f.GetAllExportedSymbolsForImage(f.Image(imageName), true); err != nil {
				log.Error(err.Error())

				log.Warn("falling back to MachO symtab")
				m, err := f.Image(imageName).GetMacho()
				if err != nil {
					return err
				}

				var sec string
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
				for _, sym := range m.Symtab.Syms {
					if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
						sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
					}
					fmt.Fprintf(w, "%#016x:\t(%s)\t%s\n", sym.Value, sym.Type.String(sec), sym.Name)
				}
				w.Flush()
			}

			return nil
		}

		/******************
		* Dump ALL symbols*
		*******************/
		log.Warn("parsing exported symbols...")
		if err = f.GetAllExportedSymbols(true); err != nil {
			log.Errorf("failed to get all exported symbols: %v", err)
		}

		log.Warn("parsing local symbols (slow)...")
		if err = f.ParseLocalSyms(); err != nil {
			log.Errorf("failed to parse private symbols", err)
			return nil
		}

		for _, image := range f.Images {
			fmt.Printf("\n%s\n", image.Name)
			// m, err := image.GetPartialMacho()
			// if err != nil {
			// 	return err
			// }
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, sym := range image.LocalSymbols {
				// sym.Sections = m.Sections
				fmt.Fprintf(w, "%s\n", sym)
			}
			w.Flush()
		}

		return nil
	},
}
