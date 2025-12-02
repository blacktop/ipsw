/*
Copyright © 2018-2025 blacktop

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
package dyld

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	dscCmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(SymAddrCmd)
	SymAddrCmd.Flags().BoolP("all", "a", false, "Find all symbol matches")
	SymAddrCmd.Flags().BoolP("binds", "b", false, "Also search LC_DYLD_INFO binds")
	SymAddrCmd.Flags().StringP("image", "i", "", "dylib image to search")
	SymAddrCmd.Flags().String("in", "", "Path to JSON file containing list of symbols to lookup")
	SymAddrCmd.Flags().StringP("output", "o", "", "Path to output JSON file")
	// SymAddrCmd.Flags().StringP("cache", "c", "", "path to addr to sym cache file")
	viper.BindPFlag("dyld.symaddr.all", SymAddrCmd.Flags().Lookup("all"))
	viper.BindPFlag("dyld.symaddr.binds", SymAddrCmd.Flags().Lookup("binds"))
	viper.BindPFlag("dyld.symaddr.image", SymAddrCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.symaddr.in", SymAddrCmd.Flags().Lookup("in"))
	viper.BindPFlag("dyld.symaddr.output", SymAddrCmd.Flags().Lookup("output"))
}

// SymAddrCmd represents the symaddr command
var SymAddrCmd = &cobra.Command{
	Use:     "symaddr <DSC>",
	Aliases: []string{"sym"},
	Short:   "Lookup or dump symbol(s)",
	Args:    cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		imageName := viper.GetString("dyld.symaddr.image")
		symbolFile := viper.GetString("dyld.symaddr.in")
		jsonFile := viper.GetString("dyld.symaddr.output")
		allMatches := viper.GetBool("dyld.symaddr.all")
		showBinds := viper.GetBool("dyld.symaddr.binds")

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

		if len(symbolFile) > 0 {
			/******************************************
			 * Search for symbols in JSON lookup file *
			 ******************************************/
			var lookups []dscCmd.Symbol

			lookupData, err := os.ReadFile(filepath.Clean(symbolFile))
			if err != nil {
				return fmt.Errorf("failed to read symbol lookup JSON file %s: %v", symbolFile, err)
			}
			if err := json.Unmarshal(lookupData, &lookups); err != nil {
				return fmt.Errorf("failed to parse symbol lookup JSON file %s: %v", symbolFile, err)
			}

			syms, err := dscCmd.GetSymbols(f, lookups)
			if err != nil {
				return fmt.Errorf("failed to lookup symbols from lookup JSON file: %v", err)
			}

			var enc *json.Encoder
			if len(jsonFile) > 0 {
				jf, err := os.Create(jsonFile)
				if err != nil {
					return err
				}
				defer jf.Close()
				enc = json.NewEncoder(jf)
			} else {
				enc = json.NewEncoder(os.Stdout)
			}

			if err := enc.Encode(syms); err != nil {
				return err
			}

			return nil
		} else if len(args) > 1 {
			if len(imageName) > 0 {
				/**********************************
				 * Search for symbol inside dylib *
				 **********************************/
				i, err := f.Image(imageName)
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}

				if lsym, err := i.GetSymbol(args[1]); err == nil {
					fmt.Println(lsym.String(colors.Active()))
				}

				// if lsym, err := i.GetLocalSymbol(args[1]); err == nil {
				// 	fmt.Println(lsym)
				// }
				// if lsym, err := i.GetPublicSymbol(args[1]); err == nil {
				// 	fmt.Println(lsym)
				// }
				// if export, err := i.GetExport(args[1]); err == nil {
				// 	fmt.Println(export)
				// }

				return nil
			}
			/**********************************
			 * Search ALL dylibs for a symbol *
			 **********************************/
			symChan, err := f.GetExportedSymbols(context.Background(), args[1])
			if err != nil {
				if !errors.Is(err, dyld.ErrNoPrebuiltLoadersInCache) {
					return fmt.Errorf("failed to get exported symbols: %v", err)
				}
			} else {
				for {
					sym, ok := <-symChan
					if !ok {
						break
					}
					fmt.Println(sym.String(colors.Active()))
					if !allMatches {
						return nil
					}
				}
			}
			for _, image := range f.Images { // use brute force search
				utils.Indent(log.Debug, 2)("Searching " + image.Name)
				if sym, err := image.GetSymbol(args[1]); err == nil {
					if (sym.Address > 0 || allMatches) && (sym.Kind != dyld.BIND || showBinds) {
						fmt.Println(sym.String(colors.Active()))
						if !allMatches {
							return nil
						}
					}
				}
			}
			return nil
		} else if len(imageName) > 0 {
			/*************************
			* Dump all dylib symbols *
			**************************/
			i, err := f.Image(imageName)
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath, err)
			}

			log.Warn("parsing private symbols for image...")
			if err := i.ParseLocalSymbols(true); err != nil {
				if errors.Is(err, dyld.ErrNoLocals) {
					utils.Indent(log.Warn, 2)(err.Error())
				} else if err != nil {
					log.Errorf("failed parse private symbols for image %s: %v", i.Name, err)
				}
			}

			log.Warn("parsing public symbols for image...")
			if err := i.ParsePublicSymbols(true); err != nil {
				log.Errorf("failed to parse public symbols for image %s: %v", i.Name, err)
			}

			return nil
		}
		/******************
		* Dump ALL symbols*
		*******************/
		log.Warn("parsing public symbols...")
		if err = f.ParsePublicSymbols(true); err != nil {
			log.Errorf("failed to get all public symbols: %v", err)
		}

		log.Warn("parsing private symbols...")
		if err = f.ParseLocalSyms(true); err != nil {
			log.Errorf("failed to parse private symbols: %v", err)
		}

		return nil
	},
}
