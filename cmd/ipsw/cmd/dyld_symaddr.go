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
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	symaddrCmd.Flags().String("in", "", "Path to JSON file containing list of symbols to lookup")
	symaddrCmd.Flags().String("out", "", "Path to output JSON file")
	// symaddrCmd.Flags().StringP("cache", "c", "", "path to addr to sym cache file")
	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// symaddrCmd represents the symaddr command
var symaddrCmd = &cobra.Command{
	Use:           "symaddr <dyld_shared_cache>",
	Short:         "Lookup or dump symbol(s)",
	SilenceUsage:  false,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		symbolFile, _ := cmd.Flags().GetString("in")
		jsonFile, _ := cmd.Flags().GetString("out")
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

		if len(symbolFile) > 0 {
			/******************************************
			 * Search for symbols in JSON lookup file *
			 ******************************************/
			var enc *json.Encoder
			var slin []dyld.Symbol
			var slout []dyld.Symbol

			symbolFile = filepath.Clean(symbolFile)
			sdata, _ := ioutil.ReadFile(symbolFile)

			if err := json.Unmarshal(sdata, &slin); err != nil {
				return fmt.Errorf("failed to parse symbol lookup JSON file %s: %v", symbolFile, err)
			}

			// group syms by image
			symages := make(map[string][]string)
			for _, s := range slin {
				if len(s.Image) > 0 {
					image, err := f.Image(s.Image)
					if err != nil {
						return err
					}
					symages[image.Name] = append(symages[image.Name], s.Name)
				} else {
					symages["unknown"] = append(symages["unknown"], s.Name)
				}
			}

			if _, uhoh := symages["unknown"]; uhoh {
				log.Warn("you should supply 'image' fields for each symbol to GREATLY increase speed")
			}

			for imageName, symNames := range symages {
				if imageName == "unknown" {
					for _, sname := range symNames {
						found := false
						for _, image := range f.Images {
							if sym, err := image.GetSymbol(sname); err == nil {
								if sym.Address > 0 {
									slout = append(slout, *sym)
									found = true
									break
								}
							}
						}
						if !found {
							log.Errorf("failed to find address for symbol %s", sname)
						}
					}
				} else {
					image, err := f.Image(imageName)
					if err != nil {
						return err
					}
					for _, name := range symNames {
						if sym, err := image.GetSymbol(name); err == nil {
							slout = append(slout, *sym)
						} else {
							log.Errorf("failed to find address for symbol %s in image %s", name, filepath.Base(image.Name))
						}
					}
				}
			}

			if len(jsonFile) > 0 {
				jFile, err := os.Create(jsonFile)
				if err != nil {
					return err
				}
				defer jFile.Close()
				enc = json.NewEncoder(jFile)
			} else {
				enc = json.NewEncoder(os.Stdout)
			}

			if err := enc.Encode(slout); err != nil {
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
					fmt.Println(lsym)
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
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, image := range f.Images {
				utils.Indent(log.Debug, 2)("Searching " + image.Name)
				if sym, err := image.GetSymbol(args[1]); err == nil {
					if sym.Address > 0 || allMatches {
						fmt.Fprintf(w, "%s\n", sym)
						if !allMatches {
							w.Flush()
							return nil
						}
					}
				}
				w.Flush()
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
