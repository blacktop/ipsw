/*
Copyright © 2018-2022 blacktop

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
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
	SymAddrCmd.Flags().String("out", "", "Path to output JSON file")
	SymAddrCmd.Flags().Bool("color", false, "Colorize output")
	// SymAddrCmd.Flags().StringP("cache", "c", "", "path to addr to sym cache file")
	SymAddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// SymAddrCmd represents the symaddr command
var SymAddrCmd = &cobra.Command{
	Use:           "symaddr <dyld_shared_cache>",
	Short:         "Lookup or dump symbol(s)",
	SilenceUsage:  false,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		symbolFile, _ := cmd.Flags().GetString("in")
		jsonFile, _ := cmd.Flags().GetString("out")
		allMatches, _ := cmd.Flags().GetBool("all")
		showBinds, _ := cmd.Flags().GetBool("binds")
		forceColor, _ := cmd.Flags().GetBool("color")

		color.NoColor = !forceColor

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
			sdata, _ := os.ReadFile(symbolFile)

			if err := json.Unmarshal(sdata, &slin); err != nil {
				return fmt.Errorf("failed to parse symbol lookup JSON file %s: %v", symbolFile, err)
			}

			// group syms by image
			symages := make(map[string][]dyld.Symbol)
			for _, s := range slin {
				if len(s.Image) > 0 {
					image, err := f.Image(s.Image)
					if err != nil {
						return err
					}
					symages[image.Name] = append(symages[image.Name], s)
				} else {
					symages["unknown"] = append(symages["unknown"], s)
				}
			}

			if _, uhoh := symages["unknown"]; uhoh {
				log.Warn("you should supply 'image' fields for each symbol to GREATLY increase speed")
			}

			for imageName, syms := range symages {
				if imageName == "unknown" {
					for _, s := range syms {
						found := false
						for _, image := range f.Images {
							if len(s.Regex) > 0 {
								re, err := regexp.Compile(s.Regex)
								if err != nil {
									return err
								}
								m, err := image.GetPartialMacho()
								if err != nil {
									return err
								}
								image.ParseLocalSymbols(false)
								for _, lsym := range image.LocalSymbols {
									if re.MatchString(lsym.Name) {
										var sec string
										if lsym.Sect > 0 && int(lsym.Sect) <= len(m.Sections) {
											sec = fmt.Sprintf("%s.%s", m.Sections[lsym.Sect-1].Seg, m.Sections[lsym.Sect-1].Name)
										}
										slout = append(slout, dyld.Symbol{
											Name:    lsym.Name,
											Address: lsym.Value,
											Type:    lsym.Type.String(sec),
											Image:   image.Name,
											Kind:    dyld.LOCAL,
										})
									}
								}
								image.ParsePublicSymbols(false)
								for _, sym := range image.PublicSymbols {
									if re.MatchString(sym.Name) {
										sym.Image = filepath.Base(image.Name)
										slout = append(slout, *sym)
									}
								}
							} else {
								if sym, err := image.GetSymbol(s.Name); err == nil {
									if sym.Address > 0 {
										slout = append(slout, *sym)
										found = true
										break
									}
								}
							}
						}
						if !found {
							log.Errorf("failed to find address for symbol %s", s.Name)
						}
					}
				} else {
					image, err := f.Image(imageName)
					if err != nil {
						return err
					}
					for _, s := range syms {
						if len(s.Regex) > 0 {
							re, err := regexp.Compile(s.Regex)
							if err != nil {
								return err
							}
							m, err := image.GetPartialMacho()
							if err != nil {
								return err
							}
							image.ParseLocalSymbols(false)
							for _, lsym := range image.LocalSymbols {
								if re.MatchString(lsym.Name) {
									var sec string
									if lsym.Sect > 0 && int(lsym.Sect) <= len(m.Sections) {
										sec = fmt.Sprintf("%s.%s", m.Sections[lsym.Sect-1].Seg, m.Sections[lsym.Sect-1].Name)
									}
									slout = append(slout, dyld.Symbol{
										Name:    lsym.Name,
										Address: lsym.Value,
										Type:    lsym.Type.String(sec),
										Image:   image.Name,
										Kind:    dyld.LOCAL,
									})
								}
							}
							image.ParsePublicSymbols(false)
							for _, sym := range image.PublicSymbols {
								if re.MatchString(sym.Name) {
									sym.Image = filepath.Base(image.Name)
									slout = append(slout, *sym)
								}
							}
						} else {
							if sym, err := image.GetSymbol(s.Name); err == nil {
								slout = append(slout, *sym)
							} else {
								log.Errorf("failed to find address for symbol %s in image %s", s.Name, filepath.Base(image.Name))
							}
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
					fmt.Println(lsym.String(forceColor))
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
			for _, image := range f.Images {
				utils.Indent(log.Debug, 2)("Searching " + image.Name)
				if sym, err := image.GetSymbol(args[1]); err == nil {
					if (sym.Address > 0 || allMatches) && (sym.Kind != dyld.BIND || showBinds) {
						fmt.Println(sym.String(forceColor))
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
