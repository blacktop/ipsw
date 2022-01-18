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
			var slin []dyld.Symbol
			var slout []dyld.Symbol
			var enc *json.Encoder
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
						if lSym, _ := f.FindLocalSymbol(sname); lSym != nil {
							i, err := f.GetImageContainingVMAddr(lSym.Value)
							if err != nil {
								return err
							}
							slout = append(slout, dyld.Symbol{
								Name:    sname,
								Address: lSym.Value,
								Image:   i.Name,
							})
						} else {
							for _, image := range f.Images {
								if sym, err := image.FindExportedSymbol(sname); err == nil {
									slout = append(slout, dyld.Symbol{
										Name:    sname,
										Address: sym.Address,
										Image:   sym.Image,
									})
									found = true
									break
								}
							}
							if !found {
								log.Errorf("failed to find address for symbol %s", sname)
							}
						}
					}
				} else {
					image, err := f.Image(imageName)
					if err != nil {
						return err
					}
					isyms, err := image.GetSymbols(symNames)
					if err != nil {
						return err
					}
					slout = append(slout, isyms...)
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
				if sym, err := f.FindExportedSymbolInImage(imageName, args[1]); err != nil {
					if errors.Is(err, dyld.ErrNoExportTrieInMachO) {
						m, err := i.GetMacho()
						if err != nil {
							return err
						}
						for _, sym := range m.Symtab.Syms {
							if sym.Name == args[1] {
								var sec string
								if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
									sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
								}
								fmt.Printf("%#09x:\t(%s)\t%s\n", sym.Value, sym.Type.String(sec), sym.Name)
								if !allMatches {
									return nil
								}
							}
						}
						if binds, err := m.GetBindInfo(); err == nil {
							for _, bind := range binds {
								if bind.Name == args[1] {
									fmt.Printf("%#09x:\t(%s.%s)\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Name)
									if !allMatches {
										return nil
									}
								}
							}
						}
					} else {
						return err
					}
				} else {
					if sym.Flags.ReExport() {
						m, err := i.GetPartialMacho()
						if err != nil {
							return err
						}
						sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
						// lookup re-exported symbol
						if rexpSym, err := f.FindExportedSymbolInImage(sym.FoundInDylib, sym.ReExport); err != nil {
							if errors.Is(err, dyld.ErrNoExportTrieInMachO) {
								image, err := f.Image(sym.FoundInDylib)
								if err != nil {
									return err
								}
								m, err = image.GetMacho()
								if err != nil {
									return err
								}
								for _, s := range m.Symtab.Syms {
									if s.Name == sym.ReExport {
										sym.Address = s.Value
										fmt.Println(sym)
										if !allMatches {
											return nil
										}
									}
								}
							} else {
								return err
							}
						} else {
							sym.Address = rexpSym.Address
							fmt.Println(sym)
							if !allMatches {
								return nil
							}
						}
					}
				}

				if sym := i.FindLocalSymbol(args[1]); sym != nil {
					sym.Macho, err = i.GetPartialMacho()
					if err != nil {
						return err
					}
					fmt.Println(sym)
				}

				return nil
			}
			/**********************************
			 * Search ALL dylibs for a symbol *
			 **********************************/
			log.Warn("searching in local symbols...")
			if lSym, _ := f.FindLocalSymbol(args[1]); lSym != nil {
				if len(lSym.FoundInDylib) > 0 {
					image, err := f.Image(lSym.FoundInDylib)
					if err != nil {
						return err
					}
					lSym.Macho, err = image.GetPartialMacho()
					if err != nil {
						return err
					}
				}
				fmt.Println(lSym)
				if !allMatches {
					return nil
				}
			}
			log.Warn("searching in exported symbols...")
			for _, image := range f.Images {
				utils.Indent(log.Debug, 2)("Searching " + image.Name)
				m, err := image.GetMacho()
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
				if sym, err := f.FindExportedSymbolInImage(image.Name, args[1]); err != nil {
					if errors.Is(err, dyld.ErrSymbolNotInExportTrie) {
						for _, sym := range m.Symtab.Syms {
							if sym.Name == args[1] {
								var sec string
								if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
									sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
								}
								fmt.Fprintf(w, "%#09x:\t(%s)\t%s\t%s\n", sym.Value, sym.Type.String(sec), sym.Name, image.Name)

								if !allMatches {
									w.Flush()
									return nil
								}
							}
						}
						if binds, err := m.GetBindInfo(); err == nil {
							for _, bind := range binds {
								if bind.Name == args[1] {
									fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Dylib, bind.Name, image.Name)

									if !allMatches {
										w.Flush()
										return nil
									}
								}
							}
						}
					}
				} else {
					if sym.Flags.ReExport() {
						sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
						// lookup re-exported symbol
						if rexpSym, err := f.FindExportedSymbolInImage(sym.FoundInDylib, sym.ReExport); err != nil {
							if errors.Is(err, dyld.ErrNoExportTrieInMachO) {
								image, err := f.Image(sym.FoundInDylib)
								if err != nil {
									return err
								}
								m, err = image.GetMacho()
								if err != nil {
									return err
								}
								for _, s := range m.Symtab.Syms {
									if s.Name == sym.ReExport {
										sym.Address = s.Value
										fmt.Fprintf(w, "%s\t%s\n", sym, image.Name)
										if !allMatches {
											w.Flush()
											return nil
										}
									}
								}
							} else {
								return err
							}
						} else {
							sym.Address = rexpSym.Address
							fmt.Fprintf(w, "%s\t%s\n", sym, image.Name)
							if !allMatches {
								w.Flush()
								return nil
							}
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
			log.Warn("parsing local symbols for image...")
			if err := i.ParseLocalSymbols(); err != nil {
				if errors.Is(err, dyld.ErrNoLocals) {
					utils.Indent(log.Warn, 2)(err.Error())
				} else if err != nil {
					return err
				}
			}

			m, err := i.GetPartialMacho()
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, sym := range i.LocalSymbols {
				sym.Macho = m
				fmt.Fprintf(w, "%s\n", sym)
			}
			w.Flush()

			// Dump ALL public symbols for a dylib
			log.Warn("parsing exported symbols for image...")
			if err := i.ParseExportedSymbols(true); err != nil {
				log.Errorf("failed to get all exported symbols for image %s: %v", imageName, err)
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
			m, err := image.GetPartialMacho()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, sym := range image.LocalSymbols {
				sym.Macho = m
				fmt.Fprintf(w, "%s\n", sym)
			}
			w.Flush()
		}

		return nil
	},
}
