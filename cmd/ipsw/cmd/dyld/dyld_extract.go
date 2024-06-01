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
package dyld

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

func rebaseMachO(dsc *dyld.File, machoPath string) error {
	f, err := os.OpenFile(machoPath, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("failed to open exported MachO %s: %v", machoPath, err)
	}
	defer f.Close()

	mm, err := macho.NewFile(f)
	if err != nil {
		return err
	}

	for _, seg := range mm.Segments() {
		uuid, mapping, err := dsc.GetMappingForVMAddress(seg.Addr)
		if err != nil {
			return err
		}

		if mapping.SlideInfoOffset == 0 {
			continue
		}

		startAddr := seg.Addr - mapping.Address
		endAddr := ((seg.Addr + seg.Memsz) - mapping.Address) + uint64(dsc.SlideInfo.GetPageSize())

		start := startAddr / uint64(dsc.SlideInfo.GetPageSize())
		end := endAddr / uint64(dsc.SlideInfo.GetPageSize())

		rebases, err := dsc.GetRebaseInfoForPages(uuid, mapping, start, end)
		if err != nil {
			return err
		}

		for _, rebase := range rebases {
			off, err := mm.GetOffset(rebase.CacheVMAddress)
			if err != nil {
				continue
			}
			if _, err := f.Seek(int64(off), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek in exported file to offset %#x from the start: %v", off, err)
			}
			if err := binary.Write(f, dsc.ByteOrder, rebase.Target); err != nil {
				return fmt.Errorf("failed to write rebase address %#x: %v", rebase.Target, err)
			}
		}
	}

	return nil
}

func init() {
	DyldCmd.AddCommand(dyldExtractCmd)
	dyldExtractCmd.Flags().BoolP("all", "a", false, "Split ALL dylibs")
	dyldExtractCmd.Flags().Bool("force", false, "Overwrite existing extracted dylib(s)")
	dyldExtractCmd.Flags().Bool("slide", false, "Apply slide info to extracted dylib(s)")
	dyldExtractCmd.Flags().Bool("objc", false, "Add ObjC metadata to extracted dylib(s) symtab")
	dyldExtractCmd.Flags().Bool("stubs", false, "Add stub islands to extracted dylib(s) symtab")
	// dyldExtractCmd.Flags().Bool("imports", false, "Add imported dylibs sym into to extracted symtab (will make BIG symtabs)")
	dyldExtractCmd.Flags().StringP("cache", "c", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	dyldExtractCmd.Flags().StringP("output", "o", "", "Directory to extract the dylib(s)")
	dyldExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("dyld.extract.all", dyldExtractCmd.Flags().Lookup("all"))
	viper.BindPFlag("dyld.extract.force", dyldExtractCmd.Flags().Lookup("force"))
	viper.BindPFlag("dyld.extract.slide", dyldExtractCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.extract.objc", dyldExtractCmd.Flags().Lookup("objc"))
	viper.BindPFlag("dyld.extract.stubs", dyldExtractCmd.Flags().Lookup("stubs"))
	// viper.BindPFlag("dyld.extract.imports", dyldExtractCmd.Flags().Lookup("imports"))
	viper.BindPFlag("dyld.extract.cache", dyldExtractCmd.Flags().Lookup("cache"))
	viper.BindPFlag("dyld.extract.output", dyldExtractCmd.Flags().Lookup("output"))
}

// dyldExtractCmd represents the extractDyld command
var dyldExtractCmd = &cobra.Command{
	Use:     "extract <DSC> <DYLIB>",
	Aliases: []string{"e"},
	Short:   "Extract dylib from dyld_shared_cache",
	Args:    cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveDefault
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	Hidden:        true, // FIXME: remove when extraction is fixed (is creating machos w/ incorrect headers/segment/section boundaries)
	RunE: func(cmd *cobra.Command, args []string) error {

		var bar *mpb.Bar
		var p *mpb.Progress
		var images []*dyld.CacheImage

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		dumpALL := viper.GetBool("dyld.extract.all")
		forceExtract := viper.GetBool("dyld.extract.force")
		slide := viper.GetBool("dyld.extract.slide")
		addObjc := viper.GetBool("dyld.extract.objc")
		addStubs := viper.GetBool("dyld.extract.stubs")
		// addImports := viper.GetBool("dyld.extract.imports")
		output := viper.GetString("dyld.extract.output")
		cacheFile := viper.GetString("dyld.extract.cache")
		// validate flags
		if dumpALL && len(args) > 1 {
			return fmt.Errorf("cannot specify DYLIB(s) when using --all")
		} else if !dumpALL && len(args) < 2 {
			return fmt.Errorf("must specify at least one DYLIB to extract")
		}

		dscPath := filepath.Clean(args[0])

		folder := filepath.Dir(dscPath) // default to folder of shared cache
		if len(output) > 0 {
			folder = output
		}

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

		if addStubs {
			if len(cacheFile) == 0 {
				cacheFile = dscPath + ".a2s"
			}
			if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
				return err
			}
		}

		if dumpALL {
			// set images to all images in shared cache
			images = f.Images
			// initialize progress bar
			p = mpb.New(mpb.WithWidth(80))
			// adding a single bar, which will inherit container's width
			name := "      "
			bar = p.New(int64(len(images)),
				// progress bar filler with customized style
				mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
				mpb.PrependDecorators(
					decor.Name(name, decor.WC{W: len(name), C: decor.DindentRight | decor.DextraSpace}),
					// replace ETA decorator with "done" message, OnComplete event
					decor.OnComplete(
						decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "✅ ",
					),
				),
				mpb.AppendDecorators(
					decor.CountersNoUnit("%d/%d"),
					decor.Name(" ] "),
				),
			)
			log.Infof("Extracting all dylibs from %s", dscPath)
		} else {
			// get images from args
			images = make([]*dyld.CacheImage, 0, len(args)-1)
			for _, arg := range args[1:] {
				image, err := f.Image(arg)
				if err != nil {
					return err
				}
				images = append(images, image)
			}
		}

		for _, image := range images {
			m, err := image.GetMacho()
			if err != nil {
				return err
			}

			fname := filepath.Join(folder, filepath.Base(image.Name)) // default to NOT full dylib path
			if dumpALL {
				fname = filepath.Join(folder, image.Name)
			}

			if _, err := os.Stat(fname); os.IsNotExist(err) || forceExtract {
				var dcf *fixupchains.DyldChainedFixups
				if m.HasFixups() {
					dcf, err = m.DyldChainedFixups()
					if err != nil {
						log.Errorf("failed to parse fixups from in memory MachO for %s: %v", filepath.Base(image.Name), err)
					}
				}

				image.ParseLocalSymbols(false)

				syms := image.GetLocalSymbolsAsMachoSymbols()

				if addObjc && m.HasObjC() {
					log.Info("Adding ObjC symbols")
					if protos, err := m.GetObjCProtocols(); err == nil {
						for _, proto := range protos {
							syms = append(syms, macho.Symbol{
								Name:  proto.Name,
								Value: proto.Ptr,
								Desc:  0xa00,
							})
							// fmt.Println(proto.Verbose())
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
					if classes, err := m.GetObjCClasses(); err == nil {
						for _, class := range classes {
							syms = append(syms, macho.Symbol{
								Name:  class.Name,
								Value: class.ClassPtr,
								Desc:  0xa00,
							})
							for _, cmeth := range class.ClassMethods {
								syms = append(syms, macho.Symbol{
									Name:  fmt.Sprintf("+[%s %s]", class.Name, cmeth.Name),
									Value: cmeth.ImpVMAddr,
									Desc:  0xa00,
								})
							}
							for _, imeth := range class.InstanceMethods {
								syms = append(syms, macho.Symbol{
									Name:  fmt.Sprintf("-[%s %s]", class.Name, imeth.Name),
									Value: imeth.ImpVMAddr,
									Desc:  0xa00,
								})
							}
							// fmt.Println(class.Verbose())
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
					if cats, err := m.GetObjCCategories(); err == nil {
						for _, cat := range cats {
							syms = append(syms, macho.Symbol{
								Name:  cat.Name,
								Value: cat.VMAddr,
								Desc:  0xa00,
							})
							for _, imeth := range cat.InstanceMethods {
								syms = append(syms, macho.Symbol{
									Name:  fmt.Sprintf("-[%s %s]", cat.Name, imeth.Name),
									Value: imeth.ImpVMAddr,
									Desc:  0xa00,
								})
							}
							// fmt.Println(cat.Verbose())
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}

				if addStubs {
					log.Info("Adding Stub Islands symbols")
					stubIslands, err := f.GetStubIslands()
					if err != nil {
						return err
					}
					for addr, sym := range stubIslands {
						syms = append(syms, macho.Symbol{
							Name:  sym,
							Value: addr,
							Desc:  0xa00,
						})
					}
				}

				// if addImports {
				// 	log.Info("Adding Imported Dylib's symbols")
				// 	for _, lib := range m.ImportedLibraries() {
				// 		img, err := f.Image(lib)
				// 		if err != nil {
				// 			return err
				// 		}
				// 		img.ParseLocalSymbols(false)
				// 		syms = append(syms, img.GetLocalSymbolsAsMachoSymbols()...)
				// 		mm, err := img.GetMacho()
				// 		if err != nil {
				// 			return err
				// 		}
				// 		if mm.Symtab != nil {
				// 			syms = append(syms, mm.Symtab.Syms...)
				// 		}
				// 	}
				// }

				if err := m.Export(fname, dcf, m.GetBaseAddress(), syms); err != nil {
					var perr *fs.PathError
					if errors.As(err, &perr) {
						return fmt.Errorf("failed to extract dylib %s: %v (try again with the '--output' flag to write dylib to a writable folder)", image.Name, err)
					}
					return fmt.Errorf("failed to extract dylib %s: %v", image.Name, err)
				}
				if slide {
					log.Info("Applying DSC slide-info")
					if err := rebaseMachO(f, fname); err != nil {
						return fmt.Errorf("failed to rebase dylib via cache slide info: %v", err)
					}
				}

				if dumpALL {
					bar.Increment()
				} else {
					log.Infof("Created %s", fname)
				}
			} else {
				if dumpALL {
					bar.Increment()
				} else {
					log.Warnf("Dylib already exists: %s", fname)
				}
			}

			m.Close()
		}

		if dumpALL {
			p.Wait()
		}

		return nil
	},
}
