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
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/crashlog"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(symbolicateCmd)

	symbolicateCmd.Flags().BoolP("unslide", "u", false, "Unslide the crashlog for easier static analysis")
	symbolicateCmd.Flags().BoolVarP(&demangleFlag, "demangle", "d", false, "Demangle symbol names")
	symbolicateCmd.MarkZshCompPositionalArgumentFile(2, "dyld_shared_cache*")
}

// TODO: handle all edge cases from `/Applications/Xcode.app/Contents/SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash` and handle spindumps etc

// symbolicateCmd represents the symbolicate command
var symbolicateCmd = &cobra.Command{
	Use:   "symbolicate <crashlog> <dyld_shared_cache>",
	Short: "Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		unslide, _ := cmd.Flags().GetBool("unslide")

		crashLog, err := crashlog.Open(args[0])
		if err != nil {
			return err
		}
		defer crashLog.Close()

		if len(args) > 1 {
			dscPath := filepath.Clean(args[1])

			fileInfo, err := os.Lstat(dscPath)
			if err != nil {
				return fmt.Errorf("file %s does not exist", dscPath)
			}

			// Check if file is a symlink
			if fileInfo.Mode()&os.ModeSymlink != 0 {
				symlinkPath, err := os.Readlink(dscPath)
				if err != nil {
					return fmt.Errorf("failed to read symlink %s: %v", dscPath, err)
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

			// Load all symbols
			// if _, err := os.Stat(dscPath + ".a2s"); os.IsNotExist(err) {
			// 	log.Info("Generating dyld_shared_cache companion symbol map file...")

			// 	// utils.Indent(log.Warn, 2)("parsing public symbols...")
			// 	// err = f.GetAllExportedSymbols(false)
			// 	// if err != nil {
			// 	// 	return err
			// 	// }
			// 	utils.Indent(log.Warn, 2)("parsing private symbols...")
			// 	err = f.ParseLocalSyms()
			// 	if err != nil {
			// 		utils.Indent(log.Warn, 2)(err.Error())
			// 		utils.Indent(log.Warn, 2)("parsing patch exports...")
			// 		for _, img := range f.Images {
			// 			for _, patch := range img.PatchableExports {
			// 				addr, err := f.GetVMAddress(uint64(patch.OffsetOfImpl))
			// 				if err != nil {
			// 					return err
			// 				}
			// 				f.AddressToSymbol[addr] = patch.Name
			// 			}
			// 		}
			// 	}
			// 	// cache all sels
			// f.GetAllSelectors(false)
			// f.GetAllClasses(false)
			// f.GetAllProtocols(false)
			// 	// save lookup map to disk to speed up subsequent requests
			// 	err = f.SaveAddrToSymMap(dscPath + ".a2s")
			// 	if err != nil {
			// 		return err
			// 	}

			// } else {
			// 	log.Info("Found dyld_shared_cache companion symbol map file...")
			// 	a2sFile, err := os.Open(dscPath + ".a2s")
			// 	if err != nil {
			// 		return fmt.Errorf("failed to open companion file %s; %v", dscPath+".a2s", err)
			// 	}

			// 	gzr, err := gzip.NewReader(a2sFile)
			// 	if err != nil {
			// 		return fmt.Errorf("failed to create gzip reader: %v", err)
			// 	}

			// 	// Decoding the serialized data
			// 	err = gob.NewDecoder(gzr).Decode(&f.AddressToSymbol)
			// 	if err != nil {
			// 		return fmt.Errorf("failed to decode addr2sym map; %v", err)
			// 	}
			// 	gzr.Close()
			// 	a2sFile.Close()
			// }

			// Symbolicate the crashing thread's backtrace
			for idx, bt := range crashLog.Threads[crashLog.CrashedThread].BackTrace {
				// calculate slide
				image := f.Image(bt.Image.Name)
				bt.Image.Slide = bt.Image.Start - image.CacheImageTextInfo.LoadAddress
				unslidAddr := bt.Address - bt.Image.Slide
				m, err := image.GetMacho()
				if err != nil {
					return err
				}
				defer m.Close()

				// check if symbol is cached
				if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
					if demangleFlag {
						symName = demangle.Do(symName, false, false)
					}
					crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = symName
					continue
				}

				if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
					if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
						if demangleFlag {
							symName = demangle.Do(symName, false, false)
						}
						crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = fmt.Sprintf("%s + %d", symName, unslidAddr-fn.StartAddr)
						continue
					}
				}

				if m.HasObjC() {
					if err := f.ParseObjcForImage(image.Name); err != nil {
						return fmt.Errorf("failed to parse objc data for image %s: %v", image.Name, err)
					}
				}

				for _, patch := range image.PatchableExports {
					addr, err := image.GetVMAddress(uint64(patch.OffsetOfImpl))
					if err != nil {
						return err
					}
					f.AddressToSymbol[addr] = patch.Name
				}

				// Load all symbol
				if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
					log.Error("failed to parse exported symbols")
				}

				if err := f.GetLocalSymbolsForImage(image); err != nil {
					if errors.Is(err, dyld.ErrNoLocals) {
						utils.Indent(log.Warn, 2)(err.Error())
					} else if err != nil {
						return err
					}
				}

				// if err := f.AnalyzeImage(image); err != nil {
				// 	return fmt.Errorf("failed to analyze image %s; %v", image.Name, err)
				// }

				if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
					if demangleFlag {
						symName = demangle.Do(symName, false, false)
					}
					crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = symName
					continue
				}

				if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
					if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
						if demangleFlag {
							symName = demangle.Do(symName, false, false)
						}
						crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = fmt.Sprintf("%s + %d", symName, unslidAddr-fn.StartAddr)
					}
				}

			}

			fmt.Println(crashLog)

			fmt.Printf("Thread %d name: %s\n",
				crashLog.CrashedThread,
				crashLog.Threads[crashLog.CrashedThread].Name)
			fmt.Printf("Thread %d Crashed:\n", crashLog.CrashedThread)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, bt := range crashLog.Threads[crashLog.CrashedThread].BackTrace {
				if unslide {
					fmt.Fprintf(w, "\t%2d: %s\t%#x\t%s\n", bt.FrameNum, bt.Image.Name, bt.Address-bt.Image.Slide, bt.Symbol)
				} else {
					fmt.Fprintf(w, "\t%2d: %s\t(slide=%#x)\t%#x\t%s\n", bt.FrameNum, bt.Image.Name, bt.Image.Slide, bt.Address, bt.Symbol)
				}
			}
			w.Flush()
			var note string
			if unslide {
				note = " (may contain slid addresses)"
			}
			fmt.Printf("\nThread %d State:%s\n%s\n", crashLog.CrashedThread, note, crashLog.Threads[crashLog.CrashedThread].State)
			// slide := crashLog.Threads[crashLog.CrashedThread].BackTrace[0].Image.Slide
			// for key, val := range crashLog.Threads[crashLog.CrashedThread].State {
			// 	unslid := val - slide
			// 	if sym, ok := f.AddressToSymbol[unslid]; ok {
			// 		fmt.Printf("%4v: %#016x %s\n", key, val, sym)
			// 	} else {
			// 		fmt.Printf("%4v: %#016x\n", key, val)
			// 	}
			// }
		} else {
			log.Errorf("please supply a dyld_shared_cache for %s running %s (%s)", crashLog.HardwareModel, crashLog.OSVersion, crashLog.OSBuild)
		}

		return nil
	},
}
