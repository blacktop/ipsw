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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/crashlog"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(symbolicateCmd)

	symbolicateCmd.Flags().BoolP("unslide", "u", false, "Unslide the crashlog for easier static analysis")
	symbolicateCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	// symbolicateCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	symbolicateCmd.MarkZshCompPositionalArgumentFile(2, "dyld_shared_cache*")
}

// TODO: handle all edge cases from `/Applications/Xcode.app/Contents/SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash` and handle spindumps etc

// symbolicateCmd represents the symbolicate command
var symbolicateCmd = &cobra.Command{
	Use:     "symbolicate <CRASHLOG> <DSC>",
	Aliases: []string{"sym"},
	Short:   "Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		unslide, _ := cmd.Flags().GetBool("unslide")
		// cacheFile, _ := cmd.Flags().GetString("cache")
		demangleFlag, _ := cmd.Flags().GetBool("demangle")

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

			// if len(cacheFile) == 0 {
			// 	cacheFile = dscPath + ".a2s"
			// }
			// if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
			// 	return err
			// }

			// Symbolicate the crashing thread's backtrace
			for idx, bt := range crashLog.Threads[crashLog.CrashedThread].BackTrace {
				image, err := f.Image(bt.Image.Name)
				if err != nil {
					log.Errorf(err.Error())
					crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = "?"
					continue
				}
				// calculate slide
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

				if err := image.Analyze(); err != nil {
					return fmt.Errorf("failed to analyze image %s; %v", image.Name, err)
				}

				for _, patch := range image.PatchableExports {
					addr, err := image.GetVMAddress(uint64(patch.GetImplOffset()))
					if err != nil {
						return err
					}
					f.AddressToSymbol[addr] = patch.GetName()
				}

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
				if len(crashLog.Threads[crashLog.CrashedThread].BackTrace) > 0 {
					var slide uint64
					if img, err := f.GetImageContainingVMAddr(crashLog.Threads[crashLog.CrashedThread].State["pc"]); err == nil {
						found := false
						for _, bt := range crashLog.Threads[crashLog.CrashedThread].BackTrace {
							if bt.Image.Name == img.Name {
								slide = bt.Image.Slide
								found = true
								break
							}
						}
						if !found {
							slide = crashLog.Threads[crashLog.CrashedThread].BackTrace[0].Image.Slide
						}
					}
					note = fmt.Sprintf(" (may contain slid addresses; slide=%#x)", slide)
				} else {
					note = " (may contain slid addresses)"
				}
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
