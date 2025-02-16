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
package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/pkg/crashlog"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(symbolicateCmd)

	symbolicateCmd.Flags().BoolP("all", "a", false, "Show all threads in crashlog")
	symbolicateCmd.Flags().BoolP("running", "r", false, "Show all running (TH_RUN) threads in crashlog")
	symbolicateCmd.Flags().StringP("proc", "p", "", "Filter crashlog by process name")
	symbolicateCmd.Flags().BoolP("unslide", "u", false, "Unslide the crashlog for easier static analysis")
	symbolicateCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	symbolicateCmd.Flags().Bool("hex", false, "Display function offsets in hexadecimal")
	symbolicateCmd.Flags().StringP("server", "s", "", "Symbol Server DB URL")
	symbolicateCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	symbolicateCmd.Flags().String("signatures", "", "Path to signatures folder")
	symbolicateCmd.Flags().String("extra", "x", "Path to folder with extra files for symbolication")
	// symbolicateCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	symbolicateCmd.MarkZshCompPositionalArgumentFile(2, "dyld_shared_cache*")
	viper.BindPFlag("symbolicate.all", symbolicateCmd.Flags().Lookup("all"))
	viper.BindPFlag("symbolicate.running", symbolicateCmd.Flags().Lookup("running"))
	viper.BindPFlag("symbolicate.proc", symbolicateCmd.Flags().Lookup("proc"))
	viper.BindPFlag("symbolicate.unslide", symbolicateCmd.Flags().Lookup("unslide"))
	viper.BindPFlag("symbolicate.demangle", symbolicateCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("symbolicate.hex", symbolicateCmd.Flags().Lookup("hex"))
	viper.BindPFlag("symbolicate.server", symbolicateCmd.Flags().Lookup("server"))
	viper.BindPFlag("symbolicate.pem-db", symbolicateCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("symbolicate.signatures", symbolicateCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("symbolicate.extra", symbolicateCmd.Flags().Lookup("extra"))
}

// TODO: handle all edge cases from `/Applications/Xcode.app/Contents/SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash` and handle spindumps etc

// symbolicateCmd represents the symbolicate command
var symbolicateCmd = &cobra.Command{
	Use:     "symbolicate <CRASHLOG> [IPSW|DSC]",
	Aliases: []string{"sym"},
	Short:   "Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)",
	Example: heredoc.Doc(`
	# Symbolicate a panic crashlog (BugType=210) with an IPSW
	❯ ipsw symbolicate panic-full-2024-03-21-004704.000.ips iPad_Pro_HFR_17.4_21E219_Restore.ipsw
	# Pretty print a crashlog (BugType=309) these are usually symbolicated by the OS
		  ❯ ipsw symbolicate --color Delta-2024-04-20-135807.ips
		  # Symbolicate a (old stype) crashlog (BugType=109) requiring a dyld_shared_cache to symbolicate
		  ❯ ipsw symbolicate Delta-2024-04-20-135807.ips
		  ⨯ please supply a dyld_shared_cache for iPhone13,3 running 14.5 (18E5154f)`),
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		/* flags */
		all := viper.GetBool("symbolicate.all")
		running := viper.GetBool("symbolicate.running")
		proc := viper.GetString("symbolicate.proc")
		unslide := viper.GetBool("symbolicate.unslide")
		// cacheFile, _ := cmd.Flags().GetString("cache")
		demangleFlag := viper.GetBool("symbolicate.demangle")
		asHex := viper.GetBool("symbolicate.hex")
		pemDB := viper.GetString("symbolicate.pem-db")
		signaturesDir := viper.GetString("symbolicate.signatures")
		extrasDir := viper.GetString("symbolicate.extra")
		/* validate flags */
		if (Verbose || all) && len(proc) > 0 {
			return fmt.Errorf("cannot use --verbose OR --all WITH --proc")
		}

		hdr, err := crashlog.ParseHeader(args[0])
		if err != nil {
			log.WithError(err).Error("failed to parse crashlog header")
			log.Warn("trying to parse as IPS crashlog (BugType=210)")
			hdr = &crashlog.IpsMetadata{
				BugType: "109",
			}
		}

		switch hdr.BugType {
		case "210", "288", "309": // NEW JSON STYLE CRASHLOG
			ips, err := crashlog.OpenIPS(args[0], &crashlog.Config{
				All:           all || Verbose,
				Running:       running,
				Process:       proc,
				Unslid:        unslide,
				Demangle:      demangleFlag,
				Hex:           asHex,
				PemDB:         pemDB,
				SignaturesDir: signaturesDir,
				ExtrasDir:     extrasDir,
				Verbose:       Verbose,
			})
			if err != nil {
				return fmt.Errorf("failed to parse IPS file: %v", err)
			}

			if len(args) < 2 && (hdr.BugType == "210" || hdr.BugType == "288") {
				if viper.IsSet("symbolicate.server") {
					u, err := url.ParseRequestURI(viper.GetString("symbolicate.server"))
					if err != nil {
						return fmt.Errorf("failed to parse symbol server URL: %v", err)
					}
					if u.Scheme == "" || u.Host == "" {
						return fmt.Errorf("invalid symbol server URL: %s (needs a valid schema AND host)", u.String())
					}
					log.WithField("server", u.String()).Info("Symbolicating 210 Panic with Symbol Server")
					if err := ips.Symbolicate210WithDatabase(u.String()); err != nil {
						return err
					}
				} else {
					log.Warnf("please supply %s %s IPSW for symbolication", ips.Payload.Product, ips.Header.OsVersion)
				}
			} else {
				// TODO: use IPSW to populate symbol server if both are supplied
				if hdr.BugType == "210" || hdr.BugType == "288" {
					/* validate IPSW */
					i, err := info.Parse(args[1])
					if err != nil {
						return err
					}
					if i.Plists.BuildManifest.ProductVersion != ips.Header.Version() ||
						i.Plists.BuildManifest.ProductBuildVersion != ips.Header.Build() ||
						!slices.Contains(i.Plists.Restore.SupportedProductTypes, ips.Payload.Product) {
						return fmt.Errorf("supplied IPSW %s does NOT match crashlog: NEED %s; %s (%s), GOT %s; %s (%s)",
							filepath.Base(args[1]),
							ips.Payload.Product, ips.Header.Version(), ips.Header.Build(),
							strings.Join(i.Plists.Restore.SupportedProductTypes, ", "),
							i.Plists.BuildManifest.ProductVersion, i.Plists.BuildManifest.ProductBuildVersion,
						)
					}
					if err := ips.Symbolicate210(filepath.Clean(args[1])); err != nil {
						return err
					}
				}
			}
			fmt.Println(ips)
		case "109": // OLD STYLE CRASHLOG
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
		default:
			log.Errorf("unsupported crashlog type: %s - %s (notify author to add support)", hdr.BugType, hdr.BugTypeDesc)
		}

		return nil
	},
}
