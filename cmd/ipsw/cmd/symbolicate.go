/*
Copyright © 2018-2026 blacktop

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
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/tui"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/internal/xcode"
	"github.com/blacktop/ipsw/pkg/crashlog"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func init() {
	rootCmd.AddCommand(symbolicateCmd)

	symbolicateCmd.Flags().BoolP("all", "a", false, "Show all threads in crashlog")
	symbolicateCmd.Flags().BoolP("running", "r", false, "Show all running (TH_RUN) threads in crashlog")
	symbolicateCmd.Flags().StringP("proc", "p", "", "Filter crashlog by process name")
	symbolicateCmd.Flags().BoolP("unslide", "u", false, "Unslide user-space addresses for static analysis (kernel frames are always unslid)")
	symbolicateCmd.Flags().String("kc-slide", "", "Apply custom KASLR slide to kernelcache frames for live debugging (hex, e.g. 0x14f74000)")
	symbolicateCmd.Flags().String("dsc-slide", "", "Rebase dyld_shared_cache frames onto this base for static analysis (hex, e.g. 0x180000000)")
	symbolicateCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	symbolicateCmd.Flags().Bool("hex", false, "Display function offsets in hexadecimal")
	symbolicateCmd.Flags().Bool("peek", false, "Show disassembly instructions around each panicked frame")
	symbolicateCmd.Flags().Int("peek-count", 5, "Number of instructions to show with --peek (centered on frame, respects function boundaries)")
	symbolicateCmd.Flags().StringP("server", "s", "", "Symbol Server DB URL")
	symbolicateCmd.Flags().Bool("force", false, "Force using the supplied IPSW even if it doesn't match the crashlog (e.g. for vPhone)")
	symbolicateCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	symbolicateCmd.Flags().String("signatures", "", "Path to signatures folder")
	symbolicateCmd.Flags().StringP("extra", "x", "", "Path to folder with extra files for symbolication")
	symbolicateCmd.Flags().Bool("ida", false, "Generate IDAPython script to mark panic frames in IDA Pro")
	// symbolicateCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	symbolicateCmd.MarkZshCompPositionalArgumentFile(2, "dyld_shared_cache*")
	viper.BindPFlag("symbolicate.all", symbolicateCmd.Flags().Lookup("all"))
	viper.BindPFlag("symbolicate.running", symbolicateCmd.Flags().Lookup("running"))
	viper.BindPFlag("symbolicate.proc", symbolicateCmd.Flags().Lookup("proc"))
	viper.BindPFlag("symbolicate.unslide", symbolicateCmd.Flags().Lookup("unslide"))
	viper.BindPFlag("symbolicate.kc-slide", symbolicateCmd.Flags().Lookup("kc-slide"))
	viper.BindPFlag("symbolicate.dsc-slide", symbolicateCmd.Flags().Lookup("dsc-slide"))
	viper.BindPFlag("symbolicate.demangle", symbolicateCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("symbolicate.hex", symbolicateCmd.Flags().Lookup("hex"))
	viper.BindPFlag("symbolicate.peek", symbolicateCmd.Flags().Lookup("peek"))
	viper.BindPFlag("symbolicate.peek-count", symbolicateCmd.Flags().Lookup("peek-count"))
	viper.BindPFlag("symbolicate.server", symbolicateCmd.Flags().Lookup("server"))
	viper.BindPFlag("symbolicate.force", symbolicateCmd.Flags().Lookup("force"))
	viper.BindPFlag("symbolicate.pem-db", symbolicateCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("symbolicate.signatures", symbolicateCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("symbolicate.extra", symbolicateCmd.Flags().Lookup("extra"))
	viper.BindPFlag("symbolicate.ida", symbolicateCmd.Flags().Lookup("ida"))
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

	# Symbolicate without an IPSW/DSC; falls back to the matching Xcode DeviceSupport DSC
	❯ ipsw symbolicate panic-full-2024-03-21-004704.000.ips
	  # Uses ~/Library/Developer/Xcode/<Platform> DeviceSupport/<device> (<build>)/Symbols
	  # (userspace frames only for panics; kernel frames still need an IPSW)

	# Show disassembly around panic frames with --peek (default 5 instructions)
	❯ ipsw symbolicate panic.ips firmware.ipsw --peek

	# Show more instructions around panic frames (10 instructions, centered on frame)
	❯ ipsw symbolicate panic.ips firmware.ipsw --peek --peek-count 10
	  # Note: If frame is at function start, extra instructions shift to after the frame

	# Unslide user-space addresses for static analysis (kernel frames are always unslid)
	❯ ipsw symbolicate panic.ips firmware.ipsw --unslide
	  # Note: Kernel frame addresses are already KASLR-unslid and match static disassemblers
	  # The --unslide flag only affects user-space frames (processes like launchd, SpringBoard, etc.)

	# Apply custom KASLR slide to kernelcache frames for lldb live debugging
	❯ ipsw symbolicate panic.ips firmware.ipsw --kc-slide 0x14f74000
	  # Useful when reproducing a crash with a different KASLR slide
	  # Shows runtime addresses you can use with lldb breakpoints

	# Rebase dyld_shared_cache frames onto a static base (e.g. to match Binary Ninja/IDA)
	❯ ipsw symbolicate crash.ips --dsc-slide 0x180000000
	  # Cache frames display as base + offset-into-cache so they line up with your disassembler
	  # (uses the report's sharedCache.base to compute the offset; pass 0 for raw cache offsets)

	# Combine both slides for full runtime address mapping
	❯ ipsw symbolicate panic.ips firmware.ipsw --kc-slide 0x14f74000 --dsc-slide 0x1a000000

	# Generate IDAPython script to mark panic frames in IDA Pro
	❯ ipsw symbolicate panic.ips firmware.ipsw --ida
	  # Outputs panic.ips.kc.ida.py for kernel frames (load in IDA with kernelcache)
	  # Outputs panic.ips.dsc.ida.py for DSC frames if present (load in IDA with DSC image)

	# Pretty print a crashlog (BugType=309) these are usually symbolicated by the OS
	❯ ipsw symbolicate --color Delta-2024-04-20-135807.ips

	# Summarize a JetsamEvent low-memory report (BugType=298): killed process, cause, and top memory consumers
	❯ ipsw symbolicate JetsamEvent-2026-06-14-150819.ips
	  # Add --all to list every process, or --proc <name> to filter to one

	# Summarize a Microstackshots resource report (BugType=145 SymptomsIO disk-writes, 202 CPU usage)
	❯ ipsw symbolicate analyticsd.diskwrites_resource-2025-07-24-160552.ips
	  # Shows the resource Event, the limit that was exceeded, and the heaviest stack
	  # Pass an IPSW/DSC (or rely on matching Xcode DeviceSupport) to symbolicate the stack:
	❯ ipsw symbolicate analyticsd.diskwrites_resource-2025-07-24-160552.ips iPhone17,1_26.0_23A5297m_Restore.ipsw

	# Symbolicate an old style crashlog (BugType=109) requiring a dyld_shared_cache
	❯ ipsw symbolicate Delta-2024-04-20-135807.ips dyld_shared_cache
	  ⨯ please supply a dyld_shared_cache for iPhone13,3 running 14.5 (18E5154f)`),
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		/* flags */
		all := viper.GetBool("symbolicate.all")
		running := viper.GetBool("symbolicate.running")
		proc := viper.GetString("symbolicate.proc")
		unslide := viper.GetBool("symbolicate.unslide")
		// cacheFile, _ := cmd.Flags().GetString("cache")
		demangleFlag := viper.GetBool("symbolicate.demangle")
		asHex := viper.GetBool("symbolicate.hex")
		peek := viper.GetBool("symbolicate.peek")
		peekCount := max(viper.GetInt("symbolicate.peek-count"), 1)
		pemDB := viper.GetString("symbolicate.pem-db")
		signaturesDir := viper.GetString("symbolicate.signatures")
		extrasDir := viper.GetString("symbolicate.extra")
		idaScript := viper.GetBool("symbolicate.ida")
		force := viper.GetBool("symbolicate.force")
		kcSlideStr := viper.GetString("symbolicate.kc-slide")
		dscSlideStr := viper.GetString("symbolicate.dsc-slide")
		/* parse slide values (base 0 auto-detects hex 0x, octal 0o, or decimal) */
		var kcSlide uint64
		if kcSlideStr != "" {
			var err error
			kcSlide, err = strconv.ParseUint(kcSlideStr, 0, 64)
			if err != nil {
				return fmt.Errorf("invalid --kc-slide value %q: must be a number (e.g., 0x14f74000 or 351748096): %v", kcSlideStr, err)
			}
		}
		var dscSlide uint64
		if dscSlideStr != "" {
			var err error
			dscSlide, err = strconv.ParseUint(dscSlideStr, 0, 64)
			if err != nil {
				return fmt.Errorf("invalid --dsc-slide value %q: must be a number (e.g., 0x1a000000 or 436207616): %v", dscSlideStr, err)
			}
		}
		/* validate flags */
		if (Verbose || all) && len(proc) > 0 {
			return fmt.Errorf("cannot use --verbose OR --all WITH --proc")
		}
		if unslide && (kcSlide != 0 || dscSlide != 0) {
			return fmt.Errorf("cannot use --unslide with --kc-slide or --dsc-slide (they are mutually exclusive)")
		}

		/* sysdiagnose archive or directory: browse every crash report inside */
		if isSysdiagnoseInput(args[0]) {
			var dscFile *dyld.File
			if len(args) > 1 { // an IPSW/DSC was supplied: symbolicate stacks against it
				f, cleanup, err := openDSCArg(filepath.Clean(args[1]), pemDB)
				if err != nil {
					return fmt.Errorf("failed to open %s: %v", filepath.Base(args[1]), err)
				}
				defer cleanup()
				dscFile = f
			}
			return browseSysdiagnose(args[0], &crashlog.Config{
				All:         all || Verbose,
				Running:     running,
				Process:     proc,
				Unslid:      unslide,
				KernelSlide: kcSlide,
				DSCSlide:    dscSlide,
				Demangle:    demangleFlag,
				Hex:         asHex,
				Verbose:     Verbose,
			}, dscFile)
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
		case "145", "202": // MICROSTACKSHOT RESOURCE REPORT (SymptomsIO disk-writes, CPU usage; text format)
			ms, err := crashlog.OpenMicrostackshot(args[0], &crashlog.Config{
				All:     all || Verbose,
				Process: proc,
				Verbose: Verbose,
			})
			if err != nil {
				return fmt.Errorf("failed to parse microstackshot report: %v", err)
			}
			if f, cleanup, err := openMicrostackshotDSC(args, ms, pemDB); err == nil {
				defer cleanup()
				ms.Symbolicate(f)
			} else {
				log.WithError(err).Warn("heaviest-stack symbolication unavailable; showing image+offset (supply an IPSW/DSC, or install matching Xcode DeviceSupport)")
			}
			fmt.Println(ms)
		case "298": // JETSAM EVENT (low-memory kill report; display only, nothing to symbolicate)
			ips, err := crashlog.OpenIPS(args[0], &crashlog.Config{
				All:     all || Verbose,
				Process: proc,
				Verbose: Verbose,
			})
			if err != nil {
				return fmt.Errorf("failed to parse JetsamEvent: %v", err)
			}
			fmt.Println(ips)
		case "183": // OTASUPDATE (software update/restore log; display only)
			ota, err := crashlog.OpenOTAUpdate(args[0], &crashlog.Config{All: all || Verbose, Verbose: Verbose})
			if err != nil {
				return fmt.Errorf("failed to parse OTAUpdate report: %v", err)
			}
			fmt.Println(ota)
		case "241": // AMT STREAMING STALL (CoreMedia HLS ABRTrace; deflate body, display only)
			ss, err := crashlog.OpenStreamStall(args[0], &crashlog.Config{Verbose: Verbose})
			if err != nil {
				return fmt.Errorf("failed to parse AMTStreamingStall report: %v", err)
			}
			fmt.Println(ss)
		case "210", "288", "308", "309": // NEW JSON STYLE CRASHLOG (308 = ExcUserFault)
			ips, err := crashlog.OpenIPS(args[0], &crashlog.Config{
				All:           all || Verbose,
				Running:       running,
				Process:       proc,
				Unslid:        unslide,
				KernelSlide:   kcSlide,
				DSCSlide:      dscSlide,
				Demangle:      demangleFlag,
				Hex:           asHex,
				Peek:          peek,
				PeekCount:     peekCount,
				PemDB:         pemDB,
				SignaturesDir: signaturesDir,
				ExtrasDir:     extrasDir,
				IDAScript:     idaScript,
				Verbose:       Verbose,
			})
			if err != nil {
				return fmt.Errorf("failed to parse IPS file: %v", err)
			}

			if len(args) < 2 && (hdr.BugType == "210" || hdr.BugType == "288") {
				// --peek and --signatures require an IPSW
				if peek {
					return fmt.Errorf("--peek requires an IPSW to show disassembly instructions")
				}
				if signaturesDir != "" {
					return fmt.Errorf("--signatures requires an IPSW to symbolicate")
				}
				if viper.GetString("symbolicate.server") != "" {
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
				} else if ds, err := xcode.FindDeviceSupport(ips.Payload.Product, ips.Header.Version(), ips.Header.Build()); err == nil {
					if len(ds.DSCs) > 0 {
						log.Infof("Using Xcode DeviceSupport DSC for %s", filepath.Base(ds.Dir))
						utils.Indent(log.Warn, 2)("userspace frames only (kernel frames need an IPSW)")
						if err := ips.Symbolicate210("", ds.DSCs, ""); err != nil {
							return err
						}
					} else {
						log.Infof("Using Xcode DeviceSupport dylibs for %s", filepath.Base(ds.Dir))
						utils.Indent(log.Warn, 2)("no DSC; userspace frames only (kernel frames need an IPSW)")
						if err := ips.Symbolicate210("", nil, ds.Symbols); err != nil {
							return err
						}
					}
				} else {
					log.WithError(err).Debug("no Xcode DeviceSupport dump found")
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
						if !force {
							return fmt.Errorf("supplied IPSW %s does NOT match crashlog: NEED %s; %s (%s), GOT %s; %s (%s) (use --force to override)",
								filepath.Base(args[1]),
								ips.Payload.Product, ips.Header.Version(), ips.Header.Build(),
								strings.Join(i.Plists.Restore.SupportedProductTypes, ", "),
								i.Plists.BuildManifest.ProductVersion, i.Plists.BuildManifest.ProductBuildVersion,
							)
						}
						log.Warnf("IPSW %s does not match crashlog (NEED %s; %s (%s), GOT %s; %s (%s)) - continuing anyway due to --force",
							filepath.Base(args[1]),
							ips.Payload.Product, ips.Header.Version(), ips.Header.Build(),
							strings.Join(i.Plists.Restore.SupportedProductTypes, ", "),
							i.Plists.BuildManifest.ProductVersion, i.Plists.BuildManifest.ProductBuildVersion,
						)
					}
					if err := ips.Symbolicate210(filepath.Clean(args[1]), nil, ""); err != nil {
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

			dscPath := ""
			if len(args) > 1 {
				dscPath = filepath.Clean(args[1])
			} else if ds, err := xcode.FindDeviceSupport(crashLog.HardwareModel, crashLog.OSVersion, crashLog.OSBuild); err == nil {
				if len(ds.DSCs) > 0 {
					dscPath = ds.DSCs[0]
					log.Infof("Using Xcode DeviceSupport DSC for %s", filepath.Base(ds.Dir))
					utils.Indent(log.Info, 2)("dsc=" + dscPath)
				} else {
					log.Warnf("Xcode DeviceSupport dump for %s has no dyld_shared_cache; loose-dylib symbolication for old-style (109) crashes is not yet supported", filepath.Base(ds.Dir))
				}
			} else {
				log.WithError(err).Debug("no Xcode DeviceSupport dump found")
			}

			if dscPath != "" {
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

				// guard the triggering-thread index (parsed from the report) before
				// indexing into Threads throughout this block
				if crashLog.CrashedThread < 0 || crashLog.CrashedThread >= len(crashLog.Threads) {
					return fmt.Errorf("crashlog triggering thread %d is out of range (have %d threads)", crashLog.CrashedThread, len(crashLog.Threads))
				}
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
					if symName, ok := f.AddressToSymbol.Get(unslidAddr); ok {
						if demangleFlag {
							symName = demangle.Do(symName, false, false)
						}
						crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = symName
						continue
					}

					if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
						if symName, ok := f.AddressToSymbol.Get(fn.StartAddr); ok {
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
						f.AddressToSymbol.Set(addr, patch.GetName())
					}

					if symName, ok := f.AddressToSymbol.Get(unslidAddr); ok {
						if demangleFlag {
							symName = demangle.Do(symName, false, false)
						}
						crashLog.Threads[crashLog.CrashedThread].BackTrace[idx].Symbol = symName
						continue
					}

					if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
						if symName, ok := f.AddressToSymbol.Get(fn.StartAddr); ok {
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

// isSysdiagnoseInput reports whether path is a directory or a tar(.gz) archive
// (a sysdiagnose) rather than a single .ips crash report.
func isSysdiagnoseInput(path string) bool {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return true
	}
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar")
}

// browseSysdiagnose collects every .ips crash report in a sysdiagnose archive or
// directory, renders each (symbolicating microstackshot stacks when dscFile is
// supplied), and presents them in an interactive browser.
func browseSysdiagnose(path string, conf *crashlog.Config, dscFile *dyld.File) error {
	files, cleanup, err := collectCrashlogs(path)
	if err != nil {
		return fmt.Errorf("failed to read sysdiagnose %s: %v", filepath.Base(path), err)
	}
	defer cleanup()
	if len(files) == 0 {
		return fmt.Errorf("no .ips crash reports found in %s", filepath.Base(path))
	}
	log.Infof("found %d crash report(s) in %s", len(files), filepath.Base(path))

	// Quiet per-report parser logs (e.g. the panic parser's missing-field
	// warnings) so they don't scroll past before the browser opens.
	if lgr, ok := log.Log.(*log.Logger); ok {
		prev := lgr.Level
		log.SetLevel(log.FatalLevel)
		defer log.SetLevel(prev)
	}

	items := make([]tui.CrashlogItem, 0, len(files))
	for _, fp := range files {
		hdr, herr := crashlog.ParseHeader(fp)
		name, when := filepath.Base(fp), ""
		if herr == nil {
			label := hdr.BugTypeDesc
			if label == "" {
				label = hdr.BugType
			}
			if hdr.Name != "" {
				label += " — " + hdr.Name
			}
			name = label
			when = hdr.Timestamp.Format("2006-01-02 15:04:05")
		}
		items = append(items, tui.CrashlogItem{
			Name:    name,
			Desc:    strings.TrimSpace(when + " • " + filepath.Base(fp)),
			Content: renderCrashlog(fp, conf, dscFile),
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	// Without an interactive terminal (piped, CI), print a plain index instead
	// of launching the browser.
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		var b strings.Builder
		for i, it := range items {
			fmt.Fprintf(&b, "%3d. %s\n     %s\n", i+1, it.Name, it.Desc)
		}
		fmt.Print(b.String())
		return nil
	}

	notice := ""
	if dscFile == nil && hasMicrostackshot(files) {
		notice = clNotice("No IPSW/DSC supplied",
			"Resource-report stacks are shown as image+offset.",
			"Pass an IPSW or dyld_shared_cache to symbolicate them:",
			"",
			"  ipsw symbolicate <sysdiagnose> <IPSW|DSC>",
			"",
			"press any key to continue")
	}
	return tui.RunCrashlogBrowser(items, notice)
}

// hasMicrostackshot reports whether any report is a microstackshot (145/202)
// whose stack would benefit from DSC symbolication.
func hasMicrostackshot(files []string) bool {
	for _, fp := range files {
		if hdr, err := crashlog.ParseHeader(fp); err == nil && (hdr.BugType == "145" || hdr.BugType == "202") {
			return true
		}
	}
	return false
}

// clNotice joins lines into the browser pop-up body.
func clNotice(title string, lines ...string) string {
	return strings.Join(append([]string{"💡  " + title, ""}, lines...), "\n")
}

// collectCrashlogs returns the paths of every .ips file in a directory or
// tar(.gz) archive (extracted to a temp dir) plus a cleanup func.
func collectCrashlogs(path string) ([]string, func(), error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		var ips []string
		_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".ips") {
				ips = append(ips, p)
			}
			return nil
		})
		return ips, func() {}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if lower := strings.ToLower(path); strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, nil, err
		}
		defer gz.Close()
		r = gz
	}

	tmp, err := os.MkdirTemp("", "ipsw-sysdiag-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(tmp) }
	var ips []string
	tr := tar.NewReader(r)
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		base := filepath.Base(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(base, ".ips") || strings.HasPrefix(base, "._") {
			continue // skip non-.ips and macOS AppleDouble (._*) companion files
		}
		// flatten with an index prefix so same-named reports in different dirs don't collide
		out := filepath.Join(tmp, fmt.Sprintf("%03d_%s", i, filepath.Base(hdr.Name)))
		of, err := os.Create(out)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		if _, err := io.Copy(of, tr); err != nil { //nolint:gosec // sysdiagnose .ips files are small text reports
			of.Close()
			cleanup()
			return nil, nil, err
		}
		of.Close()
		ips = append(ips, out)
	}
	return ips, cleanup, nil
}

// renderCrashlog parses and renders a single .ips report to display text for the
// browser. When dscFile is supplied, microstackshot (145/202) stacks are
// symbolicated against it (best effort — frames from a different build stay as
// image+offset).
func renderCrashlog(path string, conf *crashlog.Config, dscFile *dyld.File) string {
	hdr, err := crashlog.ParseHeader(path)
	if err != nil {
		return fmt.Sprintf("failed to parse %s: %v", filepath.Base(path), err)
	}
	switch hdr.BugType {
	case "145", "202":
		ms, err := crashlog.OpenMicrostackshot(path, conf)
		if err != nil {
			return fmt.Sprintf("failed to parse %s: %v", filepath.Base(path), err)
		}
		if dscFile != nil {
			ms.Symbolicate(dscFile)
		}
		return ms.String()
	case "210", "288", "298", "308", "309":
		ips, err := crashlog.OpenIPS(path, conf)
		if err != nil {
			return fmt.Sprintf("failed to parse %s: %v", filepath.Base(path), err)
		}
		return ips.String()
	case "109":
		cl, err := crashlog.Open(path)
		if err != nil {
			return fmt.Sprintf("failed to parse %s: %v", filepath.Base(path), err)
		}
		defer cl.Close()
		return cl.String()
	case "183":
		ota, err := crashlog.OpenOTAUpdate(path, conf)
		if err != nil {
			return fmt.Sprintf("failed to parse %s: %v", filepath.Base(path), err)
		}
		return ota.String()
	case "241":
		ss, err := crashlog.OpenStreamStall(path, conf)
		if err != nil {
			return fmt.Sprintf("failed to parse %s: %v", filepath.Base(path), err)
		}
		return ss.String()
	default:
		return fmt.Sprintf("%s - %s\n\n(crashlog type not yet supported for inline rendering)", hdr.BugType, hdr.BugTypeDesc)
	}
}

// openDSCArg opens a supplied dyld_shared_cache file, or an IPSW (extracting its
// DSC), into a *dyld.File with a cleanup func.
func openDSCArg(path, pemDB string) (*dyld.File, func(), error) {
	if f, err := dyld.Open(path); err == nil { // a dyld_shared_cache file
		return f, func() { f.Close() }, nil
	}
	if _, err := info.Parse(path); err != nil { // not an IPSW either
		return nil, nil, fmt.Errorf("could not open %s as a dyld_shared_cache or IPSW: %v", path, err)
	}
	ctx, fs, err := dsc.OpenFromIPSW(path, pemDB, false, true)
	if err != nil {
		return nil, nil, err
	}
	if len(fs) == 0 {
		ctx.Unmount()
		return nil, nil, fmt.Errorf("no dyld_shared_cache found in %s", path)
	}
	return fs[0], func() {
		for _, f := range fs {
			f.Close()
		}
		ctx.Unmount()
	}, nil
}

// openMicrostackshotDSC resolves a dyld_shared_cache for symbolicating a
// microstackshot's heaviest stack: a supplied DSC or IPSW (args[1]) takes
// precedence, otherwise it falls back to the matching Xcode DeviceSupport dump.
// Returns the cache, a cleanup func, and an error when no cache is available.
func openMicrostackshotDSC(args []string, ms *crashlog.Microstackshot, pemDB string) (*dyld.File, func(), error) {
	want := microstackshotCacheUUID(ms) // report's "Shared Cache:" UUID, if any

	if len(args) > 1 {
		f, cleanup, err := openDSCArg(filepath.Clean(args[1]), pemDB)
		if err != nil {
			return nil, nil, err
		}
		if want != "" && !strings.EqualFold(f.UUID.String(), want) {
			log.Warnf("supplied cache %s does not match the report's shared cache %s; symbols may be wrong", f.UUID.String(), want)
		}
		return f, cleanup, nil
	}

	ds, err := xcode.FindDeviceSupport(ms.HardwareModel, ms.Header.Version(), ms.Header.Build())
	if err != nil {
		return nil, nil, err
	}
	if len(ds.DSCs) == 0 {
		return nil, nil, fmt.Errorf("Xcode DeviceSupport for %s has no dyld_shared_cache (loose-dylib symbolication is not supported here)", filepath.Base(ds.Dir))
	}
	// DeviceSupport may carry multiple architectures; prefer the cache whose UUID
	// matches the report so image+offset doesn't resolve against the wrong cache.
	if want != "" {
		for _, p := range ds.DSCs {
			f, err := dyld.Open(p)
			if err != nil {
				continue
			}
			if strings.EqualFold(f.UUID.String(), want) {
				log.Infof("Using Xcode DeviceSupport DSC %s (matches report cache)", filepath.Base(p))
				return f, func() { f.Close() }, nil
			}
			f.Close()
		}
		log.Warnf("no Xcode DeviceSupport cache matches the report's shared cache %s; using %s (symbols may be wrong)", want, filepath.Base(ds.DSCs[0]))
	}
	log.Infof("Using Xcode DeviceSupport DSC for %s", filepath.Base(ds.Dir))
	f, err := dyld.Open(ds.DSCs[0])
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// microstackshotCacheUUID extracts the cache UUID from the report's
// "Shared Cache: <UUID> slid base address ..." line, uppercased.
func microstackshotCacheUUID(ms *crashlog.Microstackshot) string {
	if fields := strings.Fields(ms.SharedCache); len(fields) > 0 {
		return strings.ToUpper(fields[0])
	}
	return ""
}
