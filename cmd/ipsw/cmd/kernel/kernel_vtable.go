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
package kernel

import (
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(vtableCmd)

	vtableCmd.Flags().StringP("class", "c", "", "Show vtable for specific class")
	vtableCmd.Flags().BoolP("methods", "m", false, "Show method details for each class")
	vtableCmd.Flags().BoolP("inheritance", "i", false, "Show inheritance hierarchy")
	vtableCmd.Flags().IntP("limit", "l", 0, "Limit number of classes to display (0 = all)")
	vtableCmd.Flags().Uint("max", 1000, "Max instructions to emulate per constructor")
	vtableCmd.Flags().StringSliceP("entry", "e", []string{}, "Only scan specified fileset entries (e.g., com.apple.kernel)")
	vtableCmd.Flags().BoolP("json", "j", false, "Output as JSON")

	viper.BindPFlag("kernel.vtable.class", vtableCmd.Flags().Lookup("class"))
	viper.BindPFlag("kernel.vtable.methods", vtableCmd.Flags().Lookup("methods"))
	viper.BindPFlag("kernel.vtable.inheritance", vtableCmd.Flags().Lookup("inheritance"))
	viper.BindPFlag("kernel.vtable.limit", vtableCmd.Flags().Lookup("limit"))
	viper.BindPFlag("kernel.vtable.max", vtableCmd.Flags().Lookup("max"))
	viper.BindPFlag("kernel.vtable.entry", vtableCmd.Flags().Lookup("entry"))
	viper.BindPFlag("kernel.vtable.json", vtableCmd.Flags().Lookup("json"))

	// Profiling flags
	vtableCmd.Flags().String("cpuprofile", "", "Write CPU profile to file")
	vtableCmd.Flags().String("memprofile", "", "Write heap profile to file")
	vtableCmd.Flags().String("blockprofile", "", "Write block profile to file (enables block profiling)")
	vtableCmd.Flags().String("mutexprofile", "", "Write mutex profile to file (enables mutex profiling)")
	vtableCmd.Flags().String("trace", "", "Write runtime trace to file")
	vtableCmd.Flags().String("flightrecorder", "", "Write flight recorder trace to file (Go 1.25+)")
	vtableCmd.Flags().String("pprof", "", "Serve net/http/pprof on address (e.g. localhost:6060)")
	vtableCmd.Flags().Bool("timings", false, "Print timing breakdown for major phases")
	viper.BindPFlag("kernel.vtable.cpuprofile", vtableCmd.Flags().Lookup("cpuprofile"))
	viper.BindPFlag("kernel.vtable.memprofile", vtableCmd.Flags().Lookup("memprofile"))
	viper.BindPFlag("kernel.vtable.blockprofile", vtableCmd.Flags().Lookup("blockprofile"))
	viper.BindPFlag("kernel.vtable.mutexprofile", vtableCmd.Flags().Lookup("mutexprofile"))
	viper.BindPFlag("kernel.vtable.trace", vtableCmd.Flags().Lookup("trace"))
	viper.BindPFlag("kernel.vtable.flightrecorder", vtableCmd.Flags().Lookup("flightrecorder"))
	viper.BindPFlag("kernel.vtable.pprof", vtableCmd.Flags().Lookup("pprof"))
	viper.BindPFlag("kernel.vtable.timings", vtableCmd.Flags().Lookup("timings"))
}

// vtableCmd represents the vtable command
var vtableCmd = &cobra.Command{
	Use:   "vtable <kernelcache>",
	Short: "Extract and symbolicate C++ vtables from kernelcache",
	Example: heredoc.Doc(`
		# Basic vtable extraction
		❯ ipsw kernel vtable kernelcache.release.iPhone17,1
		# Show vtable for specific class
		❯ ipsw kernel vtable -c IOService kernelcache.release.iPhone17,1
		# Show method details and inheritance
		❯ ipsw kernel vtable --methods --inheritance kernelcache.release.iPhone17,1
		# Limit number of classes displayed
		❯ ipsw kernel vtable --limit 10 kernelcache.release.iPhone17,1
		# JSON output for scripting
		❯ ipsw kernel vtable --json kernelcache.release.iPhone17,1`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		className := viper.GetString("kernel.vtable.class")
		showMethods := viper.GetBool("kernel.vtable.methods")
		showInheritance := viper.GetBool("kernel.vtable.inheritance")
		entries := viper.GetStringSlice("kernel.vtable.entry")
		asJSON := viper.GetBool("kernel.vtable.json")
		maxInstructions := viper.GetUint("kernel.vtable.max")

		tStart := time.Now()

		// Optional net/http/pprof server
		if addr := viper.GetString("kernel.vtable.pprof"); addr != "" {
			go func() {
				log.Infof("pprof listening on http://%s", addr)
				_ = http.ListenAndServe(addr, nil)
			}()
		}

		// Profiles setup
		if cpup := viper.GetString("kernel.vtable.cpuprofile"); cpup != "" {
			f, err := os.Create(cpup)
			if err != nil {
				return fmt.Errorf("create cpuprofile: %w", err)
			}
			if err := pprof.StartCPUProfile(f); err != nil {
				f.Close()
				return fmt.Errorf("start cpu profile: %w", err)
			}
			defer func() {
				pprof.StopCPUProfile()
				f.Close()
			}()
		}
		if bp := viper.GetString("kernel.vtable.blockprofile"); bp != "" {
			runtime.SetBlockProfileRate(1)
			defer writeProfile("block", bp)
		}
		if mp := viper.GetString("kernel.vtable.mutexprofile"); mp != "" {
			runtime.SetMutexProfileFraction(1)
			defer writeProfile("mutex", mp)
		}
		var traceFile *os.File
		if tp := viper.GetString("kernel.vtable.trace"); tp != "" {
			f, err := os.Create(tp)
			if err != nil {
				return fmt.Errorf("create trace: %w", err)
			}
			if err := trace.Start(f); err != nil {
				f.Close()
				return fmt.Errorf("start trace: %w", err)
			}
			traceFile = f
			defer func() { trace.Stop(); traceFile.Close() }()
		}

		// Flight recorder (Go 1.25+) - continuous low-overhead profiling
		var flightRecorder *trace.FlightRecorder
		if frPath := viper.GetString("kernel.vtable.flightrecorder"); frPath != "" {
			cfg := trace.FlightRecorderConfig{
				MinAge:   15 * time.Second, // Keep last 15 seconds
				MaxBytes: 10 << 20,         // 10MB ring buffer
			}
			flightRecorder = trace.NewFlightRecorder(cfg)
			if err := flightRecorder.Start(); err != nil {
				log.Warnf("Failed to start flight recorder: %v", err)
			} else {
				defer func() {
					flightRecorder.Stop()
					if f, err := os.Create(frPath); err == nil {
						if _, err := flightRecorder.WriteTo(f); err != nil {
							log.Warnf("Failed to write flight recorder trace: %v", err)
						}
						f.Close()
						log.Infof("Flight recorder trace written to %s", frPath)
					} else {
						log.Warnf("Failed to create flight recorder file: %v", err)
					}
				}()
			}
		}

		tOpenStart := time.Now()
		m, err := macho.Open(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to open kernelcache: %v", err)
		}
		defer m.Close()
		tOpen := time.Since(tOpenStart)

		tGCStart := time.Now()

		// Create engine and run class discovery
		cppEngine := cpp.Create(m, &cpp.Config{
			ClassName:              className,
			WithMethods:            showMethods,
			Entries:                entries,
			MaxCtorInstructions:    int(maxInstructions),
			DisableStubResolution:  true,  // Skip unused stub resolution (saves ~29s CPU time on full scans)
			UseXrefAnchorDiscovery: false, // Function reordering (Phase 1) is faster than xref-based (Phase 2)
		})
		cls, err := cppEngine.GetClasses()
		if err != nil {
			return fmt.Errorf("failed to get classes from kernelcache: %v", err)
		}

		// Sort classes by Ctor field
		sort.Slice(cls, func(i, j int) bool {
			return cls[i].Ctor < cls[j].Ctor
		})

		tGetClasses := time.Since(tGCStart)

		// Get detailed phase timings
		phaseTimings := cppEngine.GetPhaseTimings()

		if len(cls) == 0 {
			log.Warn("No classes discovered")
			return nil
		}

		// Filter by specific class if requested
		if className != "" {
			filtered := make([]cpp.Class, 0, 1)
			for _, class := range cls {
				if strings.Contains(class.Name, className) {
					filtered = append(filtered, class)
				}
			}
			if len(filtered) == 0 {
				return fmt.Errorf("class containing '%s' not found", className)
			}
			cls = filtered
		}

		// Apply limit if specified
		if limit := viper.GetInt("kernel.vtable.limit"); limit > 0 && limit < len(cls) {
			cls = cls[:limit]
		}

		// Output results
		tOutStart := time.Now()
		if asJSON {
			data, err := json.Marshal(cls)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			tPrint := time.Since(tOutStart)
			if viper.GetBool("kernel.vtable.timings") || viper.GetBool("verbose") {
				log.Infof("timings: open=%s getClasses=%s output=%s total=%s", tOpen, tGetClasses, tPrint, time.Since(tStart))
				log.Infof("  └─ getClasses breakdown:")
				log.Infof("     anchor=%s fileset=%s discovery=%s dedupe=%s vtable=%s osobj=%s linking=%s",
					phaseTimings.Anchor, phaseTimings.FilesetPrep, phaseTimings.Discovery,
					phaseTimings.Dedupe, phaseTimings.Vtable, phaseTimings.OSObject, phaseTimings.Linking)
				if phaseTimings.XrefScan > 0 || phaseTimings.CtorEmulation > 0 {
					log.Infof("     └─ discovery detail: xref=%s emu=%s",
						phaseTimings.XrefScan, phaseTimings.CtorEmulation)
				}
			}
			// Heap profile at the end, if requested
			if hp := viper.GetString("kernel.vtable.memprofile"); hp != "" {
				if err := writeHeapProfile(hp); err != nil {
					return err
				}
			}
			return nil
		}

		fmt.Printf("\nDiscovered %d C++ classes:\n\n", len(cls))
		for _, class := range cls {
			fmt.Println(class.String())
			// Show inheritance hierarchy if requested
			if showInheritance && class.SuperClass != nil {
				printInheritanceChain(&class, 1)
			}
			// Show vtable and methods if requested
			if showMethods && class.VtableAddr != 0 {
				for _, method := range class.Methods {
					fmt.Printf("  %s\n", method.String())
				}
			}
		}
		tPrint := time.Since(tOutStart)
		if viper.GetBool("kernel.vtable.timings") || viper.GetBool("verbose") {
			log.Infof("timings: open=%s getClasses=%s output=%s total=%s", tOpen, tGetClasses, tPrint, time.Since(tStart))
			log.Infof("  └─ getClasses breakdown:")
			log.Infof("     anchor=%s fileset=%s discovery=%s dedupe=%s vtable=%s osobj=%s linking=%s",
				phaseTimings.Anchor, phaseTimings.FilesetPrep, phaseTimings.Discovery,
				phaseTimings.Dedupe, phaseTimings.Vtable, phaseTimings.OSObject, phaseTimings.Linking)
			if phaseTimings.XrefScan > 0 || phaseTimings.CtorEmulation > 0 {
				log.Infof("     └─ discovery detail: xref=%s emu=%s",
					phaseTimings.XrefScan, phaseTimings.CtorEmulation)
			}
		}
		if hp := viper.GetString("kernel.vtable.memprofile"); hp != "" {
			if err := writeHeapProfile(hp); err != nil {
				return err
			}
		}

		return nil
	},
}

// printInheritanceChain recursively prints the inheritance hierarchy
func printInheritanceChain(class *cpp.Class, depth int) {
	if class.SuperClass == nil {
		return
	}
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s╰─ inherits from: %s", indent, class.SuperClass.Name)
	if class.SuperClass.Bundle != "" && class.SuperClass.Bundle != class.Bundle {
		fmt.Printf(" (%s)", class.SuperClass.Bundle)
	}
	fmt.Println()
	printInheritanceChain(class.SuperClass, depth+1)
}

// writeHeapProfile writes a heap profile to the given filepath.
func writeHeapProfile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create memprofile: %w", err)
	}
	defer f.Close()
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("write heap profile: %w", err)
	}
	return nil
}

// writeProfile writes a pprof profile by name (block/mutex) to path.
func writeProfile(name, path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Errorf("create %s profile failed: %v", name, err)
		return
	}
	defer f.Close()
	if prof := pprof.Lookup(name); prof != nil {
		_ = prof.WriteTo(f, 0)
	}
}
