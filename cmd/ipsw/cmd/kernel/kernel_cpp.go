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
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime/trace"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/fatih/color"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/profile"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	colorClass  = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorBundle = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorAddr   = color.New(color.Faint).SprintfFunc()
)

func init() {
	KernelcacheCmd.AddCommand(kernelCppCmd)

	kernelCppCmd.Flags().StringArrayP("entry", "e", nil,
		"Only scan the specified bundle/entry (repeatable)")
	kernelCppCmd.Flags().StringP("class", "c", "",
		"Only emit the specified class name")
	kernelCppCmd.Flags().BoolP("json", "j", false,
		"Output classes as JSON")
	kernelCppCmd.Flags().StringP("output", "o", "",
		"Write output to file")
	kernelCppCmd.Flags().StringP("arch", "a", "",
		"Which architecture to use for fat/universal MachO")
	kernelCppCmd.Flags().BoolP("inheritance", "i", false,
		"Show inheritance hierarchy")
	kernelCppCmd.Flags().IntP("limit", "l", 0,
		"Limit number of classes to display (0 = all)")

	// Profiling flags
	kernelCppCmd.Flags().String("cpuprofile", "",
		"Write CPU profile to file")
	kernelCppCmd.Flags().String("memprofile", "",
		"Write heap profile to file")
	kernelCppCmd.Flags().String("blockprofile", "",
		"Write block profile to file")
	kernelCppCmd.Flags().String("mutexprofile", "",
		"Write mutex profile to file")
	kernelCppCmd.Flags().String("trace", "",
		"Write runtime trace to file")
	kernelCppCmd.Flags().String("flightrecorder", "",
		"Write flight recorder trace to file")
	kernelCppCmd.Flags().String("pprof", "",
		"Serve net/http/pprof on address (e.g. localhost:6060)")
	kernelCppCmd.Flags().Bool("timings", false,
		"Print timing breakdown")

	kernelCppCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")

	viper.BindPFlag("kernel.cpp.entry", kernelCppCmd.Flags().Lookup("entry"))
	viper.BindPFlag("kernel.cpp.class", kernelCppCmd.Flags().Lookup("class"))
	viper.BindPFlag("kernel.cpp.json", kernelCppCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.cpp.output", kernelCppCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.cpp.arch", kernelCppCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.cpp.inheritance", kernelCppCmd.Flags().Lookup("inheritance"))
	viper.BindPFlag("kernel.cpp.limit", kernelCppCmd.Flags().Lookup("limit"))
	viper.BindPFlag("kernel.cpp.cpuprofile", kernelCppCmd.Flags().Lookup("cpuprofile"))
	viper.BindPFlag("kernel.cpp.memprofile", kernelCppCmd.Flags().Lookup("memprofile"))
	viper.BindPFlag("kernel.cpp.blockprofile", kernelCppCmd.Flags().Lookup("blockprofile"))
	viper.BindPFlag("kernel.cpp.mutexprofile", kernelCppCmd.Flags().Lookup("mutexprofile"))
	viper.BindPFlag("kernel.cpp.trace", kernelCppCmd.Flags().Lookup("trace"))
	viper.BindPFlag("kernel.cpp.flightrecorder", kernelCppCmd.Flags().Lookup("flightrecorder"))
	viper.BindPFlag("kernel.cpp.pprof", kernelCppCmd.Flags().Lookup("pprof"))
	viper.BindPFlag("kernel.cpp.timings", kernelCppCmd.Flags().Lookup("timings"))
}

var kernelCppCmd = &cobra.Command{
	Use:   "cpp <kernelcache>",
	Short: "Discover C++ classes from kernelcache",
	Example: heredoc.Doc(`
		# Discover all classes
		❯ ipsw kernel cpp kernelcache.release.iPhone17,1
		# Show specific class
		❯ ipsw kernel cpp -c IOService kernelcache.release.iPhone17,1
		# Scan only the kernel entry
		❯ ipsw kernel cpp -e com.apple.kernel kernelcache.release.iPhone17,1
		# JSON output
		❯ ipsw kernel cpp --json kernelcache.release.iPhone17,1
		# Show inheritance hierarchy
		❯ ipsw kernel cpp --inheritance kernelcache.release.iPhone17,1
		# Profile CPU usage
		❯ ipsw kernel cpp --cpuprofile cpu.prof kernelcache.release.iPhone17,1`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		selectedArch := viper.GetString("kernel.cpp.arch")
		outputPath := viper.GetString("kernel.cpp.output")
		asJSON := viper.GetBool("kernel.cpp.json")
		className := viper.GetString("kernel.cpp.class")
		showInheritance := viper.GetBool("kernel.cpp.inheritance")
		limit := viper.GetInt("kernel.cpp.limit")
		showTimings := viper.GetBool("kernel.cpp.timings") ||
			viper.GetBool("verbose")

		tStart := time.Now()

		// --- profiling setup ---
		if addr := viper.GetString("kernel.cpp.pprof"); addr != "" {
			go func() {
				log.Infof("pprof listening on http://%s", addr)
				_ = http.ListenAndServe(addr, nil)
			}()
		}
		prof := profile.New(profile.Config{
			CPUProfile: viper.GetString("kernel.cpp.cpuprofile"),
			MemProfile: viper.GetString("kernel.cpp.memprofile"),
			BlockProf:  viper.GetString("kernel.cpp.blockprofile"),
			MutexProf:  viper.GetString("kernel.cpp.mutexprofile"),
			TraceFile:  viper.GetString("kernel.cpp.trace"),
		})
		if err := prof.Start(); err != nil {
			return fmt.Errorf("profiling: %w", err)
		}
		defer prof.Stop()
		if p := viper.GetString("kernel.cpp.flightrecorder"); p != "" {
			fr := trace.NewFlightRecorder(trace.FlightRecorderConfig{
				MinAge:   15 * time.Second,
				MaxBytes: 10 << 20,
			})
			if err := fr.Start(); err != nil {
				log.Warnf("flight recorder: %v", err)
			} else {
				defer func() {
					fr.Stop()
					if f, err := os.Create(p); err == nil {
						_, _ = fr.WriteTo(f)
						f.Close()
					}
				}()
			}
		}

		// --- open kernelcache ---
		tOpen := time.Now()
		m, err := mcmd.OpenMachO(filepath.Clean(args[0]), selectedArch)
		if err != nil {
			return fmt.Errorf("open kernelcache: %w", err)
		}
		defer m.Close()
		durOpen := time.Since(tOpen)

		// --- scan ---
		tScan := time.Now()
		classes, err := cpp.NewScanner(m.File, cpp.Config{
			Entries:   viper.GetStringSlice("kernel.cpp.entry"),
			ClassName: scannerClassFilter(className, showInheritance),
			LogStats:  showTimings,
		}).Scan()
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		durScan := time.Since(tScan)

		display := filterClassesByName(classes, className)
		if len(display) == 0 {
			log.Warn("no classes discovered")
			return nil
		}

		// Build the full super index before limiting so inheritance
		// chains can resolve parents outside the visible set.
		superIndex := buildSuperIndex(classes)

		if limit > 0 && limit < len(display) {
			display = display[:limit]
		}

		// --- output ---
		tOut := time.Now()
		var (
			out     io.Writer
			outFile *os.File
		)
		if outputPath != "" {
			outFile, err = os.Create(outputPath)
			if err != nil {
				return fmt.Errorf("create output: %w", err)
			}
			defer outFile.Close()
			out = outFile
		} else {
			out = os.Stdout
		}

		if asJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(display); err != nil {
				return err
			}
		} else {
			for _, class := range display {
				fmt.Fprintln(out, formatClass(class))
				if showInheritance {
					printInheritance(out, classes, superIndex, class, 1)
				}
			}
		}
		durOut := time.Since(tOut)

		if showTimings {
			log.Infof("timings: open=%s scan=%s output=%s total=%s",
				durOpen, durScan, durOut, time.Since(tStart))
		}

		return nil
	},
}

func formatClass(c cpp.Class) string {
	var b strings.Builder
	fmt.Fprintf(&b, "init=%s", colorAddr("%#x", c.Ctor))
	fmt.Fprintf(&b, " size=%s", colorAddr("%#04x", c.Size))
	if c.SuperMeta != 0 {
		fmt.Fprintf(&b, " parent=%s", colorAddr("%#x", c.SuperMeta))
	}
	if c.MetaPtr != 0 {
		fmt.Fprintf(&b, " meta=%s", colorAddr("%#x", c.MetaPtr))
	}
	if c.MetaVtableAddr != 0 {
		fmt.Fprintf(&b, " metavtab=%s",
			colorAddr("%#x", c.MetaVtableAddr))
	}
	if c.VtableAddr != 0 {
		fmt.Fprintf(&b, " vtab=%s",
			colorAddr("%#x", c.VtableAddr))
	}
	fmt.Fprintf(&b, " %s", colorClass(c.Name))
	if c.Bundle != "" {
		fmt.Fprintf(&b, "\t(%s)", colorBundle(c.Bundle))
	}
	return b.String()
}

func scannerClassFilter(className string, showInheritance bool) string {
	if showInheritance && className != "" {
		return ""
	}
	return className
}

func filterClassesByName(classes []cpp.Class, className string) []cpp.Class {
	if className == "" {
		return classes
	}
	filtered := make([]cpp.Class, 0, 1)
	for _, class := range classes {
		if class.Name == className {
			filtered = append(filtered, class)
		}
	}
	return filtered
}

func buildSuperIndex(classes []cpp.Class) map[uint64]int {
	idx := make(map[uint64]int, len(classes))
	for i, c := range classes {
		if c.MetaPtr != 0 {
			idx[c.MetaPtr] = i
		}
	}
	return idx
}

func printInheritance(
	out io.Writer,
	classes []cpp.Class,
	superIndex map[uint64]int,
	class cpp.Class,
	depth int,
) {
	if class.SuperMeta == 0 {
		return
	}
	parentIdx, ok := superIndex[class.SuperMeta]
	if !ok {
		return
	}
	parent := classes[parentIdx]
	indent := strings.Repeat("  ", depth)
	extra := ""
	if parent.Bundle != "" && parent.Bundle != class.Bundle {
		extra = fmt.Sprintf(" (%s)", colorBundle(parent.Bundle))
	}
	fmt.Fprintf(out, "%s╰─ inherits from: %s%s\n",
		indent, colorClass(parent.Name), extra)
	printInheritance(out, classes, superIndex, parent, depth+1)
}
