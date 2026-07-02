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
package kernel

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/blacktop/ipsw/pkg/kernelcache/pacx"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	kernelCppCmd.AddCommand(kernelCppPacxCmd)

	// Long-flags-only: the pacx mode intentionally avoids the -a/-e/-i/-l/-o/-c
	// shorthands bound by the parent `cpp` command.
	kernelCppPacxCmd.Flags().String("format", "json",
		"Comma-separated output formats: json,idapython,r2")
	kernelCppPacxCmd.Flags().String("output", ".",
		"Output directory for pacx.{json,py,r2}")
	kernelCppPacxCmd.Flags().String("arch", "",
		"Which architecture to use for fat/universal MachO")
	kernelCppPacxCmd.Flags().StringArray("entry", nil,
		"Only scan the specified bundle/entry (repeatable)")
	kernelCppPacxCmd.Flags().Bool("slots", false,
		"Include the full per-slot slots[] array in pacx.json (much larger output)")

	viper.BindPFlag("kernel.cpp.pacx.format", kernelCppPacxCmd.Flags().Lookup("format"))
	viper.BindPFlag("kernel.cpp.pacx.output", kernelCppPacxCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.cpp.pacx.arch", kernelCppPacxCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.cpp.pacx.entry", kernelCppPacxCmd.Flags().Lookup("entry"))
	viper.BindPFlag("kernel.cpp.pacx.slots", kernelCppPacxCmd.Flags().Lookup("slots"))
}

var kernelCppPacxCmd = &cobra.Command{
	Use:    "pacx <kernelcache>",
	Short:  "Emit an authenticated C++ vtable (offset, pac) xref index",
	Hidden: true,
	Example: heredoc.Doc(`
		# Emit pacx.json into the current directory
		❯ ipsw kernel cpp pacx kernelcache.release.iPhone17,1
		# Emit all formats into out/
		❯ ipsw kernel cpp pacx --format json,idapython,r2 --output out kernelcache.release.iPhone17,1`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		formats, err := parsePacxFormats(viper.GetString("kernel.cpp.pacx.format"))
		if err != nil {
			return err
		}
		outDir := viper.GetString("kernel.cpp.pacx.output")
		includeSlots := viper.GetBool("kernel.cpp.pacx.slots")

		m, err := mcmd.OpenMachO(filepath.Clean(args[0]), viper.GetString("kernel.cpp.pacx.arch"))
		if err != nil {
			return fmt.Errorf("open kernelcache: %w", err)
		}
		defer m.Close()

		scanner := cpp.NewScanner(m.File, cpp.Config{
			Entries: viper.GetStringSlice("kernel.cpp.pacx.entry"),
		})
		classes, err := scanner.Scan()
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		if len(classes) == 0 {
			log.Warn("no classes discovered")
			return nil
		}

		tables := scanner.BuildNamedMethodTables(classes)
		index := pacx.BuildIndex(buildPacxMeta(filepath.Base(args[0]), m.File), tables)

		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
		for _, format := range formats {
			path, err := writePacxFormat(index, outDir, format, includeSlots)
			if err != nil {
				return err
			}
			log.Infof("wrote %s", path)
		}
		return nil
	},
}

// parsePacxFormats splits and validates the comma-separated --format value.
func parsePacxFormats(raw string) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0, 3)
	for part := range strings.SplitSeq(raw, ",") {
		f := strings.ToLower(strings.TrimSpace(part))
		if f == "" {
			continue
		}
		switch f {
		case "json", "idapython", "r2":
		default:
			return nil, fmt.Errorf("unknown pacx format %q (want json, idapython, or r2)", f)
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no output formats requested")
	}
	return out, nil
}

// writePacxFormat writes one format's file into dir and returns its path.
func writePacxFormat(index *pacx.Index, dir, format string, includeSlots bool) (string, error) {
	var (
		name string
		emit func(io.Writer) error
	)
	switch format {
	case "json":
		name, emit = "pacx.json", func(w io.Writer) error { return index.WriteJSON(w, includeSlots) }
	case "idapython":
		name, emit = "pacx.py", index.WriteIDAPython
	case "r2":
		name, emit = "pacx.r2", index.WriteR2
	default:
		return "", fmt.Errorf("unknown pacx format %q", format)
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := emit(f); err != nil {
		return "", err
	}
	return path, nil
}

// buildPacxMeta collects the kernelcache metadata that anchors the index.
func buildPacxMeta(name string, m *macho.File) pacx.Meta {
	meta := pacx.Meta{
		Kernelcache: name,
		Arch:        m.CPU.String(),
		KernelBase:  m.GetBaseAddress(),
	}
	if u := m.UUID(); u != nil {
		meta.UUID = u.String()
	}
	if m.HasDyldChainedFixups() {
		if dcf, err := m.DyldChainedFixups(); err == nil && dcf != nil {
			meta.FixupFormat = dcf.PointerFormat.String()
		}
	}
	return meta
}
