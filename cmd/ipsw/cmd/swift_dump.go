/*
Copyright © 2026 blacktop

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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(swiftDumpCmd)

	swiftDumpCmd.Flags().Bool("all", false, "Dump ALL dylbs from DSC")
	swiftDumpCmd.Flags().Bool("deps", false, "Dump imported private frameworks as well")
	swiftDumpCmd.Flags().Bool("demangle", false, "Demangle symbol names")
	swiftDumpCmd.Flags().Bool("extra", false, "Dump all other Swift sections/info")
	swiftDumpCmd.Flags().BoolP("interface", "i", false, "🚧 Dump Swift Interface")
	swiftDumpCmd.Flags().StringP("output", "o", "", "🚧 Folder to write interface to")
	swiftDumpCmd.MarkFlagDirname("output")
	swiftDumpCmd.Flags().Bool("headers", false, "Create separate header files for each Swift type/protocol/extension")
	swiftDumpCmd.Flags().String("theme", "nord", "Color theme (nord, github, etc)")
	swiftDumpCmd.RegisterFlagCompletionFunc("theme", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return styles.Names(), cobra.ShellCompDirectiveNoFileComp
	})
	swiftDumpCmd.Flags().StringP("type", "y", "", "Dump type (regex)")
	swiftDumpCmd.Flags().StringP("proto", "p", "", "Dump protocol (regex)")
	swiftDumpCmd.Flags().StringP("ext", "e", "", "Dump extension (regex)")
	swiftDumpCmd.Flags().StringP("ass", "a", "", "Dump associated type (regex)")
	// swiftDumpCmd.Flags().Bool("re", false, "RE verbosity (with addresses)")
	swiftDumpCmd.Flags().String("arch", "", "Which architecture to use for fat/universal MachO")
	swiftDumpCmd.Flags().String("diff", "", "Structurally diff Swift against another DSC/MachO (same DYLIB)")
	swiftDumpCmd.MarkFlagFilename("diff")
	for _, other := range []string{"all", "deps", "extra", "interface", "output", "headers", "type", "proto", "ext", "ass"} {
		swiftDumpCmd.MarkFlagsMutuallyExclusive("diff", other)
	}

	viper.BindPFlag("swift-dump.all", swiftDumpCmd.Flags().Lookup("all"))
	viper.BindPFlag("swift-dump.deps", swiftDumpCmd.Flags().Lookup("deps"))
	viper.BindPFlag("swift-dump.demangle", swiftDumpCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("swift-dump.extra", swiftDumpCmd.Flags().Lookup("extra"))
	viper.BindPFlag("swift-dump.interface", swiftDumpCmd.Flags().Lookup("interface"))
	viper.BindPFlag("swift-dump.output", swiftDumpCmd.Flags().Lookup("output"))
	viper.BindPFlag("swift-dump.headers", swiftDumpCmd.Flags().Lookup("headers"))
	viper.BindPFlag("swift-dump.theme", swiftDumpCmd.Flags().Lookup("theme"))
	viper.BindPFlag("swift-dump.type", swiftDumpCmd.Flags().Lookup("type"))
	viper.BindPFlag("swift-dump.proto", swiftDumpCmd.Flags().Lookup("proto"))
	viper.BindPFlag("swift-dump.ext", swiftDumpCmd.Flags().Lookup("ext"))
	viper.BindPFlag("swift-dump.ass", swiftDumpCmd.Flags().Lookup("ass"))
	// viper.BindPFlag("swift-dump.re", swiftDumpCmd.Flags().Lookup("re"))
	viper.BindPFlag("swift-dump.arch", swiftDumpCmd.Flags().Lookup("arch"))
	viper.BindPFlag("swift-dump.diff", swiftDumpCmd.Flags().Lookup("diff"))
}

// openSwiftForDiff loads the Swift metadata of a standalone MachO, or of an
// in-cache dylib when path is a DSC. The returned func releases the backing file.
func openSwiftForDiff(path, dylib, arch string, conf *mcmd.SwiftConfig) (*mcmd.Swift, func(), error) {
	path = filepath.Clean(path)
	if ok, _ := magic.IsMachO(path); ok {
		mr, err := mcmd.OpenMachO(path, arch)
		if err != nil {
			return nil, nil, err
		}
		s, err := mcmd.NewSwift(mr.File, nil, conf)
		if err != nil {
			mr.Close()
			return nil, nil, err
		}
		return s, func() { mr.Close() }, nil
	}
	if dylib == "" {
		return nil, nil, fmt.Errorf("must provide an in-cache DYLIB to diff")
	}
	f, err := dyld.Open(path)
	if err != nil {
		return nil, nil, err
	}
	img, err := f.Image(dylib)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("failed to find dylib '%s' in DSC '%s': %v", dylib, filepath.Base(path), err)
	}
	m, err := img.GetMacho()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("failed to parse MachO from dylib '%s': %v", filepath.Base(img.Name), err)
	}
	img.ResolveLocalSymbolNames(m, conf.Demangle)
	s, err := mcmd.NewSwift(m, f, conf)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return s, func() { f.Close() }, nil
}

// runSwiftDumpDiff compares the Swift of args[0] (the newer build) against
// oldPath, using the same DYLIB (args[1]) for both when the inputs are DSCs.
func runSwiftDumpDiff(args []string, oldPath string, conf *mcmd.SwiftConfig) error {
	dylib := ""
	if len(args) > 1 {
		dylib = args[1]
	}
	arch := viper.GetString("swift-dump.arch")

	if dylib != "" {
		conf.Name = filepath.Base(dylib)
	} else {
		conf.Name = filepath.Base(args[0])
	}

	newSwift, closeNew, err := openSwiftForDiff(args[0], dylib, arch, conf)
	if err != nil {
		return fmt.Errorf("failed to load new target '%s': %w", filepath.Base(args[0]), err)
	}
	defer closeNew()

	oldSwift, closeOld, err := openSwiftForDiff(oldPath, dylib, arch, conf)
	if err != nil {
		return fmt.Errorf("failed to load --diff target '%s': %w", filepath.Base(oldPath), err)
	}
	defer closeOld()

	out, err := newSwift.Diff(oldSwift)
	if err != nil {
		return err
	}
	if conf.Color {
		return quick.Highlight(os.Stdout, out, "diff", "terminal256", conf.Theme)
	}
	fmt.Print(out)
	return nil
}

// swiftDumpCmd represents the swiftDump command
var swiftDumpCmd = &cobra.Command{
	Use:     "swift-dump [<DSC> <DYLIB>|<MACHO>]",
	Aliases: []string{"sd"},
	Short:   "🚧 Swift class-dump a dylib from a DSC or MachO",
	Example: heredoc.Doc(`
		# Swift-dump a dylib from a DSC
		❯ ipsw swift-dump <DSC> <DYLIB> --demangle
		# Swift-dump a standalone MachO binary
		❯ ipsw swift-dump <MACHO> --demangle
		# Structurally diff a dylib's Swift between two DSC versions (added/removed/changed)
		❯ ipsw swift-dump <NEW_DSC> <DYLIB> --diff <OLD_DSC> --demangle`),
	Args: cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		var s *mcmd.Swift

		// Validate Flags
		if viper.GetBool("swift-dump.interface") &&
			(viper.GetString("swift-dump.type") != "" ||
				viper.GetString("swift-dump.proto") != "" ||
				viper.GetString("swift-dump.ext") != "" ||
				viper.GetString("swift-dump.ass") != "") {
			return fmt.Errorf("cannot dump --interface and use --type, --protocol, --ext or --ass flags")
		} else if len(viper.GetString("swift-dump.output")) > 0 && !viper.GetBool("swift-dump.interface") && !viper.GetBool("swift-dump.headers") {
			return fmt.Errorf("cannot set --output without setting --interface or --headers")
		} else if viper.GetBool("swift-dump.headers") && len(viper.GetString("swift-dump.output")) == 0 {
			return fmt.Errorf("cannot set --headers without setting --output")
		}
		doDump := !viper.GetBool("swift-dump.interface") &&
			viper.GetString("swift-dump.type") == "" &&
			viper.GetString("swift-dump.proto") == "" &&
			viper.GetString("swift-dump.ext") == "" &&
			viper.GetString("swift-dump.ass") == ""

		if len(viper.GetString("swift-dump.output")) > 0 {
			if err := os.MkdirAll(viper.GetString("swift-dump.output"), 0o750); err != nil {
				return err
			}
		}

		doDemangle := viper.GetBool("swift-dump.demangle")

		// Auto-enable demangle and interface when headers is specified
		if viper.GetBool("swift-dump.headers") {
			doDemangle = true
			viper.Set("swift-dump.interface", true)
		}

		conf := mcmd.SwiftConfig{
			Verbose: Verbose,
			// Addrs:       viper.GetBool("swift-dump.re"),
			All:         viper.GetBool("swift-dump.extra"),
			Interface:   viper.GetBool("swift-dump.interface"),
			Deps:        viper.GetBool("swift-dump.deps"),
			Demangle:    doDemangle,
			IpswVersion: fmt.Sprintf("Version: %s, BuildCommit: %s", strings.TrimSpace(AppVersion), strings.TrimSpace(AppBuildCommit)),
			Color:       utils.ColorEnabled(),
			Theme:       viper.GetString("swift-dump.theme"),
			Output:      viper.GetString("swift-dump.output"),
			Headers:     viper.GetBool("swift-dump.headers"),
		}

		if oldPath := viper.GetString("swift-dump.diff"); oldPath != "" {
			return runSwiftDumpDiff(args, oldPath, &conf)
		}

		if ok, _ := magic.IsMachO(args[0]); ok { /* MachO binary */
			machoPath := filepath.Clean(args[0])
			mr, err := mcmd.OpenMachO(machoPath, viper.GetString("swift-dump.arch"))
			if err != nil {
				return err
			}
			defer mr.Close()
			m = mr.File
			if viper.GetBool("swift-dump.deps") {
				log.Error("cannot dump imported private frameworks from a MachO file (only from a DSC)")
			}

			conf.Name = filepath.Base(machoPath)

			s, err = mcmd.NewSwift(m, nil, &conf)
			if err != nil {
				return err
			}

			if viper.GetBool("swift-dump.interface") {
				return s.Interface()
			}

			if viper.GetString("swift-dump.type") != "" {
				if err := s.DumpType(viper.GetString("swift-dump.type")); err != nil {
					return fmt.Errorf("failed to dump type: %v", err)
				}
			}

			if viper.GetString("swift-dump.proto") != "" {
				if err := s.DumpProtocol(viper.GetString("swift-dump.proto")); err != nil {
					return fmt.Errorf("failed to dump protocol: %v", err)
				}
			}

			if viper.GetString("swift-dump.ext") != "" {
				if err := s.DumpExtension(viper.GetString("swift-dump.ext")); err != nil {
					return fmt.Errorf("failed to dump extension: %v", err)
				}
			}

			if viper.GetString("swift-dump.ass") != "" {
				if err := s.DumpAssociatedType(viper.GetString("swift-dump.ass")); err != nil {
					return fmt.Errorf("failed to dump associated type: %v", err)
				}
			}

			if viper.GetBool("swift-dump.headers") {
				return s.WriteHeaders()
			}

			if doDump {
				return s.Dump()
			}
		} else { /* DSC file */
			if len(args) < 2 && !viper.GetBool("swift-dump.all") {
				return fmt.Errorf("must provide an in-cache DYLIB to dump")
			}

			var images []*dyld.CacheImage

			f, err := dyld.Open(filepath.Clean(args[0]))
			if err != nil {
				return err
			}
			defer f.Close()

			if viper.GetBool("swift-dump.all") {
				images = f.Images
			} else {
				img, err := f.Image(args[1])
				if err != nil {
					return fmt.Errorf("failed to find dylib '%s' in DSC: %v", args[1], err)
				}
				images = append(images, img)
			}

			for _, image := range images {
				m, err = image.GetMacho()
				if err != nil {
					return fmt.Errorf("failed to parse MachO from dylib '%s': %v", filepath.Base(image.Name), err)
				}

				image.ResolveLocalSymbolNames(m, doDemangle)

				conf.Name = filepath.Base(image.Name)

				s, err = mcmd.NewSwift(m, f, &conf)
				if err != nil {
					if errors.Is(err, mcmd.ErrNoSwift) {
						if !viper.GetBool("swift-dump.all") {
							log.Warnf("Skipping dylib '%s': no swift metadata", filepath.Base(image.Name))
						}
						continue
					}

					return err
				}

				if viper.GetBool("swift-dump.interface") {
					if err := s.Interface(); err != nil {
						return err
					}
				}

				if viper.GetString("swift-dump.type") != "" {
					if err := s.DumpType(viper.GetString("swift-dump.type")); err != nil {
						if errors.Is(err, mcmd.ErrNoSwift) {
							if !viper.GetBool("swift-dump.all") {
								log.Warnf("Skipping dylib '%s': no swift metadata", filepath.Base(image.Name))
							}
							continue
						}
						return err
					}
				}

				if viper.GetString("swift-dump.proto") != "" {
					if err := s.DumpProtocol(viper.GetString("swift-dump.proto")); err != nil {
						if errors.Is(err, mcmd.ErrNoSwift) {
							if !viper.GetBool("swift-dump.all") {
								log.Warnf("Skipping dylib '%s': no swift metadata", filepath.Base(image.Name))
							}
							continue
						}
						return err
					}
				}

				if viper.GetString("swift-dump.ext") != "" {
					if err := s.DumpExtension(viper.GetString("swift-dump.ext")); err != nil {
						if errors.Is(err, mcmd.ErrNoSwift) {
							if !viper.GetBool("swift-dump.all") {
								log.Warnf("Skipping dylib '%s': no swift metadata", filepath.Base(image.Name))
							}
							continue
						}
						return err
					}
				}

				if viper.GetString("swift-dump.ass") != "" {
					if err := s.DumpAssociatedType(viper.GetString("swift-dump.ass")); err != nil {
						if errors.Is(err, mcmd.ErrNoSwift) {
							if !viper.GetBool("swift-dump.all") {
								log.Warnf("Skipping dylib '%s': no swift metadata", filepath.Base(image.Name))
							}
							continue
						}
						return err
					}
				}

				if viper.GetBool("swift-dump.headers") {
					if err := s.WriteHeaders(); err != nil {
						return err
					}
				}

				if doDump {
					if err := s.Dump(); err != nil {
						if errors.Is(err, mcmd.ErrNoSwift) {
							if !viper.GetBool("swift-dump.all") {
								log.Warnf("Skipping dylib '%s': no swift metadata", filepath.Base(image.Name))
							}
							continue
						}

						return fmt.Errorf("failed to dump Swift info for dylib '%s': %v", filepath.Base(image.Name), err)
					}
				}
			}
		}

		return nil
	},
}
