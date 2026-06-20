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
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getImages(dscPath string) []string {
	if ok, _ := magic.IsMachO(dscPath); ok {
		return nil
	}
	var images []string
	if f, err := dyld.Open(dscPath); err == nil {
		defer f.Close()
		for _, image := range f.Images {
			images = append(images, filepath.Base(image.Name))
		}
	}
	return images
}

// dscExtractedHint augments errors from class-dumping a standalone MachO. A dylib
// extracted from a dyld_shared_cache keeps relative ObjC method lists whose
// selectors are offsets into the cache's shared selector-string table; that table
// isn't present in a standalone file, so the method names can't be resolved.
// Point the user at the in-cache path, which resolves everything.
func dscExtractedHint(err error, m *macho.File, machoPath string) error {
	if err == nil {
		return nil
	}
	// The sentinel is obscured by %v wraps deeper in the ObjC parse chain, so the
	// File flag is the reliable signal; errors.Is covers a clean propagation.
	if !errors.Is(err, macho.ErrObjCSelectorBaseUnavailable) && (m == nil || !m.ObjCSelectorBaseUnavailable()) {
		return err
	}
	return fmt.Errorf("%q looks like a dylib extracted from a dyld_shared_cache: its ObjC method "+
		"selectors reference the cache's shared selector table, which is unavailable in a standalone "+
		"file.\n\tClass-dump directly from the cache instead: ipsw class-dump <DSC> %s",
		machoPath, filepath.Base(machoPath))
}

func init() {
	rootCmd.AddCommand(classDumpCmd)

	classDumpCmd.Flags().Bool("all", false, "Dump ALL dylbs from DSC")
	classDumpCmd.Flags().Bool("deps", false, "Dump imported private frameworks as well")
	classDumpCmd.Flags().BoolP("xcfw", "x", false, "🚧 Generate a XCFramework for the dylib")
	// classDumpCmd.Flags().BoolP("generic", "g", false, "🚧 Generate a XCFramework for ALL targets")
	classDumpCmd.Flags().BoolP("spm", "s", false, "🚧 Generate a Swift Package for the dylib")
	classDumpCmd.Flags().Bool("demangle", false, "Demangle symbol names (same as verbose)")
	classDumpCmd.Flags().Bool("headers", false, "Dump ObjC headers")
	classDumpCmd.Flags().StringP("output", "o", "", "Folder to write headers to")
	classDumpCmd.MarkFlagDirname("output")
	classDumpCmd.Flags().String("theme", "nord", "Color theme (nord, github, etc)")
	classDumpCmd.RegisterFlagCompletionFunc("theme", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return styles.Names(), cobra.ShellCompDirectiveNoFileComp
	})
	classDumpCmd.Flags().StringP("class", "c", "", "Dump class (regex)")
	classDumpCmd.Flags().StringP("proto", "p", "", "Dump protocol (regex)")
	classDumpCmd.Flags().StringP("cat", "a", "", "Dump category (regex)")
	classDumpCmd.Flags().Bool("refs", false, "Dump ObjC references too")
	classDumpCmd.Flags().Bool("re", false, "RE verbosity (with addresses)")
	classDumpCmd.Flags().String("arch", "", "Which architecture to use for fat/universal MachO")
	classDumpCmd.Flags().String("diff", "", "Structurally diff ObjC against another DSC/MachO (same DYLIB)")
	classDumpCmd.MarkFlagFilename("diff")
	classDumpCmd.MarkFlagsMutuallyExclusive("diff", "headers", "xcfw", "spm")

	viper.BindPFlag("class-dump.all", classDumpCmd.Flags().Lookup("all"))
	viper.BindPFlag("class-dump.deps", classDumpCmd.Flags().Lookup("deps"))
	viper.BindPFlag("class-dump.xcfw", classDumpCmd.Flags().Lookup("xcfw"))
	// viper.BindPFlag("class-dump.generic", classDumpCmd.Flags().Lookup("generic"))
	viper.BindPFlag("class-dump.spm", classDumpCmd.Flags().Lookup("spm"))
	viper.BindPFlag("class-dump.demangle", classDumpCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("class-dump.headers", classDumpCmd.Flags().Lookup("headers"))
	viper.BindPFlag("class-dump.output", classDumpCmd.Flags().Lookup("output"))
	viper.BindPFlag("class-dump.class", classDumpCmd.Flags().Lookup("class"))
	viper.BindPFlag("class-dump.proto", classDumpCmd.Flags().Lookup("proto"))
	viper.BindPFlag("class-dump.cat", classDumpCmd.Flags().Lookup("cat"))
	viper.BindPFlag("class-dump.theme", classDumpCmd.Flags().Lookup("theme"))
	viper.BindPFlag("class-dump.refs", classDumpCmd.Flags().Lookup("refs"))
	viper.BindPFlag("class-dump.re", classDumpCmd.Flags().Lookup("re"))
	viper.BindPFlag("class-dump.arch", classDumpCmd.Flags().Lookup("arch"))
	viper.BindPFlag("class-dump.diff", classDumpCmd.Flags().Lookup("diff"))
}

// openObjCForDiff opens path (an in-cache DYLIB selected from a DSC, or a MachO)
// and returns an ObjC parser plus a closer for the underlying file(s).
func openObjCForDiff(path, dylib, arch string, conf *mcmd.ObjcConfig) (*mcmd.ObjC, func(), error) {
	if ok, _ := magic.IsMachO(path); ok {
		mr, err := mcmd.OpenMachO(path, arch)
		if err != nil {
			return nil, nil, err
		}
		o, err := mcmd.NewObjC(mr.File, nil, conf)
		if err != nil {
			mr.Close()
			return nil, nil, err
		}
		return o, func() { mr.Close() }, nil
	}
	if dylib == "" {
		return nil, nil, fmt.Errorf("must provide an in-cache DYLIB to diff")
	}
	f, err := dyld.Open(filepath.Clean(path))
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
	o, err := mcmd.NewObjC(m, f, conf)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return o, func() { f.Close() }, nil
}

// runClassDumpDiff compares the ObjC of args[0] (the newer build) against
// oldPath, using the same DYLIB (args[1]) for both when the inputs are DSCs.
func runClassDumpDiff(args []string, oldPath string, conf *mcmd.ObjcConfig) error {
	if viper.GetBool("class-dump.all") {
		return fmt.Errorf("--diff cannot be combined with --all (diff one DYLIB at a time)")
	}
	if viper.GetString("class-dump.class") != "" || viper.GetString("class-dump.proto") != "" || viper.GetString("class-dump.cat") != "" {
		return fmt.Errorf("--diff cannot be combined with --class/--proto/--cat (it diffs the whole dylib)")
	}
	dylib := ""
	if len(args) > 1 {
		dylib = args[1]
	}
	arch := viper.GetString("class-dump.arch")

	// conf.Name is set later in RunE for the normal dump paths; populate it here
	// so the diff header reports the dylib/MachO being compared.
	if dylib != "" {
		conf.Name = filepath.Base(dylib)
	} else {
		conf.Name = filepath.Base(args[0])
	}

	newObjc, closeNew, err := openObjCForDiff(args[0], dylib, arch, conf)
	if err != nil {
		return fmt.Errorf("failed to load new target '%s': %w", filepath.Base(args[0]), err)
	}
	defer closeNew()

	oldObjc, closeOld, err := openObjCForDiff(oldPath, dylib, arch, conf)
	if err != nil {
		return fmt.Errorf("failed to load --diff target '%s': %w", filepath.Base(oldPath), err)
	}
	defer closeOld()

	out, err := newObjc.Diff(oldObjc)
	if err != nil {
		return err
	}
	if conf.Color {
		// Syntax-highlight the ```diff body for the terminal (same approach as
		// internal/utils/git.go); without --color the raw fenced markdown prints.
		return quick.Highlight(os.Stdout, out, "diff", "terminal256", conf.Theme)
	}
	fmt.Print(out)
	return nil
}

// classDumpCmd represents the classDump command
var classDumpCmd = &cobra.Command{
	// TODO: is this too much magic? (should we be explicit about what the input is?)
	Use:     "class-dump [<DSC> <DYLIB>|<MACHO>]",
	Aliases: []string{"cd"},
	Short:   "ObjC class-dump a dylib from a DSC or MachO",
	Example: heredoc.Doc(`
		# Class-dump a dylib from a DSC
		❯ ipsw class-dump <DSC> /System/Library/Frameworks/Foundation.framework/Foundation
		# Class-dump a standalone MachO binary
		❯ ipsw class-dump <MACHO>
		# Dump a single class (regex) with RE addresses
		❯ ipsw class-dump <DSC> <DYLIB> --class 'NSString' --re
		# Write ObjC headers to a folder
		❯ ipsw class-dump <DSC> <DYLIB> --headers --output /tmp/headers
		# Structurally diff a dylib's ObjC between two DSC versions (added/removed/changed)
		❯ ipsw class-dump <NEW_DSC> <DYLIB> --diff <OLD_DSC> --color`),
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
		var o *mcmd.ObjC

		// flag validation
		if viper.GetBool("class-dump.headers") &&
			(viper.GetString("class-dump.class") != "" ||
				viper.GetString("class-dump.proto") != "" ||
				viper.GetString("class-dump.cat") != "") {
			return fmt.Errorf("cannot dump --headers and use --class, --protocol or --category flags")
		} else if viper.GetBool("class-dump.headers") && (viper.GetBool("class-dump.xcfw") || viper.GetBool("class-dump.spm")) {
			return fmt.Errorf("cannot dump --headers and use --xcfw or --spm flags")
		} else if viper.GetBool("class-dump.re") && !Verbose &&
			!viper.GetBool("class-dump.headers") && !viper.GetBool("class-dump.xcfw") && !viper.GetBool("class-dump.spm") {
			return fmt.Errorf("cannot use --re without --verbose (or --headers/--xcfw/--spm)")
		} else if len(viper.GetString("class-dump.output")) > 0 && (!viper.GetBool("class-dump.headers") && !viper.GetBool("class-dump.xcfw") && !viper.GetBool("class-dump.spm")) {
			return fmt.Errorf("cannot set --output without setting --headers, --xcfw or --spm")
		}
		doDump := false
		if viper.GetString("class-dump.class") == "" &&
			viper.GetString("class-dump.proto") == "" &&
			viper.GetString("class-dump.cat") == "" &&
			!viper.GetBool("class-dump.headers") &&
			!viper.GetBool("class-dump.xcfw") &&
			!viper.GetBool("class-dump.spm") {
			doDump = true
		}
		// } else if viper.GetBool("class-dump.generic") && !viper.GetBool("class-dump.xcfw") {
		// 	return fmt.Errorf("cannot use --generic without --xcfw")
		// }

		// if viper.GetBool("class-dump.generic") {
		// 	log.Warn("Generating XCFramework for ALL targets (this might causes errors as some symbols are not available on all platforms)")
		// }

		if len(viper.GetString("class-dump.output")) > 0 {
			if err := os.MkdirAll(viper.GetString("class-dump.output"), 0o750); err != nil {
				return err
			}
		}

		demangleOpt := viper.GetBool("class-dump.demangle")
		conf := mcmd.ObjcConfig{
			Verbose:  Verbose || demangleOpt,
			Addrs:    viper.GetBool("class-dump.re"),
			Headers:  viper.GetBool("class-dump.headers"),
			ObjcRefs: viper.GetBool("class-dump.refs"),
			Deps:     viper.GetBool("class-dump.deps"),
			// Generic:     viper.GetBool("class-dump.generic"),
			Demangle:    demangleOpt,
			IpswVersion: fmt.Sprintf("Version: %s, BuildCommit: %s", strings.TrimSpace(AppVersion), strings.TrimSpace(AppBuildCommit)),
			Color:       viper.GetBool("color") && !viper.GetBool("no-color"),
			Theme:       viper.GetString("class-dump.theme"),
			Output:      viper.GetString("class-dump.output"),
		}

		if oldPath := viper.GetString("class-dump.diff"); oldPath != "" {
			return runClassDumpDiff(args, oldPath, &conf)
		}

		if ok, _ := magic.IsMachO(args[0]); ok { /* MachO binary */
			machoPath := filepath.Clean(args[0])
			mr, err := mcmd.OpenMachO(machoPath, viper.GetString("class-dump.arch"))
			if err != nil {
				return err
			}
			defer mr.Close()
			m = mr.File
			if viper.GetBool("class-dump.deps") {
				log.Error("cannot dump imported private frameworks from a MachO file (only from a DSC)")
			}

			conf.Name = filepath.Base(machoPath)

			o, err = mcmd.NewObjC(m, nil, &conf)
			if err != nil {
				return dscExtractedHint(err, m, machoPath)
			}

			if viper.GetBool("class-dump.headers") {
				return dscExtractedHint(o.Headers(), m, machoPath)
			}

			if viper.GetBool("class-dump.xcfw") {
				return dscExtractedHint(o.XCFramework(), m, machoPath)
			}

			if viper.GetBool("class-dump.spm") {
				return dscExtractedHint(o.SwiftPackage(), m, machoPath)
			}

			if viper.GetString("class-dump.class") != "" {
				if err := o.DumpClass(viper.GetString("class-dump.class")); err != nil {
					return dscExtractedHint(err, m, machoPath)
				}
			}

			if viper.GetString("class-dump.proto") != "" {
				if err := o.DumpProtocol(viper.GetString("class-dump.proto")); err != nil {
					return dscExtractedHint(err, m, machoPath)
				}
			}

			if viper.GetString("class-dump.cat") != "" {
				if err := o.DumpCategory(viper.GetString("class-dump.cat")); err != nil {
					return dscExtractedHint(err, m, machoPath)
				}
			}

			if doDump {
				return dscExtractedHint(o.Dump(), m, machoPath)
			}
		} else { /* DSC file */
			if len(args) < 2 && !viper.GetBool("class-dump.all") {
				return fmt.Errorf("must provide an in-cache DYLIB to dump")
			}

			var images []*dyld.CacheImage

			f, err := dyld.Open(filepath.Clean(args[0]))
			if err != nil {
				return err
			}
			defer f.Close()

			if viper.GetBool("class-dump.all") {
				images = f.Images
			} else {
				img, err := f.Image(args[1])
				if err != nil {
					return fmt.Errorf("failed to find dylib '%s' in DSC: %v", args[1], err)
				}
				images = append(images, img)
			}

			for _, img := range images {
				m, err = img.GetMacho()
				if err != nil {
					return fmt.Errorf("failed to parse MachO from dylib '%s': %v", filepath.Base(img.Name), err)
				}

				conf.Name = filepath.Base(img.Name)

				o, err = mcmd.NewObjC(m, f, &conf)
				if err != nil {
					if errors.Is(err, mcmd.ErrNoObjc) {
						if !viper.GetBool("class-dump.all") {
							log.Warnf("no ObjC data found in dylib '%s'", filepath.Base(img.Name))
						}
						continue
					}
					if viper.GetBool("class-dump.all") {
						log.WithError(err).Warnf("failed to create ObjC parser for dylib '%s'", filepath.Base(img.Name))
						continue
					}
					return fmt.Errorf("failed to create ObjC parser for dylib '%s': %v", filepath.Base(img.Name), err)
				}

				if viper.GetBool("class-dump.headers") {
					log.WithField("dylib", filepath.Base(img.Name)).Info("Dumping ObjC headers")
					if err := o.Headers(); err != nil {
						return fmt.Errorf("failed to dump headers for dylib '%s': %v", filepath.Base(img.Name), err)
					}
					continue
				}

				if viper.GetBool("class-dump.xcfw") {
					if err := o.XCFramework(); err != nil {
						return fmt.Errorf("failed to generate XCFramework for dylib '%s': %v", filepath.Base(img.Name), err)
					}
				}

				if viper.GetBool("class-dump.spm") {
					if err := o.SwiftPackage(); err != nil {
						return fmt.Errorf("failed to generate Swift Package for dylib '%s': %v", filepath.Base(img.Name), err)
					}
				}

				if viper.GetString("class-dump.class") != "" {
					if err := o.DumpClass(viper.GetString("class-dump.class")); err != nil {
						return fmt.Errorf("failed to dump class '%s' from dylib '%s': %v", viper.GetString("class-dump.class"), filepath.Base(img.Name), err)
					}
				}

				if viper.GetString("class-dump.proto") != "" {
					if err := o.DumpProtocol(viper.GetString("class-dump.proto")); err != nil {
						return fmt.Errorf("failed to dump protocol '%s' from dylib '%s': %v", viper.GetString("class-dump.proto"), filepath.Base(img.Name), err)
					}
				}

				if viper.GetString("class-dump.cat") != "" {
					if err := o.DumpCategory(viper.GetString("class-dump.cat")); err != nil {
						return fmt.Errorf("failed to dump category '%s' from dylib '%s': %v", viper.GetString("class-dump.cat"), filepath.Base(img.Name), err)
					}
				}

				if doDump {
					if err := o.Dump(); err != nil {
						return fmt.Errorf("failed to dump dylib '%s': %v", filepath.Base(img.Name), err)
					}
				}
			}
		}

		return nil
	},
}
