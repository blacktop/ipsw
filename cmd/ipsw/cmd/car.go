/*
Copyright © 2025 blacktop

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
	"io"
	"os"
	"path"
	"strconv"

	here "github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/profile"
	"github.com/blacktop/ipsw/pkg/car"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var profileFlags profile.ProfilingFlags

func init() {
	rootCmd.AddCommand(carCmd)

	carCmd.Flags().StringP("output", "o", "", "Output folder to extract renditions")
	carCmd.Flags().BoolP("json", "j", false, "Output the selected inventory as JSON")
	carCmd.Flags().StringArray("name", nil, "Match a logical or rendition name glob (repeatable)")
	carCmd.Flags().String("scale", "", "Match the exact scale key (1, 2, 3)")
	carCmd.Flags().String("idiom", "", "Match the exact idiom key (0=universal, 1=phone, 2=pad, 3=desktop)")
	carCmd.Flags().String("appearance", "", "Match the exact numeric appearance key")
	carCmd.Flags().String("localization", "", "Match the exact numeric localization key")
	carCmd.Flags().String("gamut", "", "Match the exact numeric display-gamut key")
	carCmd.Flags().Bool("metadata-only", false, "Inspect catalog metadata without decoding pixels")
	carCmd.Flags().Bool("dry-run", false, "Preview export destinations without decoding or extracting assets")
	carCmd.Flags().String("manifest", "", "Write an export manifest to a new file, or '-' for stdout")
	carCmd.Flags().Bool("render", false, "Render HEIF, PDF, and SVG payloads as PNG")
	carCmd.Flags().Bool("raw", false, "Export complete encoded CSI renditions instead of converted assets")
	carCmd.Flags().Bool("apply-orientation", false, "Apply EXIF rotation or mirroring to PNG exports")
	carCmd.Flags().String("astc-decoder", "", "Path to astcenc for ASTC decoding")
	carCmd.MarkFlagDirname("output")
	carCmd.MarkFlagFilename("manifest", "json")
	carCmd.MarkFlagFilename("astc-decoder")
	viper.BindPFlag("car.output", carCmd.Flags().Lookup("output"))
	viper.BindPFlag("car.json", carCmd.Flags().Lookup("json"))
	viper.BindPFlag("car.name", carCmd.Flags().Lookup("name"))
	viper.BindPFlag("car.scale", carCmd.Flags().Lookup("scale"))
	viper.BindPFlag("car.idiom", carCmd.Flags().Lookup("idiom"))
	viper.BindPFlag("car.appearance", carCmd.Flags().Lookup("appearance"))
	viper.BindPFlag("car.localization", carCmd.Flags().Lookup("localization"))
	viper.BindPFlag("car.gamut", carCmd.Flags().Lookup("gamut"))
	viper.BindPFlag("car.metadata-only", carCmd.Flags().Lookup("metadata-only"))
	viper.BindPFlag("car.dry-run", carCmd.Flags().Lookup("dry-run"))
	viper.BindPFlag("car.manifest", carCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("car.render", carCmd.Flags().Lookup("render"))
	viper.BindPFlag("car.raw", carCmd.Flags().Lookup("raw"))
	viper.BindPFlag("car.apply-orientation", carCmd.Flags().Lookup("apply-orientation"))
	viper.BindPFlag("car.astc-decoder", carCmd.Flags().Lookup("astc-decoder"))
	profile.AddFlags(carCmd, &profileFlags)
}

var carCmd = &cobra.Command{
	Use:   "car <Assets.car>",
	Short: "Inspect and extract compiled asset catalogs",
	Long: here.Doc(`
		Inspect a compiled asset catalog and optionally extract its renditions.
		Use --metadata-only --json to inspect keys before selecting exact numeric
		variants. Name globs match stored rendition names and logical asset names;
		requested numeric keys must exist and match exactly, including zero.
		--json cannot be combined with --dry-run or --manifest -.

		HEIF/PDF/SVG rendering and native BC7 decoding require macOS with cgo.
		ASTC decoding can also use an external astcenc executable through
		--astc-decoder. Original JPEG and WebP payloads are preserved unchanged.
		RLE-compressed original payloads, including DATA, are unsupported;
		use --raw to retain their complete CSI records. Bitmap RLE is supported.

		Exports replace existing rendition files atomically. Unsupported layouts
		and codecs are reported separately; decode or write failures cause a nonzero
		exit. Use --raw to preserve unsupported renditions as original CSI records.
	`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	Example: here.Doc(`
		# Inspect metadata without decoding images
		$ ipsw car Assets.car --metadata-only --json

		# Extract all supported renditions
		$ ipsw car Assets.car --output assets

		# Extract matching variants; quote globs to prevent shell expansion
		$ ipsw car Assets.car --name 'AppIcon*' --scale 2 --idiom 1 --output icons

		# Preview exact keys, crops, and destinations without extracting
		$ ipsw car Assets.car --dry-run --output assets

		# Render embedded documents/images and record every export result
		$ ipsw car Assets.car --render --apply-orientation --output images --manifest exports.json

		# Preserve original CSI data, including unsupported encodings
		$ ipsw car Assets.car --raw --output original
	`),
	RunE: func(cmd *cobra.Command, args []string) error {
		options, err := readCAROptions()
		if err != nil {
			return err
		}
		if options.manifest != "" && options.manifest != "-" {
			if _, err := os.Lstat(options.manifest); err == nil {
				return fmt.Errorf("manifest already exists: %s", options.manifest)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("check manifest: %w", err)
			}
		}
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		prof := profile.New(profileFlags.ToConfig())
		if err := prof.Start(); err != nil {
			return fmt.Errorf("failed to start profiling: %w", err)
		}
		defer func() {
			if err := prof.Stop(); err != nil {
				log.Errorf("failed to stop profiling: %v", err)
			}
			if profileFlags.IsEnabled() && !options.json && !options.dryRun && options.manifest != "-" {
				prof.PrintStats()
			}
		}()
		asset, err := car.Parse(args[0], &options.config)
		if err != nil {
			return err
		}
		if options.manifest != "" {
			if err := writeCARManifest(asset, options.config.Output, options.manifest, cmd.OutOrStdout()); err != nil {
				return err
			}
		}
		if options.dryRun {
			if options.manifest == "" {
				if err := asset.WriteManifest(cmd.OutOrStdout(), options.config.Output); err != nil {
					return err
				}
			}
		} else if options.manifest != "-" {
			if options.json {
				output, err := asset.ToJSON()
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(output)); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintln(cmd.OutOrStdout(), asset); err != nil {
				return err
			}
		}
		if options.config.Export || options.dryRun {
			failed := 0
			for _, entry := range asset.PlanExport(options.config.Output) {
				if entry.Status == "failed" {
					failed++
				}
			}
			if failed > 0 {
				return fmt.Errorf("CAR export has %d failed selected renditions; see the output or manifest", failed)
			}
		}
		return nil
	},
}

type carCommandOptions struct {
	config   car.Config
	json     bool
	dryRun   bool
	manifest string
}

func readCAROptions() (carCommandOptions, error) {
	options := carCommandOptions{
		config: car.Config{Output: viper.GetString("car.output"), Verbose: Verbose,
			MetadataOnly: viper.GetBool("car.metadata-only"), Raw: viper.GetBool("car.raw"),
			Render: viper.GetBool("car.render"), ApplyOrientation: viper.GetBool("car.apply-orientation"),
			ASTCDecoder: viper.GetString("car.astc-decoder")},
		json: viper.GetBool("car.json"), dryRun: viper.GetBool("car.dry-run"), manifest: viper.GetString("car.manifest"),
	}
	conf := &options.config
	if options.json && (options.dryRun || options.manifest == "-") {
		return options, fmt.Errorf("--json cannot be combined with --dry-run or --manifest -")
	}
	if conf.Raw && (conf.Render || conf.ApplyOrientation || conf.ASTCDecoder != "") {
		return options, fmt.Errorf("--raw cannot be combined with --render, --apply-orientation, or --astc-decoder")
	}
	if conf.MetadataOnly && !options.dryRun && (conf.Output != "" || conf.Render || conf.ApplyOrientation || conf.ASTCDecoder != "") {
		return options, fmt.Errorf("--metadata-only cannot export or render images; use --dry-run to preview export options")
	}
	if conf.ApplyOrientation && conf.Output == "" && !options.dryRun {
		return options, fmt.Errorf("--apply-orientation requires --output or --dry-run")
	}
	query := &car.VariantQuery{Names: viper.GetStringSlice("car.name")}
	for _, pattern := range query.Names {
		if _, err := path.Match(pattern, ""); err != nil {
			return options, fmt.Errorf("invalid --name pattern %q: %w", pattern, err)
		}
	}
	for _, field := range []struct {
		name   string
		target **uint16
	}{
		{"scale", &query.Scale}, {"idiom", &query.Idiom}, {"appearance", &query.Appearance},
		{"localization", &query.Localization}, {"gamut", &query.DisplayGamut},
	} {
		value := viper.GetString("car." + field.name)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return options, fmt.Errorf("--%s must be an integer from 0 to 65535: %q", field.name, value)
		}
		number := uint16(parsed)
		*field.target = &number
	}
	conf.Query = query
	conf.MetadataOnly = conf.MetadataOnly || options.dryRun
	conf.Export = conf.Output != "" && !conf.MetadataOnly
	return options, nil
}

func writeCARManifest(asset *car.Asset, output, filename string, stdout io.Writer) (err error) {
	if filename == "-" {
		return asset.WriteManifest(stdout, output)
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create manifest: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(filename)
		}
	}()
	return asset.WriteManifest(file, output)
}
