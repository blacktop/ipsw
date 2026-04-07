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
package ota

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var validCryptexes = []string{"app", "system"}

func validateOTAExtractArgs(args []string, pattern, payloadRange string, confirm bool, cryptex string, dyld, kernel bool) error {
	if err := cobra.RangeArgs(1, 2)(nil, args); err != nil {
		return err
	}

	filenameProvided := len(args) == 2
	if filenameProvided && pattern != "" {
		return fmt.Errorf("cannot use both FILENAME and --pattern")
	}
	if filenameProvided && (cryptex != "" || dyld || kernel) {
		return fmt.Errorf("cannot use FILENAME with --cryptex, --dyld, or --kernel")
	}
	if payloadRange != "" && pattern == "" {
		return fmt.Errorf("--range requires --pattern")
	}
	if confirm && pattern == "" {
		return fmt.Errorf("--confirm requires --pattern")
	}

	return nil
}

func matchesPostBOMPattern(re *regexp.Regexp, name string) bool {
	// Preserve compatibility with basename-anchored patterns while also
	// supporting full-path matches.
	return re.MatchString(name) || re.MatchString(filepath.Base(name))
}

func outputPathForExtraction(outputDir, name string, flat bool) string {
	if flat {
		return filepath.Join(outputDir, filepath.Base(name))
	}
	return filepath.Join(outputDir, name)
}

type otaOpenable interface {
	Open(name string, decomp bool) (fs.File, error)
}

func copyOTAFileToPath(o otaOpenable, name string, decomp bool, outputPath string) error {
	ff, err := o.Open(name, decomp)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' in OTA: %w", name, err)
	}
	defer ff.Close()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	if _, err := io.Copy(out, ff); err != nil {
		closeErr := out.Close()
		removeErr := os.Remove(outputPath)
		if closeErr != nil {
			err = fmt.Errorf("%w (close: %v)", err, closeErr)
		}
		if removeErr != nil {
			err = fmt.Errorf("%w (cleanup: %v)", err, removeErr)
		}
		return fmt.Errorf("failed to write file: %w", err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("failed to close output file '%s': %w", outputPath, err)
	}

	return nil
}

func readOTAFile(o otaOpenable, name string, decomp bool) ([]byte, error) {
	ff, err := o.Open(name, decomp)
	if err != nil {
		return nil, fmt.Errorf("failed to open file '%s' in OTA: %w", name, err)
	}
	defer ff.Close()

	data, err := io.ReadAll(ff)
	if err != nil {
		return nil, fmt.Errorf("failed to read file '%s' in OTA: %w", name, err)
	}

	return data, nil
}

func init() {
	OtaCmd.AddCommand(otaExtractCmd)

	otaExtractCmd.Flags().StringP("cryptex", "c", "", "Extract cryptex as DMG (requires full OTA)")
	otaExtractCmd.RegisterFlagCompletionFunc("cryptex", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return validCryptexes, cobra.ShellCompDirectiveDefault
	})
	otaExtractCmd.Flags().BoolP("dyld", "d", false, "Extract dyld_shared_cache files")
	otaExtractCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache")
	otaExtractCmd.Flags().StringP("pattern", "p", "", "Regex pattern to match files")
	otaExtractCmd.Flags().StringP("range", "r", "", "Regex pattern to limit payloadv2 files searched (requires --pattern)")
	otaExtractCmd.Flags().BoolP("confirm", "y", false, "Skip prompt and search payloadv2 files (requires --pattern)")
	otaExtractCmd.Flags().BoolP("decomp", "x", false, "Decompress pbzx files")
	otaExtractCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting")
	otaExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	otaExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.extract.cryptex", otaExtractCmd.Flags().Lookup("cryptex"))
	viper.BindPFlag("ota.extract.dyld", otaExtractCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("ota.extract.kernel", otaExtractCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("ota.extract.pattern", otaExtractCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("ota.extract.range", otaExtractCmd.Flags().Lookup("range"))
	viper.BindPFlag("ota.extract.confirm", otaExtractCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("ota.extract.decomp", otaExtractCmd.Flags().Lookup("decomp"))
	viper.BindPFlag("ota.extract.flat", otaExtractCmd.Flags().Lookup("flat"))
	viper.BindPFlag("ota.extract.output", otaExtractCmd.Flags().Lookup("output"))
}

// otaExtractCmd represents the extract command
var otaExtractCmd = &cobra.Command{
	Use:           "extract <OTA> [FILENAME]",
	Aliases:       []string{"e"},
	Short:         "Extract OTA payload files",
	Args:          cobra.RangeArgs(1, 2),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		decomp := viper.GetBool("ota.extract.decomp")
		cryptex := viper.GetString("ota.extract.cryptex")
		flat := viper.GetBool("ota.extract.flat")
		pattern := viper.GetString("ota.extract.pattern")
		payloadRange := viper.GetString("ota.extract.range")
		confirm := viper.GetBool("ota.extract.confirm")
		dyldExtract := viper.GetBool("ota.extract.dyld")
		kernelExtract := viper.GetBool("ota.extract.kernel")
		// validate flags
		if err := validateOTAExtractArgs(args, pattern, payloadRange, confirm, cryptex, dyldExtract, kernelExtract); err != nil {
			return err
		}
		if cryptex != "" && !slices.Contains(validCryptexes, cryptex) {
			return fmt.Errorf("invalid --cryptex: '%s' (must be one of: %s)", cryptex, strings.Join(validCryptexes, ", "))
		}

		o, err := ota.Open(filepath.Clean(args[0]), ResolveAEAKeyFromFlags(args[0]))
		if err != nil {
			return fmt.Errorf("failed to open OTA file: %v", err)
		}

		info, err := o.Info()
		if err != nil {
			return fmt.Errorf("failed to get OTA info: %v", err)
		}
		output, err := info.GetFolder()
		if err != nil {
			return fmt.Errorf("failed to get OTA folder: %v", err)
		}

		if viper.GetString("ota.extract.output") != "" {
			output = filepath.Join(viper.GetString("ota.extract.output"), output)
			if err := os.MkdirAll(output, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %v", err)
			}
		}

		if cryptex != "" || dyldExtract || kernelExtract || pattern != "" {
			cwd, _ := os.Getwd()
			/* CRYPTEX */
			if cryptex != "" {
				log.Infof("Extracting %s Cryptex", cryptex)
				out, err := o.ExtractCryptex(cryptex, output)
				if err != nil {
					return fmt.Errorf("failed to extract %s cryptex: %v", cryptex, err)
				}
				if rel, err := filepath.Rel(cwd, out); err != nil {
					utils.Indent(log.Info, 2)(out)
				} else {
					utils.Indent(log.Info, 2)(rel)
				}
			}
			/* DYLD_SHARED_CACHE */
			if dyldExtract {
				log.Info("Extracting dyld_shared_cache files")
				out, err := o.ExtractFromCryptexes(dyld.CacheUberRegex, output)
				if err != nil {
					log.WithError(err).Error("failed to extract dyld_shared_cache from cryptexes; falling back to OTA asset files/payloads")
					viper.Set("ota.extract.pattern", dyld.CacheUberRegex)
				}
				for _, fname := range out {
					if rel, err := filepath.Rel(cwd, fname); err != nil {
						utils.Indent(log.Info, 2)(fname)
					} else {
						utils.Indent(log.Info, 2)(rel)
					}
				}
			}
			/* KERNELCACHE */
			if kernelExtract {
				log.Info("Extracting kernelcache(s)")
				re := regexp.MustCompile(`kernelcache.*$`)
				for _, f := range o.Files() { // search in OTA asset files
					if f.IsDir() {
						continue
					}
					if re.MatchString(f.Name()) {
						data, err := readOTAFile(o, f.Name(), false)
						if err != nil {
							return fmt.Errorf("failed to read kernelcache: %v", err)
						}
						comp, err := kernelcache.ParseImg4Data(data)
						if err != nil {
							return fmt.Errorf("failed to parse kernelcache: %v", err)
						}
						kdata, err := kernelcache.DecompressData(comp)
						if err != nil {
							return fmt.Errorf("failed to parse kernelcache compressed data: %v", err)
						}
						fname := outputPathForExtraction(output, f.Name(), flat)
						if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
							return fmt.Errorf("failed to create output directory: %v", err)
						}
						if rel, err := filepath.Rel(cwd, fname); err != nil {
							utils.Indent(log.Info, 2)(fname)
						} else {
							utils.Indent(log.Info, 2)(rel)
						}
						if err := os.WriteFile(fname, kdata, 0o644); err != nil {
							return fmt.Errorf("failed to write kernelcache: %v", err)
						}
					}
				}
			}
			/* PATTERN */
			if pattern != "" {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("failed to compile regex pattern '%s': %v", pattern, err)
				}
				log.WithField("pattern", re.String()).Info("Extracting Files Matching Pattern")
				for _, f := range o.Files() { // search in OTA asset files
					if f.IsDir() {
						continue
					}
					if matchesPostBOMPattern(re, f.Name()) {
						fname := outputPathForExtraction(output, f.Name(), flat)
						utils.Indent(log.Info, 2)(fname)
						if err := copyOTAFileToPath(o, f.Name(), decomp, fname); err != nil {
							return err
						}
					}
				}
				bomFound := false
				for _, f := range o.PostFiles() { // search in OTA post.bom files
					if f.IsDir() {
						continue
					}
					if matchesPostBOMPattern(re, f.Name()) {
						utils.Indent(log.Warn, 2)(fmt.Sprintf("Found '%s' in post.bom (most likely in payloadv2 files)", filepath.Base(f.Name())))
						bomFound = true
					}
				}
				if bomFound {
					cont := true
					if !confirm {
						cont = false
						prompt := &survey.Confirm{
							Message: fmt.Sprintf("Search for '%s' in payloadv2 files?", re.String()),
						}
						survey.AskOne(prompt, &cont)
					}
					if cont {
						utils.Indent(log.Info, 2)(fmt.Sprintf("Searching for '%s' in OTA payload files", re.String()))
						return o.GetPayloadFiles(
							pattern,
							payloadRange,
							output)
					}
				}
			}
			return nil
		}

		/* ALL FILES */
		if len(args) == 1 && pattern == "" {
			log.Info("Extracting all files from OTA")
			for _, f := range o.Files() {
				if f.IsDir() {
					continue
				}
				fname := outputPathForExtraction(output, f.Name(), flat)
				if _, err := os.Stat(fname); err == nil {
					log.Warnf("already exists: '%s' ", fname)
					continue
				}
				utils.Indent(log.Info, 2)(fname)
				if err := copyOTAFileToPath(o, f.Name(), decomp, fname); err != nil {
					return err
				}
			}
			/* SINGLE FILE */
		} else if len(args) > 1 {
			name := filepath.Clean(args[1])
			fname := filepath.Join(output, name)
			log.Infof("Extracting to '%s'", fname)
			if err := copyOTAFileToPath(o, name, decomp, fname); err != nil {
				return err
			}
		}

		return nil
	},
}
