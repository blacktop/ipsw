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
package ota

import (
	"fmt"
	"io"
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
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var validCryptexes = []string{"app", "system"}

func init() {
	OtaCmd.AddCommand(otaExtractCmd)

	otaExtractCmd.Flags().StringP("cryptex", "c", "", "Extract cryptex as DMG (requires full OTA)")
	otaExtractCmd.RegisterFlagCompletionFunc("cryptex", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return validCryptexes, cobra.ShellCompDirectiveDefault
	})
	otaExtractCmd.Flags().BoolP("dyld", "d", false, "Extract dyld_shared_cache files")
	otaExtractCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache")
	otaExtractCmd.Flags().StringP("pattern", "p", "", "Regex pattern to match files")
	otaExtractCmd.Flags().StringP("range", "r", "", "Regex pattern control the payloadv2 file range to search")
	otaExtractCmd.Flags().BoolP("confirm", "y", false, "Confirm searching for pattern in payloadv2 files")
	otaExtractCmd.Flags().BoolP("decomp", "x", false, "Decompress pbzx files")
	otaExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	otaExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.extract.cryptex", otaExtractCmd.Flags().Lookup("cryptex"))
	viper.BindPFlag("ota.extract.dyld", otaExtractCmd.Flags().Lookup("dyld"))
	viper.BindPFlag("ota.extract.kernel", otaExtractCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("ota.extract.pattern", otaExtractCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("ota.extract.range", otaExtractCmd.Flags().Lookup("range"))
	viper.BindPFlag("ota.extract.confirm", otaExtractCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("ota.extract.decomp", otaExtractCmd.Flags().Lookup("decomp"))
	viper.BindPFlag("ota.extract.output", otaExtractCmd.Flags().Lookup("output"))
}

// otaExtractCmd represents the extract command
var otaExtractCmd = &cobra.Command{
	Use:           "extract <OTA> [FILENAME]>",
	Aliases:       []string{"e"},
	Short:         "Extract OTA payload files",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		decomp := viper.GetBool("ota.extract.decomp")
		cryptex := viper.GetString("ota.extract.cryptex")
		// validate flags
		if len(args) > 1 && viper.IsSet("ota.extract.pattern") {
			return fmt.Errorf("cannot use both FILENAME and flag for --pattern")
		}
		if viper.IsSet("ota.extract.cryptex") && !slices.Contains(validCryptexes, cryptex) {
			return fmt.Errorf("invalid --cryptex: '%s' (must be one of: %s)", cryptex, strings.Join(validCryptexes, ", "))
		}

		o, err := ota.Open(filepath.Clean(args[0]), viper.GetString("ota.key-val"))
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

		if viper.IsSet("ota.extract.output") {
			output = filepath.Join(viper.GetString("ota.extract.output"), output)
			if err := os.MkdirAll(output, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %v", err)
			}
		}

		if viper.IsSet("ota.extract.cryptex") || viper.GetBool("ota.extract.dyld") || viper.GetBool("ota.extract.kernel") || viper.IsSet("ota.extract.pattern") {
			cwd, _ := os.Getwd()
			/* CRYPTEX */
			if viper.IsSet("ota.extract.cryptex") {
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
			if viper.GetBool("ota.extract.dyld") {
				log.Info("Extracting dyld_shared_cache Files")
				out, err := o.ExtractFromCryptexes(dyld.CacheUberRegex, output)
				if err != nil {
					return fmt.Errorf("failed to extract dyld_shared_cache: %v", err)
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
			if viper.GetBool("ota.extract.kernel") {
				log.Info("Extracting kernelcache(s)")
				re := regexp.MustCompile(`kernelcache.*$`)
				for _, f := range o.Files() { // search in OTA asset files
					if f.IsDir() {
						continue
					}
					if re.MatchString(f.Path()) {
						ff, err := o.Open(f.Path(), false)
						if err != nil {
							return fmt.Errorf("failed to open file '%s' in OTA: %v", f.Path(), err)
						}
						data, err := io.ReadAll(ff)
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
						fname := filepath.Join(output, f.Name())
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
			if viper.IsSet("ota.extract.pattern") {
				re, err := regexp.Compile(viper.GetString("ota.extract.pattern"))
				if err != nil {
					return fmt.Errorf("failed to compile regex pattern '%s': %v", viper.GetString("ota.extract.pattern"), err)
				}
				log.WithField("pattern", re.String()).Info("Extracting Files Matching Pattern")
				for _, f := range o.Files() { // search in OTA asset files
					if f.IsDir() {
						continue
					}
					if re.MatchString(f.Path()) {
						ff, err := o.Open(f.Path(), decomp)
						if err != nil {
							return fmt.Errorf("failed to open file '%s' in OTA: %v", f.Path(), err)
						}
						fname := filepath.Join(output, f.Path())
						if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
							return fmt.Errorf("failed to create output directory: %v", err)
						}
						out, err := os.Create(fname)
						if err != nil {
							return fmt.Errorf("failed to create file: %v", err)
						}
						defer out.Close()
						utils.Indent(log.Info, 2)(fname)
						if _, err := io.Copy(out, ff); err != nil {
							return fmt.Errorf("failed to write file: %v", err)
						}
					}
				}
				bomFound := false
				for _, f := range o.PostFiles() { // search in OTA post.bom files
					if f.IsDir() {
						continue
					}
					if re.MatchString(f.Name()) {
						utils.Indent(log.Warn, 2)(fmt.Sprintf("Found '%s' in post.bom (most likely in payloadv2 files)", f.Name()))
						bomFound = true
					}
				}
				if bomFound {
					cont := true
					if !viper.GetBool("ota.extract.confirm") {
						cont = false
						prompt := &survey.Confirm{
							Message: fmt.Sprintf("Search for '%s' in payloadv2 files?", re.String()),
						}
						survey.AskOne(prompt, &cont)
					}
					if cont {
						utils.Indent(log.Info, 2)(fmt.Sprintf("Searching for '%s' in OTA payload files", re.String()))
						return o.GetPayloadFiles(
							viper.GetString("ota.extract.pattern"),
							viper.GetString("ota.extract.range"),
							output)
					}
				}
			}
			return nil
		}

		/* ALL FILES */
		if len(args) == 1 && !viper.IsSet("ota.extract.pattern") {
			log.Info("Extracting All Files From OTA")
			for _, f := range o.Files() {
				if f.IsDir() {
					continue
				}
				fname := filepath.Join(output, f.Path())
				if _, err := os.Stat(fname); err == nil {
					log.Warnf("already exists: '%s' ", fname)
					continue
				}
				ff, err := o.Open(f.Path(), decomp)
				if err != nil {
					return fmt.Errorf("failed to open file '%s' in OTA: %v", f.Path(), err)
				}
				if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
					return fmt.Errorf("failed to create output directory: %v", err)
				}
				out, err := os.Create(fname)
				if err != nil {
					return fmt.Errorf("failed to create file: %v", err)
				}
				defer out.Close()
				utils.Indent(log.Info, 2)(fname)
				if _, err := io.Copy(out, ff); err != nil {
					return fmt.Errorf("failed to write file: %v", err)
				}
			}
			/* SINGLE FILE */
		} else if len(args) > 1 {
			f, err := o.Open(filepath.Clean(args[1]), decomp)
			if err != nil {
				return fmt.Errorf("failed to open file '%s' in OTA: %v", filepath.Clean(args[1]), err)
			}
			fname := filepath.Join(output, filepath.Clean(args[1]))
			if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
				return fmt.Errorf("failed to create output directory: %v", err)
			}
			out, err := os.Create(fname)
			if err != nil {
				return fmt.Errorf("failed to create file: %v", err)
			}
			defer out.Close()
			log.Infof("Extracting to '%s'", out.Name())
			if _, err := io.Copy(out, f); err != nil {
				return fmt.Errorf("failed to write file: %v", err)
			}
		}

		return nil
	},
}
