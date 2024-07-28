/*
Copyright © 2018-2024 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	OtaCmd.AddCommand(otaExtractCmd)

	otaExtractCmd.Flags().StringP("pattern", "p", "", "Regex pattern to match files")
	otaExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	otaExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("ota.extract.pattern", otaExtractCmd.Flags().Lookup("pattern"))
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

		if len(args) > 1 && viper.IsSet("ota.extract.pattern") {
			return fmt.Errorf("cannot use both FILENAME and flag for --pattern")
		}

		o, err := ota.Open(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to open OTA file: %v", err)
		}

		output := filepath.Dir(filepath.Clean(args[0]))
		if viper.IsSet("ota.extract.output") {
			output = filepath.Clean(viper.GetString("ota.extract.output"))
		}

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
				ff, err := o.Open(f.Path())
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
		} else if len(args) > 1 {
			f, err := o.Open(filepath.Clean(args[1]))
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
		} else {
			if !viper.IsSet("ota.extract.pattern") {
				return fmt.Errorf("must provide a --pattern to match files")
			}
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
					ff, err := o.Open(f.Path())
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
			for _, f := range o.PostFiles() { // search in OTA post.bom files
				if f.IsDir() {
					continue
				}
				if re.MatchString(f.Name()) {
					log.Warnf("'%s' most likely in payloadv2 files", f.Name())
				}
			}
		}

		return nil
	},
}
