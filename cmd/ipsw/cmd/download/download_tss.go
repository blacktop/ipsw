//go:build !386

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
package download

import (
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/tss"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadTssCmd)
	// Download behavior flags
	downloadTssCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadTssCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	// Filter flags
	downloadTssCmd.Flags().StringP("device", "d", "", "iOS Device (i.e. iPhone11,2)")
	downloadTssCmd.Flags().StringP("version", "v", "", "iOS Version (i.e. 12.3.1)")
	downloadTssCmd.Flags().StringP("build", "b", "", "iOS BuildID (i.e. 16F203)")
	// Command-specific flags
	downloadTssCmd.Flags().BoolP("signed", "s", false, "Check if iOS version is still being signed")
	downloadTssCmd.Flags().BoolP("usb", "u", false, "Download blobs for USB connected device")
	// downloadTssCmd.Flags().StringP("output", "o", "", "Output directory to save blobs to")
	// downloadTssCmd.MarkFlagDirname("output")
	// Bind persistent flags
	viper.BindPFlag("download.tss.proxy", downloadTssCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.tss.insecure", downloadTssCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.tss.device", downloadTssCmd.Flags().Lookup("device"))
	viper.BindPFlag("download.tss.version", downloadTssCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.tss.build", downloadTssCmd.Flags().Lookup("build"))
	// Bind command-specific flags
	viper.BindPFlag("download.tss.signed", downloadTssCmd.Flags().Lookup("signed"))
	viper.BindPFlag("download.tss.usb", downloadTssCmd.Flags().Lookup("usb"))
	// viper.BindPFlag("download.tss.output", downloadTssCmd.Flags().Lookup("output"))
}

// downloadTssCmd represents the tss command
var downloadTssCmd = &cobra.Command{
	Use:           "tss",
	Aliases:       []string{"t", "tsschecker"},
	Short:         "🚧 Download SHSH Blobs",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		device := viper.GetString("download.tss.device")
		build := viper.GetString("download.tss.build")
		version := viper.GetString("download.tss.version")
		proxy := viper.GetString("download.tss.proxy")
		insecure := viper.GetBool("download.tss.insecure")
		// flags
		isSigned := viper.GetBool("download.tss.signed")
		// output := viper.GetString("download.tss.output")

		if device == "" {
			device = "iPhone10,3"
		}

		conf := &tss.Config{
			Proxy:    proxy,
			Insecure: insecure,
			Device:   device,
			Version:  version,
			Build:    build,
		}

		if viper.GetBool("download.tss.usb") {
			dev, err := utils.PickDevice()
			if err != nil {
				return err
			}
			conf.ECID = uint64(dev.UniqueChipID)
			conf.Device = dev.ProductType
			conf.Build = dev.BuildVersion
			conf.Version = dev.ProductVersion
			conf.ApNonce = dev.ApNonce
			conf.SepNonce = dev.SEPNonce
			conf.Image4Supported = dev.Image4Supported
		}

		if isSigned {
			if _, err := tss.GetTSSResponse(conf); err != nil {
				log.Errorf("🔥 %s is NO LONGER being signed: %v", conf.Version, err)
			} else {
				log.Infof("✅ %s is still being signed", conf.Version)
			}
			return nil
		}

		return fmt.Errorf("downloading SHSH blobs has not been implimented yet")
	},
}
