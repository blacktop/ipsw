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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
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
	downloadTssCmd.Flags().Uint64("ecid", 0, "Device ECID")
	downloadTssCmd.Flags().BoolP("signed", "s", false, "Check if iOS version is still being signed")
	downloadTssCmd.Flags().BoolP("usb", "u", false, "Download blobs for USB connected device")
	downloadTssCmd.Flags().BoolP("latest", "l", false, "Check latest iOS version")
	downloadTssCmd.Flags().Bool("beta", false, "Check for beta iOS versions")
	downloadTssCmd.Flags().StringP("output", "o", "", "Output path for SHSH blobs")
	downloadTssCmd.MarkFlagFilename("output")
	// Bind persistent flags
	viper.BindPFlag("download.tss.proxy", downloadTssCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.tss.insecure", downloadTssCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.tss.device", downloadTssCmd.Flags().Lookup("device"))
	viper.BindPFlag("download.tss.version", downloadTssCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.tss.build", downloadTssCmd.Flags().Lookup("build"))
	// Bind command-specific flags
	viper.BindPFlag("download.tss.ecid", downloadTssCmd.Flags().Lookup("ecid"))
	viper.BindPFlag("download.tss.signed", downloadTssCmd.Flags().Lookup("signed"))
	viper.BindPFlag("download.tss.usb", downloadTssCmd.Flags().Lookup("usb"))
	viper.BindPFlag("download.tss.latest", downloadTssCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.tss.beta", downloadTssCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.tss.output", downloadTssCmd.Flags().Lookup("output"))
}

// downloadTssCmd represents the tss command
var downloadTssCmd = &cobra.Command{
	Use:     "tss",
	Aliases: []string{"t", "tsschecker"},
	Short:   "Check signing status and download SHSH blobs",
	Example: heredoc.Doc(`
		# Check if iOS version is still being signed
		❯ ipsw download tss --device iPhone14,2 --version 17.0 --signed

		# Check if latest iOS version is still being signed
		❯ ipsw download tss --device iPhone14,2 --latest --signed

		# Check signing status for USB connected device
		❯ ipsw download tss --usb --signed

		# Check signing status for a specific ECID
		❯ ipsw download tss --device iPhone14,2 --version 17.0 --ecid 1234567890 --signed

		# Download SHSH blobs for specific device/version
		❯ ipsw download tss --device iPhone14,2 --version 17.0 --output 1234567890.shsh
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.tss.proxy")
		insecure := viper.GetBool("download.tss.insecure")
		// filters
		device := viper.GetString("download.tss.device")
		version := viper.GetString("download.tss.version")
		build := viper.GetString("download.tss.build")
		// flags
		ecid := viper.GetUint64("download.tss.ecid")
		isSigned := viper.GetBool("download.tss.signed")
		output := viper.GetString("download.tss.output")
		useLatest := viper.GetBool("download.tss.latest")
		useBeta := viper.GetBool("download.tss.beta")
		// validate flags
		if device == "" {
			return fmt.Errorf("device must be specified with --device")
		}
		if !viper.IsSet("download.tss.ecid") && !viper.GetBool("download.tss.usb") {
			ecid, err = tss.RandomECID()
			if err != nil {
				return fmt.Errorf("failed to generate random ECID: %v", err)
			}
		}

		var configDir string
		if len(viper.ConfigFileUsed()) == 0 {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			configDir = filepath.Join(home, ".config", "ipsw")
			if err := os.MkdirAll(configDir, 0770); err != nil {
				return fmt.Errorf("failed to create config folder: %v", err)
			}
		} else {
			configDir = filepath.Dir(viper.ConfigFileUsed())
		}

		result, err := download.LocalAppleDBQuery(&download.ADBQuery{
			OSes:      []string{"iOS"},
			Type:      "ipsw",
			Version:   version,
			Build:     build,
			Device:    device,
			IsRelease: !useBeta,
			IsBeta:    useBeta,
			Latest:    useLatest,
			Proxy:     proxy,
			Insecure:  insecure,
			ConfigDir: configDir,
		})
		if err != nil {
			return fmt.Errorf("failed to query AppleDB: %v", err)
		}
		if len(result) == 0 {
			return fmt.Errorf("no IPSW found for %s %s", device, version)
		}

		var url string
		for _, link := range result[0].Links {
			if link.Active {
				url = link.URL
			}
		}
		if url == "" {
			return fmt.Errorf("no active IPSW URL found for %s %s", device, version)
		}

		zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
			Proxy:    proxy,
			Insecure: insecure,
		})
		if err != nil {
			return fmt.Errorf("unable to download remote IPSW: %v", err)
		}
		i, err := info.ParseZipFiles(zr.File)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW info: %v", err)
		}
		if len(version) == 0 {
			version = i.Plists.BuildManifest.ProductVersion
		}
		if len(build) == 0 {
			build = i.Plists.BuildManifest.ProductBuildVersion
		}

		conf := &tss.Config{
			Proxy:           proxy,
			Insecure:        insecure,
			Device:          device,
			Version:         version,
			Build:           build,
			Output:          output,
			ECID:            ecid,
			Image4Supported: true, // Default to true for modern devices
			Info:            i,
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

		fields := log.Fields{}
		if len(conf.Version) > 0 {
			fields["version"] = conf.Version
		}
		if len(conf.Build) > 0 {
			fields["build"] = conf.Build
		}
		if len(conf.Device) > 0 {
			fields["device"] = conf.Device
		}
		if useBeta {
			fields["beta"] = "true"
		}
		if useLatest {
			fields["latest"] = "true"
		}

		response, err := tss.GetTSSResponse(conf)
		if err != nil {
			if !errors.Is(err, tss.ErrNotSigned) {
				return fmt.Errorf("failed to get TSS response: %v", err)
			}
		}

		if isSigned {
			if err != nil {
				log.WithFields(fields).Errorf("💀 No longer being signed")
			} else {
				log.WithFields(fields).Infof("✅ Is still being signed")
			}
		}

		if len(output) > 0 {
			if len(response) == 0 {
				return fmt.Errorf("no SHSH blob data returned")
			}
			if err := os.MkdirAll(filepath.Dir(output), 0770); err != nil {
				return fmt.Errorf("failed to create output directory: %v", err)
			}
			if err := os.WriteFile(output, response, 0644); err != nil {
				return fmt.Errorf("failed to write SHSH blob to %s: %v", output, err)
			}
			log.WithField("output", output).Info("SHSH blob saved")
		}

		return nil
	},
}
