/*
Copyright © 2024 blacktop

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var supportedOSes = []string{"audioOS", "bridgeOS", "iOS", "iPadOS", "iPodOS", "macOS", "tvOS", "watchOS", "visionOS"}
var supportedRsrOSes = []string{"iOS", "iPadOS", "macOS"}
var supportedFWs = []string{"ipsw", "ota", "rsr"}

func init() {
	DownloadCmd.AddCommand(downloadAppledbCmd)

	downloadAppledbCmd.Flags().StringArray("os", []string{}, fmt.Sprintf("Operating system to download (%s)", strings.Join(supportedOSes, ", ")))
	downloadAppledbCmd.Flags().String("type", "ipsw", fmt.Sprintf("FW type to download (%s)", strings.Join(supportedFWs, ", ")))
	downloadAppledbCmd.Flags().Bool("kernel", false, "Extract kernelcache from remote IPSW")
	downloadAppledbCmd.Flags().String("pattern", "", "Download remote files that match regex")
	downloadAppledbCmd.Flags().Bool("beta", false, "Download beta IPSWs")
	downloadAppledbCmd.Flags().Bool("latest", false, "Download latest IPSWs")
	downloadAppledbCmd.Flags().StringP("prereq-build", "p", "", "OTA prerequisite build")
	downloadAppledbCmd.Flags().BoolP("urls", "u", false, "Dump URLs only")
	downloadAppledbCmd.Flags().BoolP("json", "j", false, "Dump DB query results as JSON")
	downloadAppledbCmd.Flags().BoolP("api", "a", false, "Use Github API")
	downloadAppledbCmd.Flags().String("api-token", "", "Github API Token")
	downloadAppledbCmd.Flags().StringP("output", "o", "", "Folder to download files to")
	downloadAppledbCmd.Flags().BoolP("flat", "f", false, "Do NOT perserve directory structure when downloading with --pattern")
	downloadAppledbCmd.Flags().Bool("usb", false, "Download IPSWs for USB attached iDevices")

	viper.BindPFlag("download.appledb.os", downloadAppledbCmd.Flags().Lookup("os"))
	viper.BindPFlag("download.appledb.type", downloadAppledbCmd.Flags().Lookup("type"))
	viper.BindPFlag("download.appledb.kernel", downloadAppledbCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("download.appledb.pattern", downloadAppledbCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("download.appledb.beta", downloadAppledbCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.appledb.latest", downloadAppledbCmd.Flags().Lookup("latest"))
	viper.BindPFlag("download.appledb.prereq-build", downloadAppledbCmd.Flags().Lookup("prereq-build"))
	viper.BindPFlag("download.appledb.urls", downloadAppledbCmd.Flags().Lookup("urls"))
	viper.BindPFlag("download.appledb.json", downloadAppledbCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.appledb.api", downloadAppledbCmd.Flags().Lookup("api"))
	viper.BindPFlag("download.appledb.api-token", downloadAppledbCmd.Flags().Lookup("api-token"))
	viper.BindPFlag("download.appledb.output", downloadAppledbCmd.Flags().Lookup("output"))
	viper.BindPFlag("download.appledb.flat", downloadAppledbCmd.Flags().Lookup("flat"))
	viper.BindPFlag("download.appledb.usb", downloadAppledbCmd.Flags().Lookup("usb"))

	downloadAppledbCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("model") // TODO: remove this?
		c.Parent().HelpFunc()(c, s)
	})
	downloadAppledbCmd.MarkFlagDirname("output")
	downloadAppledbCmd.MarkFlagRequired("os")
	downloadAppledbCmd.RegisterFlagCompletionFunc("os", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return supportedOSes, cobra.ShellCompDirectiveDefault
	})
	downloadAppledbCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return supportedFWs, cobra.ShellCompDirectiveDefault
	})
}

// downloadAppledbCmd represents the appledb command
var downloadAppledbCmd = &cobra.Command{
	Use:     "appledb",
	Aliases: []string{"db"},
	Short:   "Download IPSWs from appledb",
	Example: `  # Download the iOS 16.5 beta 4 kernelcache from remote IPSW
  ❯ ipsw download appledb --os iOS --version '16.5 beta 4' --device iPhone15,2 --kernel
   • Querying AppleDB...
   • Parsing remote IPSW       build=20F5059a devices=iPhone15,2 version=16.5
   • Extracting remote kernelcache
      • Writing 20F5059a__iPhone15,2/kernelcache.release.iPhone15,2`,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")
		// parent flags
		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))
		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
		removeCommas := viper.GetBool("download.remove-commas")
		// filters
		device := viper.GetString("download.device")
		version := viper.GetString("download.version")
		build := viper.GetString("download.build")
		// output
		asURLs := viper.GetBool("download.appledb.urls")
		asJSON := viper.GetBool("download.appledb.json")
		// flags
		osTypes := viper.GetStringSlice("download.appledb.os")
		fwType := viper.GetString("download.appledb.type")
		kernel := viper.GetBool("download.appledb.kernel")
		pattern := viper.GetString("download.appledb.pattern")
		isBeta := viper.GetBool("download.appledb.beta")
		latest := viper.GetBool("download.appledb.latest")
		prereqBuild := viper.GetString("download.appledb.prereq-build")
		output := viper.GetString("download.appledb.output")
		useAPI := viper.GetBool("download.appledb.api")
		apiToken := viper.GetString("download.appledb.api-token")
		flat := viper.GetBool("download.appledb.flat")
		// verify args
		for _, osType := range osTypes {
			if !utils.StrSliceHas(supportedOSes, osType) {
				return fmt.Errorf("valid --os flag choices are: %v", supportedOSes)
			}
		}
		if !utils.StrSliceHas(supportedFWs, fwType) {
			return fmt.Errorf("valid --type flag choices are: %v", supportedFWs)
		}
		if (asURLs || asJSON) && (kernel || len(pattern) > 0) {
			return fmt.Errorf("cannot use (--urls OR --json) with (--kernel OR --pattern)")
		}
		if isBeta && len(build) > 0 {
			return fmt.Errorf("cannot use --beta with --build")
		}
		if len(prereqBuild) > 0 && !(fwType == "ota" || fwType == "rsr") {
			return fmt.Errorf("cannot use --prereq-build with --type %s", fwType)
		}

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		if fwType == "rsr" {
			for idx, osType := range osTypes {
				if utils.StrSliceContains(supportedRsrOSes, osType) {
					osTypes[idx] = filepath.Join("Rapid Security Responses", osType)
				} else {
					return fmt.Errorf("for --type 'rsr', the valid --os choices are: %v", supportedRsrOSes)
				}
			}
		}

		var destPath string
		if len(output) > 0 {
			destPath = filepath.Clean(output)
		}

		if viper.GetBool("download.appledb.usb") {
			dev, err := utils.PickDevice()
			if err != nil {
				return err
			}
			device = dev.ProductType
			build = dev.BuildVersion
		}

		log.Info("Querying AppleDB...")
		var results []download.OsFileSource
		if useAPI {
			results, err = download.AppleDBQuery(&download.ADBQuery{
				OSes:              osTypes,
				Type:              fwType,
				Version:           version,
				Build:             build,
				PrerequisiteBuild: prereqBuild,
				Device:            device,
				IsBeta:            isBeta,
				Latest:            latest,
				Proxy:             proxy,
				Insecure:          insecure,
				APIToken:          apiToken,
			})
			if err != nil {
				return err
			}
		} else {
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
			results, err = download.LocalAppleDBQuery(&download.ADBQuery{
				OSes:              osTypes,
				Type:              fwType,
				Version:           version,
				Build:             build,
				PrerequisiteBuild: prereqBuild,
				Device:            device,
				IsBeta:            isBeta,
				Latest:            latest,
				Proxy:             proxy,
				Insecure:          insecure,
				APIToken:          apiToken,
				ConfigDir:         configDir,
			})
			if err != nil {
				return err
			}
		}

		log.Debug("URLs to download:")
		if asJSON {
			jsonData, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal json: %v", err)
			}

			if viper.GetBool("color") && !viper.GetBool("no-color") {
				if err := quick.Highlight(os.Stdout, string(jsonData)+"\n", "json", "terminal256", "nord"); err != nil {
					return fmt.Errorf("failed to highlight json: %v", err)
				}
			} else {
				fmt.Println(string(jsonData))
			}
			return nil
		}
		for _, result := range results {
			for _, link := range result.Links {
				if link.Active {
					if asURLs {
						fmt.Println(link.URL)
					} else {
						utils.Indent(log.Debug, 2)(link.URL)
					}
					break
				}
			}
		}
		if asURLs {
			return nil
		}

		cont := true
		if !confirm {
			if len(results) > 1 { // if filtered to a single device skip the prompt
				cont = false
				prompt := &survey.Confirm{
					Message: fmt.Sprintf("You are about to download %d IPSW files. Continue?", len(results)),
				}
				survey.AskOne(prompt, &cont)
			}
		}

		if cont {
			if kernel || len(pattern) > 0 {
				for _, result := range results {
					var url string
					for _, link := range result.Links {
						if link.Active {
							url = link.URL
						}
					}
					d, v, b := download.ParseIpswURLString(url)
					log.WithFields(log.Fields{"devices": d, "build": b, "version": v}).Info("Parsing remote IPSW")

					config := &extract.Config{
						URL:          url,
						Pattern:      pattern,
						Proxy:        proxy,
						Insecure:     insecure,
						KernelDevice: device,
						Flatten:      flat,
						Progress:     true,
						Output:       output,
					}

					// REMOTE KERNEL MODE
					if kernel {
						log.Info("Extracting remote kernelcache")
						if out, err := extract.Kernelcache(config); err != nil {
							return err
						} else {
							for fn := range out {
								utils.Indent(log.Info, 2)("Created " + fn)
							}
						}
					}
					// PATTERN MATCHING MODE
					if len(pattern) > 0 {
						log.Infof("Downloading files matching pattern %#v", pattern)
						if out, err := extract.Search(config); err != nil {
							return err
						} else {
							for _, f := range out {
								utils.Indent(log.Info, 2)("Created " + f)
							}
						}
					}
				}
			} else { // NORMAL MODE
				downloader := download.NewDownload(proxy, insecure, skipAll, resumeAll, restartAll, false, viper.GetBool("verbose"))
				for idx, result := range results {
					var url string
					for _, link := range result.Links {
						if link.Active {
							url = link.URL
						}
					}
					var fname string
					switch fwType {
					case "ipsw":
						fname = filepath.Join(destPath, getDestName(url, removeCommas))
					case "ota", "rsr":
						var details string
						if version != "" {
							details += fmt.Sprintf("%s_", version)
						}
						if build != "" {
							details += fmt.Sprintf("%s_", build)
						}
						if device != "" {
							details += fmt.Sprintf("%s_", device)
						} else {
							var devices string
							sort.Strings(result.DeviceMap)
							if len(result.DeviceMap) > 5 {
								devices = fmt.Sprintf("%s_and_%d_others", result.DeviceMap[0], len(result.DeviceMap)-1)
							} else {
								devices = strings.Join(result.DeviceMap, "_")
							}
							details += fmt.Sprintf("%s_", devices)
						}
						details += fmt.Sprintf("%s_", strings.ToUpper(result.Type))
						fname = filepath.Join(destPath, fmt.Sprintf("%s%s", details, getDestName(url, removeCommas)))
					}
					if _, err := os.Stat(fname); os.IsNotExist(err) {
						if fwType == "ipsw" {
							log.Infof("Getting (%d/%d) %s: %s", idx+1, len(results), strings.ToUpper(result.Type), filepath.Base(fname))
						} else {
							log.WithFields(log.Fields{"devices": result.DeviceMap}).Infof("Getting (%d/%d) %s: %s", idx+1, len(results), strings.ToUpper(result.Type), filepath.Base(fname))
						}
						// download file
						downloader.URL = url
						downloader.DestName = fname
						downloader.Sha1 = result.Hashes.Sha1

						err = downloader.Do()
						if err != nil {
							return fmt.Errorf("failed to download IPSW: %v", err)
						}
					} else {
						log.Warnf("IPSW already exists: %s", fname)
					}
				}
			}
		}

		return nil
	},
}
