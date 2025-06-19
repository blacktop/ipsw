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
package cmd

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(infoCmd)
	infoCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	infoCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	infoCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	infoCmd.Flags().BoolP("list", "l", false, "List files in IPSW/OTA")
	infoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	infoCmd.Flags().BoolP("lookup", "k", false, "Lookup DMG keys on theapplewiki.com")

	viper.BindPFlag("info.proxy", infoCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("info.insecure", infoCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("info.remote", infoCmd.Flags().Lookup("remote"))
	viper.BindPFlag("info.list", infoCmd.Flags().Lookup("list"))
	viper.BindPFlag("info.json", infoCmd.Flags().Lookup("json"))
	viper.BindPFlag("info.lookup", infoCmd.Flags().Lookup("lookup"))

	infoCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw", "*.zip")
	infoCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	}
}

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:           "info <IPSW>",
	Aliases:       []string{"i"},
	Short:         "Display IPSW/OTA Info",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var i *info.Info

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetBool("info.remote") {
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
				Proxy:    viper.GetString("info.proxy"),
				Insecure: viper.GetBool("info.insecure"),
			})
			if err != nil {
				return fmt.Errorf("failed to create new remote zip reader: %w", err)
			}
			if viper.GetBool("info.list") {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
				fmt.Fprintf(w, "PATH\tSIZE\n")
				fmt.Fprintf(w, "----\t----\n")
				for _, f := range zr.File {
					fmt.Fprintf(w, "%s\t%s\n", f.Name, humanize.Bytes(f.UncompressedSize64))
				}
				w.Flush()
			} else {
				i, err = info.ParseZipFiles(zr.File)
				if err != nil {
					return fmt.Errorf("failed to parse plists in zip: %w", err)
				}
			}
		} else { // LOCAL
			fPath := filepath.Clean(args[0])
			if _, err := os.Stat(fPath); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", fPath)
			}
			if viper.GetBool("info.list") {
				zr, err := zip.OpenReader(fPath)
				if err != nil {
					return fmt.Errorf("failed to open %s: %v", fPath, err)
				}
				defer zr.Close()

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
				fmt.Fprintf(w, "PATH\tSIZE\n")
				fmt.Fprintf(w, "----\t----\n")
				for _, f := range zr.File {
					fmt.Fprintf(w, "%s\t%s\n", f.Name, humanize.Bytes(f.UncompressedSize64))
				}
				w.Flush()
			} else {
				var err error
				if viper.GetBool("info.lookup") {
					var (
						device  string
						version string
						build   string
					)
					re := regexp.MustCompile(`(?P<device>.+)_(?P<version>.+)_(?P<build>.+)_(?i)Restore\.ipsw$`)
					if re.MatchString(fPath) {
						matches := re.FindStringSubmatch(fPath)
						if len(matches) < 4 {
							return fmt.Errorf("failed to parse IPSW filename: %s", fPath)
						}
						device = filepath.Base(matches[1])
						version = matches[2]
						build = matches[3]
					} else {
						return fmt.Errorf("failed to parse IPSW filename: %s", fPath)
					}
					if device == "" || build == "" {
						return fmt.Errorf("device or build information is missing from IPSW filename (required for key lookup)")
					}
					log.Info("Downloading Keys...")
					wkeys, err := download.GetWikiFirmwareKeys(&download.WikiConfig{
						Keys:    true,
						Device:  strings.Replace(device, "ip", "iP", 1),
						Version: version,
						Build:   strings.ToUpper(build),
						// Beta:    viper.GetBool("download.key.beta"),
					}, "", false)
					if err != nil {
						return fmt.Errorf("failed querying theapplewiki.com: %v", err)
					}
					dtkey, err := wkeys.GetKeyByRegex(`.*DeviceTree.*(img3|im4p)$`)
					if err != nil {
						return fmt.Errorf("failed to get DeviceTree key: %v", err)
					}
					i, err = info.Parse(fPath, dtkey)
					if err != nil {
						return fmt.Errorf("failed to parse IPSW: %v", err)
					}
				} else {
					i, err = info.Parse(fPath)
					if err != nil {
						return fmt.Errorf("failed to parse IPSW: %v", err)
					}
				}
			}
		}
		// DISPLAY
		if !viper.GetBool("info.list") {
			if viper.GetBool("info.json") {
				dat, err := json.Marshal(i.ToJSON())
				if err != nil {
					return fmt.Errorf("failed to JSON marshal info: %v", err)
				}
				fmt.Println(string(dat))
			} else {
				title := fmt.Sprintf("[%s Info]", i.Plists.Type)
				fmt.Printf("\n%s\n", title)
				fmt.Println(strings.Repeat("=", len(title)))
				fmt.Println(i)
				if Verbose {
					if i.Plists.BuildManifest != nil {
						fmt.Println(i.Plists.BuildManifest)
					}
					if i.Plists.Restore != nil {
						fmt.Println(i.Plists.Restore)
					}
					if i.Plists.AssetDataInfo != nil {
						fmt.Println(i.Plists.AssetDataInfo)
					}
					if i.Plists.OTAInfo != nil {
						fmt.Println(i.Plists.OTAInfo)
					}
				}
			}
		}

		return nil
	},
}
