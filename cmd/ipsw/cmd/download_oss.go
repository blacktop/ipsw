/*
Copyright © 2021 blacktop

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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(ossCmd)

	ossCmd.Flags().String("macos", "", "macOS version to download")
	ossCmd.MarkFlagRequired("macos")
	ossCmd.Flags().BoolP("all", "a", false, "Download all the files")
	ossCmd.Flags().StringP("product", "p", "", "macOS product to download (i.e. dyld)")
	viper.BindPFlag("download.oss.macos", ossCmd.Flags().Lookup("macos"))
	viper.BindPFlag("download.oss.all", ossCmd.Flags().Lookup("all"))
	viper.BindPFlag("download.oss.product", ossCmd.Flags().Lookup("product"))
}

// ossCmd represents the oss command
var ossCmd = &cobra.Command{
	Use:           "oss <macOS version>",
	Short:         "Download opensource.apple.com file list for macOS version",
	SilenceUsage:  false,
	SilenceErrors: true,
	Run: func(cmd *cobra.Command, args []string) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
		viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.white-list", cmd.Flags().Lookup("white-list"))
		viper.BindPFlag("download.black-list", cmd.Flags().Lookup("black-list"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.model", cmd.Flags().Lookup("model"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))
		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		// flags
		macOS := viper.GetString("download.oss.macos")
		downloadAll := viper.GetBool("download.oss.all")
		downloadProduct := viper.GetString("download.oss.product")

		o, err := download.NewOSS(strings.Replace(macOS, ".", "", -1), proxy, insecure)
		if err != nil {
			log.Fatal(err.Error())
		}

		if downloadAll {
			for _, product := range o.Projects {
				err = product.Download()
				if err != nil {
					utils.Indent(log.Error, 2)(err.Error())
				}
			}
		} else if len(downloadProduct) > 0 {
			for name, product := range o.Projects {
				if strings.Contains(strings.ToLower(name), downloadProduct) {
					err = product.Download()
					if err != nil {
						utils.Indent(log.Error, 2)(err.Error())
					}
				}
			}
		} else {
			if dat, err := json.MarshalIndent(o, "", "   "); err == nil {
				fmt.Println(string(dat))
			} else {
				log.Fatal(err.Error())
			}
		}
	},
}
