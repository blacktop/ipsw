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
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(macosCmd)

	macosCmd.Flags().BoolP("installer", "", false, "Show latest macOS installers")
	// macosCmd.Flags().StringP("work-dir", "w", "", "macOS installer creator working directory")
	macosCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote installer")
}

// macosCmd represents the macos command
var macosCmd = &cobra.Command{
	Use:   "macos",
	Short: "Download and parse macOS IPSWs",
	RunE: func(cmd *cobra.Command, args []string) error {

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
		// proxy := viper.GetString("download.proxy")
		// insecure := viper.GetBool("download.insecure")
		// confirm := viper.GetBool("download.confirm")
		// skipAll := viper.GetBool("download.skip-all")
		// resumeAll := viper.GetBool("download.resume-all")
		// restartAll := viper.GetBool("download.restart-all")
		// removeCommas := viper.GetBool("download.remove-commas")
		// filters
		// device := viper.GetString("download.device")
		// model := viper.GetString("download.model")
		// version := viper.GetString("download.version")
		// build := viper.GetString("download.build")
		// doDownload := viper.GetStringSlice("download.white-list")
		// doNotDownload := viper.GetStringSlice("download.black-list")

		showInstallers, _ := cmd.Flags().GetBool("installer")
		// workDir, _ := cmd.Flags().GetString("work-dir")
		// remoteKernel, _ := cmd.Flags().GetBool("kernel")

		// var destPath string
		// if len(args) > 0 {
		// 	destPath = filepath.Clean(args[0])
		// }

		if showInstallers {
			if prods, err := download.GetProductInfo(); err != nil {
				log.Error(err.Error())
			} else {
				fmt.Println(prods)
				// for _, prod := range prods {
				// 	// if prod.ProductID == "071-14766" {
				// 	if prod.ProductID == "001-68446" {
				// 		if err := prod.DownloadInstaller(workDir, proxy, insecure, skipAll); err != nil {
				// 			log.Error(err.Error())
				// 		}
				// 	}
				// }
			}
			return nil
		}

		return nil
	},
}
