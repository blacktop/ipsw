/*
Copyright © 2018-2022 blacktop

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
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	downloadCmd.AddCommand(macosCmd)

	macosCmd.Flags().BoolP("list", "l", false, "Show latest macOS installers")
	macosCmd.Flags().StringP("work-dir", "w", "", "macOS installer creator working directory")
	// macosCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote installer")
	viper.BindPFlag("download.macos.list", macosCmd.Flags().Lookup("list"))
	viper.BindPFlag("download.macos.work-dir", macosCmd.Flags().Lookup("work-dir"))
	// viper.BindPFlag("download.macos.kernel", macosCmd.Flags().Lookup("kernel"))
}

// macosCmd represents the macos command
var macosCmd = &cobra.Command{
	Use:           "macos",
	Short:         "Download macOS installers",
	SilenceUsage:  false,
	SilenceErrors: true,
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
		// viper.BindPFlag("download.remove-commas", cmd.Flags().Lookup("remove-commas"))
		viper.BindPFlag("download.white-list", cmd.Flags().Lookup("white-list"))
		viper.BindPFlag("download.black-list", cmd.Flags().Lookup("black-list"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.model", cmd.Flags().Lookup("model"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

		cmd.Flags().Lookup("remove-commas").Hidden = true

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
		// filters
		version := viper.GetString("download.version")
		build := viper.GetString("download.build")
		// flags
		showInstallers := viper.GetBool("download.macos.list")
		workDir := viper.GetString("download.macos.work-dir")
		// remoteKernel := viper.GetString("download.macos.kernel")

		// verify args
		if len(version) > 0 && len(build) > 0 {
			return fmt.Errorf("you cannot supply a --version AND a --build (they are mutually exclusive)")
		}

		prods, err := download.GetProductInfo()
		if err != nil {
			return err
		}

		if showInstallers {
			fmt.Println(prods)
			return nil
		}

		if len(version) > 0 {
			prods = prods.FilterByVersion(version)
		}

		var prodList []string
		for _, p := range prods {
			prodList = append(prodList, fmt.Sprintf("%-35s%-8s - %-8s - %s", p.Title, p.Version, p.Build, p.PostDate.Format("01Jan06 15:04:05")))
		}

		if len(prodList) == 0 {
			return fmt.Errorf("no installers found for given options")
		}

		var prod download.ProductInfo
		if len(prodList) > 1 && len(build) == 0 {
			choice := 0
			prompt := &survey.Select{
				Message:  "Choose an installer:",
				Options:  prodList,
				PageSize: 20,
			}
			if err := survey.AskOne(prompt, &choice); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				log.Fatal(err.Error())
			}
			prod = prods[choice]
		} else {
			for _, p := range prods {
				if version == p.Version || build == p.Build {
					prod = p
				}
			}
		}

		cont := true
		if !confirm {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf("You are about to download the %s installer files. Continue?", prod.Title),
			}
			if err := survey.AskOne(prompt, &cont); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				log.Fatal(err.Error())
			}
		}
		if cont {
			if err := prod.DownloadInstaller(workDir, proxy, insecure, skipAll, resumeAll, restartAll); err != nil {
				return err
			}
		}

		return nil
	},
}
