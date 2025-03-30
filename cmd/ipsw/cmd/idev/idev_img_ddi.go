//go:build darwin

/*
Copyright © 2025 blacktop

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
package idev

import (
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(ddiCmd)

	ddiCmd.Flags().BoolP("info", "i", false, "Show DDI info")
	ddiCmd.Flags().BoolP("xcode", "x", false, "Update DDI from Xcode")
	ddiCmd.Flags().StringP("source-dir", "s", "", "Update DDI from source directory")
	ddiCmd.Flags().BoolP("clean", "c", false, "Clean DDI")
	viper.BindPFlag("idev.img.ddi.info", ddiCmd.Flags().Lookup("info"))
	viper.BindPFlag("idev.img.ddi.xcode", ddiCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.ddi.source-dir", ddiCmd.Flags().Lookup("source-dir"))
	viper.BindPFlag("idev.img.ddi.clean", ddiCmd.Flags().Lookup("clean"))
}

// ddiCmd represents the ddi command
var ddiCmd = &cobra.Command{
	Use:   "ddi",
	Short: "DDI commands",
	// SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if !viper.IsSet("idev.img.ddi.info") && !viper.IsSet("idev.img.ddi.xcode") && !viper.IsSet("idev.img.ddi.source-dir") && !viper.IsSet("idev.img.ddi.clean") {
			return fmt.Errorf("no subcommand provided, must provide one of: --info, --xcode, --source-dir, --clean")
		}

		if viper.GetBool("idev.img.ddi.info") {
			ddi, err := utils.PreferredDDI()
			if err != nil {
				return fmt.Errorf("failed to get preferred DDI: %v", err)
			}
			if len(ddi.Result.Platforms.IOS) == 0 &&
				len(ddi.Result.Platforms.MacOS) == 0 &&
				len(ddi.Result.Platforms.TvOS) == 0 &&
				len(ddi.Result.Platforms.WatchOS) == 0 &&
				len(ddi.Result.Platforms.XrOS) == 0 {
				log.Warn("no DDIs found")
			}
			for _, platform := range ddi.Result.Platforms.IOS {
				fmt.Println(platform.String())
			}
			for _, platform := range ddi.Result.Platforms.MacOS {
				fmt.Println(platform.String())
			}
			for _, platform := range ddi.Result.Platforms.TvOS {
				fmt.Println(platform.String())
			}
			for _, platform := range ddi.Result.Platforms.WatchOS {
				fmt.Println(platform.String())
			}
			for _, platform := range ddi.Result.Platforms.XrOS {
				fmt.Println(platform.String())
			}
		} else if viper.GetBool("idev.img.ddi.xcode") {
			out, err := utils.UpdateDDIsFromXCode()
			if err != nil {
				return fmt.Errorf("failed to update DDIs from Xcode: %v", err)
			}
			fmt.Println(out)
		} else if viper.GetBool("idev.img.ddi.source-dir") {
			out, err := utils.UpdateDDIs(viper.GetString("idev.img.ddi.source-dir"))
			if err != nil {
				return fmt.Errorf("failed to update DDIs from source directory: %v", err)
			}
			fmt.Println(out)
		} else if viper.GetBool("idev.img.ddi.clean") {
			out, err := utils.CleanDDIs()
			if err != nil {
				return fmt.Errorf("failed to clean DDIs: %v", err)
			}
			fmt.Println(out)
		}

		return nil
	},
}
