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
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(ddiCmd)

	ddiCmd.Flags().BoolP("info", "i", false, "Show DDI info")
	ddiCmd.Flags().BoolP("xcode", "x", false, "Update DDI from Xcode")
	ddiCmd.Flags().StringP("source", "s", "", "Update DDI from source directory")
	ddiCmd.Flags().BoolP("clean", "c", false, "Clean DDI")
	ddiCmd.Flags().BoolP("backup", "b", false, "Backup DDI")
	ddiCmd.Flags().StringP("output", "o", "", "Output directory")
	ddiCmd.MarkFlagDirname("output")
	viper.BindPFlag("idev.img.ddi.info", ddiCmd.Flags().Lookup("info"))
	viper.BindPFlag("idev.img.ddi.xcode", ddiCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("idev.img.ddi.source", ddiCmd.Flags().Lookup("source"))
	viper.BindPFlag("idev.img.ddi.clean", ddiCmd.Flags().Lookup("clean"))
	viper.BindPFlag("idev.img.ddi.backup", ddiCmd.Flags().Lookup("backup"))
	viper.BindPFlag("idev.img.ddi.output", ddiCmd.Flags().Lookup("output"))
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

		if !viper.IsSet("idev.img.ddi.info") &&
			!viper.IsSet("idev.img.ddi.xcode") &&
			!viper.IsSet("idev.img.ddi.source") &&
			!viper.IsSet("idev.img.ddi.clean") &&
			!viper.IsSet("idev.img.ddi.backup") {
			return fmt.Errorf("no subcommand provided, must provide one of: --info, --xcode, --source, --clean, --backup")
		}
		if (viper.IsSet("idev.img.ddi.source") || viper.IsSet("idev.img.ddi.clean")) && viper.IsSet("idev.img.ddi.backup") {
			return fmt.Errorf("cannot specify both --backup AND [--source or --clean]")
		}

		if viper.GetBool("idev.img.ddi.info") {
			ddi, err := utils.PreferredDDI()
			if err != nil {
				return fmt.Errorf("failed to get preferred DDI: %v", err)
			}
			if ddi.Empty() {
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
		} else if viper.IsSet("idev.img.ddi.source") {
			if isZip, _ := magic.IsZip(viper.GetString("idev.img.ddi.source")); isZip {
				tmpdir, err := os.MkdirTemp("", "ddi-")
				if err != nil {
					return fmt.Errorf("failed to create temporary directory: %v", err)
				}
				defer os.RemoveAll(tmpdir)

				log.Infof("Extracting %s to %s", viper.GetString("idev.img.ddi.source"), tmpdir)
				zipReader, err := zip.OpenReader(viper.GetString("idev.img.ddi.source"))
				if err != nil {
					return fmt.Errorf("failed to open zip file: %v", err)
				}
				defer zipReader.Close()

				for _, file := range zipReader.File {
					filePath := filepath.Join(tmpdir, file.Name)
					// Create directory tree
					if file.FileInfo().IsDir() {
						if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
							return fmt.Errorf("failed to create directory: %v", err)
						}
						continue
					}
					// Create parent directory if needed
					if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
						return fmt.Errorf("failed to create parent directory: %v", err)
					}
					// Extract file
					srcFile, err := file.Open()
					if err != nil {
						return fmt.Errorf("failed to open file in zip: %v", err)
					}
					dstFile, err := os.Create(filePath)
					if err != nil {
						srcFile.Close()
						return fmt.Errorf("failed to create destination file: %v", err)
					}
					if _, err := io.Copy(dstFile, srcFile); err != nil {
						srcFile.Close()
						dstFile.Close()
						return fmt.Errorf("failed to copy file contents: %v", err)
					}
					srcFile.Close()
					dstFile.Close()
				}
				// Update source to use the extracted path
				viper.Set("idev.img.ddi.source", tmpdir)
			}
			out, err := utils.UpdateDDIs(viper.GetString("idev.img.ddi.source"))
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

		if viper.GetBool("idev.img.ddi.backup") {
			out, err := utils.BackupDDIs(viper.GetString("idev.img.ddi.output"))
			if err != nil {
				return fmt.Errorf("failed to backup DDIs: %v", err)
			}
			log.Infof("DDI backup created at: %s", out)
		}

		return nil
	},
}
