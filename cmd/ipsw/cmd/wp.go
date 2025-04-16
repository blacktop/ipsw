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
package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/wallpaper"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(wpCmd)

	wpCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	wpCmd.Flags().StringP("output", "o", "", "Folder to extract wallpapers to")
	wpCmd.MarkFlagDirname("output")
}

// wpCmd represents the wp command
var wpCmd = &cobra.Command{
	Use:           "wp <IPSW>",
	Short:         "🚧 Extract wallpapers from IPSW",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		// flags
		pemDB, _ := cmd.Flags().GetString("pem-db")
		// output, _ := cmd.Flags().GetString("output")

		ctx, err := mount.DmgInIPSW(filepath.Clean(args[0]), "fs", pemDB, nil)
		if err != nil {
			return fmt.Errorf("failed to mount %s DMG: %v", args[0], err)
		}
		defer ctx.Unmount()

		wp, err := wallpaper.ParseFolder(ctx.MountPoint)
		if err != nil {
			return fmt.Errorf("failed to parse wallpaper folder: %v", err)
		}

		log.WithFields(log.Fields{
			"id":         wp.DefaultWallpaper.Default.WallpaperIdentifier,
			"collection": wp.DefaultWallpaper.Default.CollectionIdentifier,
		}).Info("Default Wallpaper")

		for _, collection := range wp.Collections {
			log.WithFields(log.Fields{
				"id":   collection.Meta.ID,
				"name": collection.Meta.Name,
			}).Info("Collection")
			for _, wallpaper := range collection.Wallpapers {
				if sz, err := wallpaper.GetSize(); err == nil {
					utils.Indent(log.WithFields(log.Fields{
						"id":    wallpaper.Meta.ID,
						"name":  wallpaper.Meta.Name,
						"size":  fmt.Sprintf("%dw⨯%dh", sz.Width, sz.Height),
						"scale": fmt.Sprintf("%dx", sz.Scale),
					}).Info, 2)("Wallpaper")
				} else {
					utils.Indent(log.WithFields(log.Fields{
						"id":   wallpaper.Meta.ID,
						"name": wallpaper.Meta.Name,
					}).Info, 2)("Wallpaper")
				}
			}
		}
		for _, cwp := range wp.CarPlays {
			log.WithField("name", filepath.Base(cwp)).Info("CarPlay")
		}

		return nil
	},
}
