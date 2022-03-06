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
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(infoCmd)
	infoCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	infoCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	infoCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	infoCmd.Flags().BoolP("list", "l", false, "List files in IPSW/OTA")
	infoCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw", "*.zip")
	infoCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	}
}

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:           "info <IPSW>",
	Short:         "Display IPSW/OTA Info",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var i *info.Info

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// settings
		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		// flags
		remoteFlag, _ := cmd.Flags().GetBool("remote")
		listFiles, _ := cmd.Flags().GetBool("list")

		if remoteFlag {
			zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
				Proxy:    proxy,
				Insecure: insecure,
			})
			if err != nil {
				return fmt.Errorf("failed to create new remote zip reader: %w", err)
			}
			if listFiles {
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
		} else {
			fPath := filepath.Clean(args[0])
			if _, err := os.Stat(fPath); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", fPath)
			}
			if listFiles {
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
				i, err = info.Parse(fPath)
				if err != nil {
					return fmt.Errorf("failed to parse plists: %w", err)
				}
			}
		}

		if !listFiles {
			title := fmt.Sprintf("[%s Info]", i.Plists.Type)
			fmt.Printf("\n%s\n", title)
			fmt.Println(strings.Repeat("=", len(title)))
			fmt.Println(i)
		}

		return nil
	},
}
