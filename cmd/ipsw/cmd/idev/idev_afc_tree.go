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
package idev

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/afc"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	AfcCmd.AddCommand(idevAfcTreeCmd)

	idevAfcTreeCmd.Flags().BoolP("flat", "f", false, "Flat output")
	viper.BindPFlag("idev.afc.tree.flat", idevAfcTreeCmd.Flags().Lookup("flat"))
}

// idevAfcTreeCmd represents the tree command
var idevAfcTreeCmd = &cobra.Command{
	Use:           "tree",
	Short:         "List contents of directories in a tree-like format rooted at /var/mobile/Media",
	Args:          cobra.MaximumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		flat := viper.GetBool("idev.afc.tree.flat")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := afc.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to afc: %w", err)
		}
		defer cli.Close()

		fpath := "/"

		if len(args) > 0 {
			fpath = args[0]
		}

		var dirColor = colors.BoldHiBlue().SprintFunc()
		var sizeColor = colors.BoldHiMagenta().SprintFunc()

		if flat {
			if err := cli.Walk(fpath, func(path string, info os.FileInfo, err error) error {
				if info.IsDir() {
					fmt.Println(dirColor(path))
				} else {
					if viper.GetBool("verbose") {
						fmt.Printf("%s (%s)\n", path, sizeColor(humanize.Bytes(uint64(info.Size()))))
					} else {
						fmt.Println(path)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to walk %s: %w", fpath, err)
			}
		} else {
			tree := afc.NewTree(fpath, dirColor(fpath))
			curDir := tree
			if err := cli.Walk(fpath, func(path string, info os.FileInfo, err error) error {
				if info.IsDir() {
					if tree.Path() == path { // skip root dir
						return nil
					}
					// fmt.Printf("curDir.Text()=%s\nfilepath.Dir(path)=%s\n", curDir.Text(), filepath.Dir(path))
					pathDir := filepath.Dir(path)
					_ = pathDir
					if tree.Path() == filepath.Dir(path) {
						curDir = tree.Add(path, dirColor(filepath.Base(path)))
					} else if curDir.Path() == filepath.Dir(path) {
						curDir = curDir.Add(path, dirColor(filepath.Base(path)))
					} else {
						node := tree.Find(filepath.Dir(path))
						if node != nil {
							curDir = node.Add(path, dirColor(filepath.Base(path)))
						} else {
							log.Warnf("failed to find node for %s", filepath.Dir(path))
						}
					}
				} else {
					text := filepath.Base(path)
					if viper.GetBool("verbose") {
						text = fmt.Sprintf("%s (%s)", text, sizeColor(humanize.Bytes(uint64(info.Size()))))
					}
					if curDir.Path() == filepath.Dir(path) {
						curDir.Add(path, text)
					} else {
						if node := tree.Find(filepath.Dir(path)); node != nil {
							node.Add(path, text)
						} else {
							log.Warnf("failed to find node for %s", filepath.Dir(path))
						}
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to walk %s: %w", fpath, err)
			}

			fmt.Println(tree.Print())
		}
		return nil
	},
}
