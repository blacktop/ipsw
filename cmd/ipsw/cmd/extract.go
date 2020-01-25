// +build !windows,cgo

/*
Copyright © 2019 blacktop

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
	"net/url"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	kernelFlag     bool
	dyldFlag       bool
	deviceTreeFlag bool
	remote         bool
)

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	extractCmd.Flags().Bool("insecure", false, "do not verify ssl certs")

	extractCmd.Flags().BoolVarP(&remote, "remote", "r", false, "Extract from URL")
	extractCmd.Flags().BoolVarP(&kernelFlag, "kernel", "k", false, "Extract kernelcache")
	extractCmd.Flags().BoolVarP(&dyldFlag, "dyld", "d", false, "Extract dyld_shared_cache")
	extractCmd.Flags().BoolVarP(&deviceTreeFlag, "device-tree", "t", false, "Extract DeviceTree")

	extractCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw")
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract <IPSW | URL>",
	Short: "Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if remote {
			proxy, _ := cmd.Flags().GetString("proxy")
			insecure, _ := cmd.Flags().GetBool("insecure")

			if !isURL(args[0]) {
				log.Fatal("must supply valid URL when using the remote flag")
			}

			if deviceTreeFlag {
				log.Error("unable to extract DeviceTree remotely (for now)")
				// err := devicetree.RemoteParse(args[0])
				// if err != nil {
				// 	return errors.Wrap(err, "failed to extract DeviceTree")
				// }
			}
			if dyldFlag {
				log.Error("unable to extract dyld_shared_cache remotely")
			}
			if kernelFlag {
				log.Info("Extracting Kernelcache")
				zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
					Proxy:    proxy,
					Insecure: insecure,
				})
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}

				err = kernelcache.RemoteParse(zr)
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcaches from remote ipsw")
				}
			}
		} else {
			if _, err := os.Stat(args[0]); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", args[0])
			}

			if kernelFlag {
				log.Info("Extracting kernelcaches")
				err := kernelcache.Extract(args[0])
				if err != nil {
					return errors.Wrap(err, "failed to extract kernelcaches")
				}
			}

			if dyldFlag {
				log.Info("Extracting dyld_shared_cache")
				err := dyld.Extract(args[0])
				if err != nil {
					return errors.Wrap(err, "failed to extract dyld_shared_cache")
				}
			}

			if deviceTreeFlag {
				log.Info("Extracting DeviceTrees")
				err := devicetree.Extract(args[0])
				if err != nil {
					return errors.Wrap(err, "failed to extract DeviceTrees")
				}
			}
		}

		return nil
	},
}
