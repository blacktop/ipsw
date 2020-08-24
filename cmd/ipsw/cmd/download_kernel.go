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
	"math/rand"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	downloadCmd.AddCommand(downloadKernelCmd)
}

type stop struct {
	error
}

func retry(attempts int, sleep time.Duration, f func() error) error {
	if err := f(); err != nil {
		if s, ok := err.(stop); ok {
			// Return the original error for later checking
			return s.error
		}

		if attempts--; attempts > 0 {
			jitter := time.Duration(rand.Int63n(int64(sleep)))
			sleep = sleep + jitter/2

			time.Sleep(sleep)
			return retry(attempts, 2*sleep, f)
		}
		return err
	}

	return nil
}

// downloadKernelCmd represents the downloadKernel command
var downloadKernelCmd = &cobra.Command{
	Use:   "kernel",
	Short: "Download just the kernelcache",
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")

		ipsws, err := filterIPSWs(cmd)
		if err != nil {
			log.Fatal(err.Error())
		}

		log.Debug("URLs to Download:")
		for _, i := range ipsws {
			utils.Indent(log.Debug, 2)(i.URL)
		}

		for _, i := range ipsws {

			log.WithFields(log.Fields{
				"device":  i.Identifier,
				"build":   i.BuildID,
				"version": i.Version,
				"signed":  i.Signed,
			}).Info("Getting Kernelcache")

			err = retry(3, time.Second, func() error {
				zr, err := download.NewRemoteZipReader(i.URL, &download.RemoteConfig{
					Proxy:    proxy,
					Insecure: insecure,
				})
				if err != nil {
					return errors.Wrap(err, "failed to create remote zip reader of ipsw")
				}

				err = kernelcache.RemoteParseV2(zr, i.BuildID)
				if err != nil {
					return errors.Wrap(err, "failed to download kernelcache from remote ipsw")
				}

				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	},
}
