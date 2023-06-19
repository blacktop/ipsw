/*
Copyright © 2023 blacktop

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
	"bufio"
	"bytes"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(nonceCmd)

	nonceCmd.Flags().BoolP("qr-code", "q", false, "Generate QR code of nonce")
	nonceCmd.Flags().StringP("output", "o", "", "Folder to write QR code PNG to")
}

// nonceCmd represents the nonce command
var nonceCmd = &cobra.Command{
	Use:           "nonce",
	Short:         "Query Nonce",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid, _ := cmd.Flags().GetString("udid")
		asQrCode, _ := cmd.Flags().GetBool("qr-code")
		output, _ := cmd.Flags().GetString("output")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
		}

		cli, err := mount.NewClient(udid)
		if err != nil {
			return fmt.Errorf("failed to connect to mobile_image_mounter: %w", err)
		}
		defer cli.Close()

		personalID, err := cli.PersonalizationIdentifiers("")
		if err != nil {
			return fmt.Errorf("failed to get personalization identifiers: %w", err)
		}

		nonce, err := cli.Nonce("DeveloperDiskImage")
		if err != nil {
			return fmt.Errorf("failed to get nonce: %w", err)
		}

		if asQrCode {
			// Create the barcode
			qrCode, err := qr.Encode(fmt.Sprintf("ApBoardID=%d,ApChipID=%d,ApECID=%d,ApNonce=%s", personalID["BoardId"], personalID["ChipID"], personalID["UniqueChipID"], nonce), qr.M, qr.Auto)
			if err != nil {
				return fmt.Errorf("failed to encode nonce as QR code: %w", err)
			}
			// Scale the barcode to 500x500 pixels
			qrCode, err = barcode.Scale(qrCode, 500, 500)
			if err != nil {
				return fmt.Errorf("failed to scale QR code: %w", err)
			}

			var dat bytes.Buffer
			buf := bufio.NewWriter(&dat)
			if err := png.Encode(buf, qrCode); err != nil {
				return fmt.Errorf("failed to encode QR code as PNG: %w", err)
			}
			buf.Flush()

			if len(output) > 0 {
				if err := os.MkdirAll(output, 0750); err != nil {
					return fmt.Errorf("failed to create output folder: %w", err)
				}
				fname := filepath.Join(output, fmt.Sprintf("nonce_qr_code_%s.png", time.Now().Format("02Jan2006_150405")))
				log.Infof("Writing QR code to %s", fname)
				return os.WriteFile(fname, dat.Bytes(), 0644)
			}

			log.Warn("Displaying QR code in terminal (supported in iTerm2)")
			println()
			return utils.DisplayImageInTerminal(bytes.NewReader(dat.Bytes()), 500, 500)
		}

		fmt.Println(nonce)

		return nil
	},
}
