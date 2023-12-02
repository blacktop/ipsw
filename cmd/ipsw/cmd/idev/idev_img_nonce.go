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
	"encoding/json"
	"fmt"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/mount"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	ImgCmd.AddCommand(nonceCmd)

	nonceCmd.Flags().BoolP("json", "j", false, "Print as JSON")
	nonceCmd.Flags().BoolP("readable", "r", false, "Print nonce as a more readable string")
	nonceCmd.Flags().BoolP("qr-code", "q", false, "Generate QR code of nonce")
	nonceCmd.Flags().IntP("qr-size", "z", 256, "QR size in pixels")
	nonceCmd.Flags().String("url", "", "QR code URL")
	nonceCmd.Flags().StringP("mail", "m", "", "QR mailto address")
	nonceCmd.Flags().StringP("subject", "s", "Device Nonce Info", "QR mailto subject")
	nonceCmd.Flags().StringP("output", "o", "", "Folder to write QR code PNG to")
	nonceCmd.MarkFlagDirname("output")
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
		color.NoColor = viper.GetBool("no-color")

		// flags
		udid, _ := cmd.Flags().GetString("udid")
		asJSON, _ := cmd.Flags().GetBool("json")
		readable, _ := cmd.Flags().GetBool("readable")
		asQrCode, _ := cmd.Flags().GetBool("qr-code")
		qrcSize, _ := cmd.Flags().GetInt("qr-size")
		qrURL, _ := cmd.Flags().GetString("url")
		email, _ := cmd.Flags().GetString("mail")
		emailSubject, _ := cmd.Flags().GetString("subject")
		output, _ := cmd.Flags().GetString("output")
		// Validate flags
		if asQrCode && readable {
			return fmt.Errorf("cannot specify both --qr-code and --readable")
		} else if len(qrURL) > 0 && len(email) > 0 {
			return fmt.Errorf("cannot specify both --url and --mail")
		}

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

		nonce, err := cli.Nonce("DeveloperDiskImage")
		if err != nil {
			return fmt.Errorf("failed to get nonce: %w", err)
		}

		personalID, err := cli.PersonalizationIdentifiers("")
		if err != nil {
			log.Errorf("failed to get personalization identifiers: %v ('personalization' might not be supported on this device)", err)
		}

		personalID["ApNonce"] = nonce

		delete(personalID, "CertificateProductionStatus")
		delete(personalID, "EffectiveProductionStatusAp")
		delete(personalID, "SecurityDomain")
		delete(personalID, "CertificateSecurityMode")
		delete(personalID, "EffectiveSecurityModeAp")

		if asQrCode {
			// Create the barcode
			var parts []string
			var qrCodeStr string
			for k, v := range personalID {
				switch t := v.(type) {
				case uint64:
					parts = append(parts, fmt.Sprintf("%s=%d", k, t))
				case string:
					parts = append(parts, fmt.Sprintf("%s=%s", k, t))
				}
			}
			qrCodeStr = strings.Join(parts, ",")
			if len(email) > 0 {
				qrCodeStr = fmt.Sprintf("mailto:%s?subject=%s&body=%s", email, emailSubject, qrCodeStr)
			} else if len(qrURL) > 0 {
				qrCodeStr = strings.Join(parts, "&")
				u, err := url.Parse(fmt.Sprintf("%s?%s", qrURL, qrCodeStr))
				if err != nil {
					return fmt.Errorf("failed to parse URL: %w", err)
				}
				qrCodeStr = u.String()
			}
			qrCode, err := qr.Encode(qrCodeStr, qr.M, qr.Auto)
			if err != nil {
				return fmt.Errorf("failed to encode nonce as QR code: %w", err)
			}
			// Scale the barcode to 512x512 pixels
			qrCode, err = barcode.Scale(qrCode, 512, 512)
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

			log.Warn("Displaying QR code in terminal (supported in iTerm2 and VSCode, otherwise supply --output flag)")
			println()
			return utils.DisplayImageInTerminal(bytes.NewReader(dat.Bytes()), dat.Len(), qrcSize, qrcSize)
		}

		if readable {
			if personalID != nil {
				fmt.Printf("%s %d\n", color.New(color.Faint, color.FgHiBlue).Sprintf("ApBoardID: "), personalID["BoardId"])
				fmt.Printf("%s %d\n", color.New(color.Faint, color.FgHiBlue).Sprintf("ApChipID:  "), personalID["ChipID"])
				fmt.Printf("%s %d\n", color.New(color.Faint, color.FgHiBlue).Sprintf("ApECID:    "), personalID["UniqueChipID"])
			}
			fmt.Println(color.New(color.Faint, color.FgHiBlue).Sprintf("Nonce:"))
			var out string
			for i, c := range nonce {
				if i > 0 && i%4 == 0 && i%24 != 0 {
					out += color.New(color.Faint).Sprint("-")
				} else if i > 0 && i%24 == 0 {
					out += "\n"
				}
				out += color.New(color.Bold).Sprintf("%c", c)
			}
			fmt.Println(out)
		} else {
			if asJSON {
				var out []byte
				if personalID == nil {
					out, err = json.MarshalIndent(&struct {
						ApNonce string `json:"nonce,omitempty"`
					}{
						ApNonce: nonce,
					}, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal JSON: %w", err)
					}
				} else {
					out, err = json.MarshalIndent(personalID, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal JSON: %w", err)
					}
				}
				fmt.Println(string(out))
			} else {
				fmt.Println(nonce)
			}
		}

		return nil
	},
}
