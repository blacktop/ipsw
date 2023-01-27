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
package cmd

import (
	"archive/zip"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/usb/pongo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(pongoCmd)
	pongoCmd.Flags().StringP("output", "o", "", "Folder to write JSON to")
	viper.BindPFlag("pongo.output", pongoCmd.Flags().Lookup("output"))
}

// pongoCmd represents the pongo command
var pongoCmd = &cobra.Command{
	Use:           "pongo <IPSW>",
	Short:         "PongoOS Terminal",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		ipswPath := filepath.Clean(args[0])

		if _, err := os.Stat(ipswPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", ipswPath)
		}

		i, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse plists in IPSW: %v", err)
		}
		folder, err := i.GetFolder()
		if err != nil {
			log.Errorf("failed to get folder from remote zip metadata: %v", err)
		}
		destPath := filepath.Join(filepath.Clean(viper.GetString("pongo.output")), folder)

		zr, err := zip.OpenReader(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to open zip: %v", err)
		}
		defer zr.Close()

		kbags, err := img4.ParseZipKeyBags(zr.File, i, "")
		if err != nil {
			return fmt.Errorf("failed to parse IPSW im4p kbags: %v", err)
		}

		cli, err := pongo.NewClient()
		if err != nil {
			return fmt.Errorf("failed to connect to pongo: %w", err)
		}
		defer cli.Close()

		if err := cli.SendCommand("sep auto"); err != nil {
			return fmt.Errorf("failed to send command: %w", err)
		}

		for idx, kbag := range kbags.Files {
			utils.Indent(log.WithFields(log.Fields{"file": kbag.Name}).Info, 2)("Decrypting Keybag")

			if len(kbag.Keybags) != 2 {
				return fmt.Errorf("failed decrypt keybags (bad input): expected keybags to have prod and dev kbags: len=%d", len(kbag.Keybags))
			}

			if err := cli.SendCommand(
				fmt.Sprintf("sep decrypt %s%s", hex.EncodeToString(kbag.Keybags[0].IV), hex.EncodeToString(kbag.Keybags[0].Key)),
			); err != nil {
				return fmt.Errorf("failed to send command: %v", err)
			}

			time.Sleep(1 * time.Second)

			out, err := cli.GetStdOut()
			if err != nil {
				return fmt.Errorf("failed to get stdout: %v", err)
			}

			parts := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
			if len(parts) != 3 {
				return fmt.Errorf("got unexpected output: %v", parts)
			}
			if !strings.HasPrefix(parts[1], "kbag out: ") {
				return fmt.Errorf("got unexpected output: %v; should have prefex 'kbag out: '", parts[1])
			}

			ivkey := strings.TrimPrefix(parts[1], "kbag out: ")
			ivKeyBytes, err := hex.DecodeString(ivkey)
			if err != nil {
				return fmt.Errorf("failed to decode iv+key string: %v", err)
			}
			kbags.Files[idx].Keybags = append(kbags.Files[idx].Keybags, img4.Keybag{
				IV:   ivKeyBytes[:aes.BlockSize],
				Key:  ivKeyBytes[aes.BlockSize:],
				Type: img4.DECRYPTED,
			})
		}

		kbJSON, err := kbags.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to marshal keybags: %v", err)
		}

		os.Mkdir(destPath, 0770)
		log.Infof("Writing keybags to %s", filepath.Join(destPath, "kbags.json"))
		if err := os.WriteFile(filepath.Join(destPath, "kbags.json"), kbJSON, 0660); err != nil {
			return fmt.Errorf("failed to write %s: %v", filepath.Join(destPath, "kbags.json"), err)
		}

		return nil
	},
}
