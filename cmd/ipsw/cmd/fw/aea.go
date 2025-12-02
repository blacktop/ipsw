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
package fw

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(aeaCmd)

	aeaCmd.Flags().Bool("id", false, "Print AEA file ID")
	aeaCmd.Flags().BoolP("info", "i", false, "Print info")
	aeaCmd.Flags().BoolP("fcs-key", "f", false, "Get fcs-key JSON")
	aeaCmd.Flags().BoolP("key", "k", false, "Get archive decryption key")
	aeaCmd.Flags().StringP("key-val", "b", "", "Base64 encoded symmetric encryption key")
	aeaCmd.Flags().StringP("pem", "p", "", "AEA private_key.pem file")
	aeaCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	aeaCmd.Flags().BoolP("encrypt", "e", false, "AEA encrypt file")
	aeaCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	aeaCmd.Flags().Bool("insecure", false, "Allow insecure connections")
	aeaCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	aeaCmd.MarkFlagDirname("output")
	aeaCmd.MarkFlagsMutuallyExclusive("info", "fcs-key", "key")
	viper.BindPFlag("fw.aea.id", aeaCmd.Flags().Lookup("id"))
	viper.BindPFlag("fw.aea.info", aeaCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.aea.fcs-key", aeaCmd.Flags().Lookup("fcs-key"))
	viper.BindPFlag("fw.aea.key", aeaCmd.Flags().Lookup("key"))
	viper.BindPFlag("fw.aea.key-val", aeaCmd.Flags().Lookup("key-val"))
	viper.BindPFlag("fw.aea.pem", aeaCmd.Flags().Lookup("pem"))
	viper.BindPFlag("fw.aea.pem-db", aeaCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("fw.aea.encrypt", aeaCmd.Flags().Lookup("encrypt"))
	viper.BindPFlag("fw.aea.proxy", aeaCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("fw.aea.insecure", aeaCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("fw.aea.output", aeaCmd.Flags().Lookup("output"))
}

// aeaCmd represents the ane command
var aeaCmd = &cobra.Command{
	Use:           "aea",
	Short:         "Parse AEA1 DMGs",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var pemData []byte

		// flags
		fcsKey := viper.GetBool("fw.aea.fcs-key")
		adKey := viper.GetBool("fw.aea.key")
		base64Key := viper.GetString("fw.aea.key-val")
		showID := viper.GetBool("fw.aea.id")
		showInfo := viper.GetBool("fw.aea.info")
		pemFile := viper.GetString("fw.aea.pem")
		pemDB := viper.GetString("fw.aea.pem-db")
		doEncrypt := viper.GetBool("fw.aea.encrypt")
		proxy := viper.GetString("fw.aea.proxy")
		insecure := viper.GetBool("fw.aea.insecure")
		output := viper.GetString("fw.aea.output")
		// validate flags
		if (adKey || showID || showInfo) && output != "" {
			return fmt.Errorf("--output flag is not valid with --id, --info or --key flags")
		} else if (adKey || showID || showInfo) && (fcsKey || base64Key != "") {
			return fmt.Errorf("cannot use --id, --info or --key flags with --fcs-key or --key-val")
		} else if fcsKey && base64Key != "" {
			return fmt.Errorf("cannot use --fcs-key with --key-val")
		}
		if base64Key != "" {
			base64Key = strings.TrimPrefix(base64Key, "base64:")
		}

		var bold = colors.Bold().SprintFunc()
		var info = colors.HiGreen().SprintFunc()

		if output == "" {
			output = filepath.Dir(args[0])
		}

		if showID {
			id, err := aea.ID(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse AEA id: %v", err)
			}
			fmt.Println(hex.EncodeToString(id[:]))
		} else if showInfo {
			metadata, err := aea.Info(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse AEA: %v", err)
			}
			log.Info("AEA Info")
			for k, v := range metadata {
				if k == "encryption_key" {
					fmt.Printf("%s:\n%s\n\n", bold("["+k+"]"), info(string(v)))
				} else if b64data, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(string(v)); err == nil {
					fmt.Printf("%s:\n%s\n", bold("["+k+"]"), utils.HexDump(b64data, 0))
				} else {
					if colors.Active() {
						fmt.Println(bold("[" + k + "]"))
						if err := quick.Highlight(os.Stdout, string(v)+"\n\n", "json", "terminal256", "nord"); err != nil {
							return fmt.Errorf("failed to highlight json: %v", err)
						}
					} else {
						fmt.Printf("%s:\n%s\n\n", bold("["+k+"]"), v)
					}
				}
			}
		} else if fcsKey {
			metadata, err := aea.Info(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse AEA: %v", err)
			}
			pkmap, err := metadata.GetPrivateKey(nil, pemDB, false, proxy, insecure)
			if err != nil {
				return fmt.Errorf("failed to get private key: %v", err)
			}
			data, err := json.Marshal(pkmap)
			if err != nil {
				return fmt.Errorf("failed to marshal private key: %v", err)
			}
			fname := filepath.Join(output, "fcs-keys.json")
			log.Infof("Created %s", fname)
			if err := os.WriteFile(fname, data, 0o644); err != nil {
				return fmt.Errorf("failed to write private key to file: %v", err)
			}
			if colors.Active() {
				if err := quick.Highlight(os.Stdout, string(data)+"\n\n", "json", "terminal256", "nord"); err != nil {
					return fmt.Errorf("failed to highlight json: %v", err)
				}
			}
		} else if adKey {
			if pemFile != "" {
				pemData, err = os.ReadFile(pemFile)
				if err != nil {
					return fmt.Errorf("failed to read pem file: %v", err)
				}
			}
			metadata, err := aea.Info(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse AEA: %v", err)
			}
			wkey, err := metadata.DecryptFCS(pemData, pemDB, proxy, insecure)
			if err != nil {
				return fmt.Errorf("failed to HPKE decrypt fcs-key: %v", err)
			}
			fmt.Printf("base64:%s\n", base64.StdEncoding.EncodeToString(wkey))
		} else if doEncrypt {
			if base64Key == "" {
				return fmt.Errorf("must provide a base64 encoded symmetric encryption key via --key-val")
			}
			if err := aea.Encrypt(args[0], &aea.EncryptConfig{
				Output:    output,
				B64SymKey: base64Key,
			}); err != nil {
				return fmt.Errorf("failed to encrypt AEA: %v", err)
			}
		} else {
			if pemFile != "" {
				pemData, err = os.ReadFile(pemFile)
				if err != nil {
					return fmt.Errorf("failed to read pem file: %v", err)
				}
			}
			out, err := aea.Decrypt(&aea.DecryptConfig{
				Input:       args[0],
				Output:      output,
				PrivKeyData: pemData,
				B64SymKey:   base64Key,
				PemDB:       pemDB,
				Proxy:       proxy,
				Insecure:    insecure,
			})
			if err != nil {
				return fmt.Errorf("failed to parse AEA: %v", err)
			}
			log.Infof("Extracted AEA to %s", out)
		}

		return nil
	},
}
