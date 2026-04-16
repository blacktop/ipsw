/*
Copyright © 2018-2026 blacktop

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
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	otacmd "github.com/blacktop/ipsw/cmd/ipsw/cmd/ota"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/devicetree"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var reDeviceTreeIm4p = regexp.MustCompile(`.*DeviceTree.*im4p$`)

func init() {
	rootCmd.AddCommand(deviceTreeCmd)
	deviceTreeCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	deviceTreeCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	deviceTreeCmd.Flags().BoolP("summary", "s", false, "Output summary only")
	deviceTreeCmd.Flags().BoolP("json", "j", false, "Output to stdout as JSON")
	deviceTreeCmd.Flags().BoolP("remote", "r", false, "Extract from URL")
	deviceTreeCmd.Flags().StringP("filter", "f", "", "Filter DeviceTree to parse (if multiple i.e. macOS)")
	deviceTreeCmd.Flags().String("key-val", "", "Base64 encoded AEA symmetric encryption key")
	deviceTreeCmd.Flags().String("key-db", "", "Path to AEA keys JSON database (auto-lookup by filename)")
	deviceTreeCmd.Flags().BoolP("confirm", "y", false, "Skip confirmation prompt for OTA downloads")
	deviceTreeCmd.MarkFlagFilename("key-db", "json")
	deviceTreeCmd.MarkZshCompPositionalArgumentFile(1, "DeviceTree*im4p")
	deviceTreeCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"im4p", "ipsw", "zip", "aea"}, cobra.ShellCompDirectiveFilterFileExt
	}
	viper.BindPFlag("dtree.proxy", deviceTreeCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("dtree.insecure", deviceTreeCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("dtree.summary", deviceTreeCmd.Flags().Lookup("summary"))
	viper.BindPFlag("dtree.json", deviceTreeCmd.Flags().Lookup("json"))
	viper.BindPFlag("dtree.remote", deviceTreeCmd.Flags().Lookup("remote"))
	viper.BindPFlag("dtree.filter", deviceTreeCmd.Flags().Lookup("filter"))
	viper.BindPFlag("dtree.key-val", deviceTreeCmd.Flags().Lookup("key-val"))
	viper.BindPFlag("dtree.key-db", deviceTreeCmd.Flags().Lookup("key-db"))
	viper.BindPFlag("dtree.confirm", deviceTreeCmd.Flags().Lookup("confirm"))
}

// deviceTreeCmd represents the deviceTree command
var deviceTreeCmd = &cobra.Command{
	Use:           "dtree <IPSW/OTA/DeviceTree>",
	Aliases:       []string{"dt", "devicetree"},
	Short:         "Parse DeviceTree",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dtrees := make(map[string]*devicetree.DeviceTree)

		if viper.GetBool("dtree.remote") {
			isOTA, err := isRemoteOTA(args[0], viper.GetString("dtree.proxy"), viper.GetBool("dtree.insecure"))
			if err != nil {
				return fmt.Errorf("failed to probe remote file type: %v", err)
			}
			if isOTA {
				log.Warn("OTA archives do not support partial downloads — the entire file must be downloaded and decrypted")
				if !viper.GetBool("dtree.confirm") {
					var cont bool
					if err := survey.AskOne(&survey.Confirm{Message: "Continue with full OTA download?"}, &cont); err != nil {
						return fmt.Errorf("cannot prompt for confirmation (use -y to skip): %v", err)
					}
					if !cont {
						return nil
					}
				}
				dtrees, err = extractDeviceTreeFromRemoteOTA(args[0])
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree from remote OTA: %v", err)
				}
			} else {
				zr, err := download.NewRemoteZipReader(args[0], &download.RemoteConfig{
					Proxy:    viper.GetString("dtree.proxy"),
					Insecure: viper.GetBool("dtree.insecure"),
				})
				if err != nil {
					return fmt.Errorf("failed to download DeviceTree: %v", err)
				}
				dtrees, err = devicetree.ParseZipFiles(zr.File)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
			}
		} else {
			fPath := filepath.Clean(args[0])

			isAEA, _ := magic.IsAEA(fPath)
			isAA, _ := magic.IsAA(fPath)
			if isAEA || isAA {
				dtrees, err = extractDeviceTreeFromOTA(fPath)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree from OTA: %v", err)
				}
			} else if ok, _ := magic.IsZip(fPath); ok {
				zr, err := zip.OpenReader(fPath)
				if err != nil {
					return fmt.Errorf("failed to open zip: %v", err)
				}
				dtrees, err = devicetree.ParseZipFiles(zr.File)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
			} else if ok, _ := magic.IsImg3(fPath); ok {
				content, err := os.ReadFile(fPath)
				if err != nil {
					return fmt.Errorf("failed to read DeviceTree: %v", err)
				}
				var dtree *devicetree.DeviceTree
				dtree, err = devicetree.ParseImg3Data(content)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
				dtrees[fPath] = dtree
			} else if ok, _ := magic.IsIm4p(fPath); ok {
				content, err := os.ReadFile(fPath)
				if err != nil {
					return fmt.Errorf("failed to read DeviceTree: %v", err)
				}
				var dtree *devicetree.DeviceTree
				dtree, err = devicetree.ParseImg4Data(content)
				if err != nil {
					return fmt.Errorf("failed to extract DeviceTree: %v", err)
				}
				dtrees[fPath] = dtree
			} else {
				content, err := os.ReadFile(fPath)
				if err != nil {
					return fmt.Errorf("failed to read DeviceTree: %v", err)
				}
				var dtree *devicetree.DeviceTree
				dtree, err = devicetree.ParseData(bytes.NewReader(content))
				if err != nil {
					return fmt.Errorf("failed to parse DeviceTree: %v", err)
				}
				dtrees[fPath] = dtree
			}
		}

		for name, dtree := range dtrees {
			if viper.GetString("dtree.filter") != "" {
				if !strings.Contains(strings.ToLower(name), strings.ToLower(viper.GetString("dtree.filter"))) {
					continue
				}
			}
			log.Infof("DeviceTree: %s", name)
			if viper.GetBool("dtree.json") {
				// jq '.[ "device-tree" ].children [] | select(.product != null) | .product."product-name"'
				// jq '.[ "device-tree" ].compatible'
				// jq '.[ "device-tree" ].model'
				j, err := json.Marshal(dtree)
				if err != nil {
					return err
				}
				fmt.Println(string(j))
			} else {
				if s, err := dtree.Summary(); err == nil {
					utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", s.ProductType))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Board Config: %s", s.BoardConfig))
					utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", s.ProductName))
					if len(s.SocName) > 0 {
						var deviceType string
						if len(s.DeviceType) > 0 {
							deviceType = fmt.Sprintf(" (%s)", s.DeviceType)
						}
						utils.Indent(log.Info, 2)(fmt.Sprintf("SoC Name: %s%s", s.SocName, deviceType))
					}
					if viper.GetBool("dtree.summary") {
						continue
					}
				}
				fmt.Println(dtree.String())
			}
		}

		return nil
	},
}

func isRemoteOTA(remoteURL, proxy string, insecure bool) (bool, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}
	req, err := http.NewRequest("GET", remoteURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Range", "bytes=0-3")
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to fetch remote header: %v", err)
	}
	defer resp.Body.Close()
	data := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, data); err != nil {
		return false, fmt.Errorf("failed to read remote header: %v", err)
	}
	if magic.Magic(binary.BigEndian.Uint32(data)) == magic.MagicAEA1 {
		return true, nil
	}
	switch magic.Magic(binary.LittleEndian.Uint32(data)) {
	case magic.MagicYAA1, magic.MagicAA01:
		return true, nil
	}
	return false, nil
}

func extractDeviceTreeFromOTA(fPath string) (map[string]*devicetree.DeviceTree, error) {
	conf := resolveOTAKeyConfig(fPath)
	o, err := ota.Open(fPath, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to open OTA: %v", err)
	}
	return parseDeviceTreesFromOTA(o)
}

func extractDeviceTreeFromRemoteOTA(remoteURL string) (map[string]*devicetree.DeviceTree, error) {
	tmpFile, err := os.CreateTemp("", "ipsw-dtree-ota-*.aea")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpPath) // remove placeholder so downloader can rename into it
	defer os.Remove(tmpPath)
	defer os.Remove(tmpPath + ".download") // cleanup partial download

	log.Info("Downloading OTA...")
	downloader := download.NewDownload(
		viper.GetString("dtree.proxy"),
		viper.GetBool("dtree.insecure"),
		false, false, false, true /* ignoreSha1 */, Verbose,
	)
	downloader.URL = remoteURL
	downloader.DestName = tmpPath
	if err := downloader.Do(); err != nil {
		return nil, fmt.Errorf("failed to download OTA: %v", err)
	}

	// Use the original URL for key-db lookup and filename-embedded
	// key extraction (the temp path has a random name).
	conf := resolveOTAKeyConfig(remoteURL)
	if conf.SymmetricKey == "" {
		conf.SymmetricKey = extractEmbeddedKey(remoteURL)
	}
	o, err := ota.Open(tmpPath, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to open downloaded OTA: %v", err)
	}
	return parseDeviceTreesFromOTA(o)
}

// extractEmbeddedKey extracts a base64 AEA key from a filename
// pattern like "name[key].aea" — mirrors pkg/ota getKeyFromName.
func extractEmbeddedKey(name string) string {
	base := filepath.Base(name)
	_, rest, ok := strings.Cut(base, "[")
	if !ok {
		return ""
	}
	key, _, ok := strings.Cut(rest, "]")
	if !ok {
		return ""
	}
	key = strings.ReplaceAll(key, "-", "+")
	key = strings.ReplaceAll(key, "_", "/")
	return key
}

func resolveOTAKeyConfig(otaPath string) *ota.Config {
	conf := otacmd.ResolveAEAKey(
		otaPath,
		viper.GetString("dtree.key-db"),
		viper.GetString("dtree.key-val"),
		viper.GetBool("dtree.insecure"),
	)
	conf.Proxy = viper.GetString("dtree.proxy")
	return conf
}

func parseDeviceTreesFromOTA(o *ota.AA) (map[string]*devicetree.DeviceTree, error) {
	dtrees := make(map[string]*devicetree.DeviceTree)
	for _, file := range o.Files() {
		if file.IsDir() {
			continue
		}
		if !reDeviceTreeIm4p.MatchString(file.Name()) {
			continue
		}
		f, err := o.Open(file.Name(), true)
		if err != nil {
			log.WithError(err).Warnf("failed to open %s in OTA", file.Name())
			continue
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			log.WithError(err).Warnf("failed to read %s from OTA", file.Name())
			continue
		}
		dt, err := devicetree.ParseImg4Data(data)
		if err != nil {
			log.WithError(err).Warnf("failed to parse DeviceTree %s", file.Name())
			continue
		}
		dtrees[filepath.Base(file.Name())] = dt
	}
	if len(dtrees) == 0 {
		return nil, fmt.Errorf("no DeviceTree files found in OTA")
	}
	return dtrees, nil
}
