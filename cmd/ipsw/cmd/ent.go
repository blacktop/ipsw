/*
Copyright © 2021 blacktop

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
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(entCmd)

	entCmd.Flags().StringP("ent", "e", "", "Entitlement to search for")
	entCmd.Flags().String("db", "", "Path to entitlement database to use")
	entCmd.Flags().StringP("file", "f", "", "Output entitlements for file")
}

type Entitlements map[string]interface{}

// entCmd represents the ent command
var entCmd = &cobra.Command{
	Use:          "ent <IPSW>",
	Short:        "Search IPSW filesystem DMG for MachOs with a given entitlement",
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var fsDMG string
		var entDB map[string]string
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		entitlement, _ := cmd.Flags().GetString("ent")
		entDBPath, _ := cmd.Flags().GetString("db")
		searchFile, _ := cmd.Flags().GetString("file")

		if len(entitlement) == 0 && len(searchFile) == 0 {
			log.Errorf("you must supply a --ent OR --file")
			return nil
		} else if len(entitlement) > 0 && len(searchFile) > 0 {
			log.Errorf("you can only use --ent OR --file (not both)")
			return nil
		}

		ipswPath := filepath.Clean(args[0])
		if len(entDBPath) > 0 {
			entDBPath = strings.TrimSuffix(ipswPath, filepath.Ext(ipswPath)) + ".entDB"
		}

		if _, err := os.Stat(entDBPath); os.IsNotExist(err) {
			i, err := info.Parse(ipswPath)
			if err != nil {
				return fmt.Errorf("failed to parse ipsw info: %v", err)
			}

			found := false
			for k, v := range i.Plists.Restore.SystemRestoreImageFileSystems {
				if v == "APFS" {
					fsDMG = k
					found = true
				}
			}
			if !found {
				return fmt.Errorf("failed to parse ipsw info: %v", err)
			}

			fileSystem, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
				return strings.EqualFold(f.Name, fsDMG)
			})
			if err != nil || len(fileSystem) == 1 {
				return fmt.Errorf("failed extract %s from ipsw, found %v: %v", fsDMG, fileSystem, err)
			}
			defer os.Remove(fileSystem[0])

			mountPoint := "/tmp/filesystem_dmg"
			utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", fileSystem[0]))
			if err := utils.Mount(fileSystem[0], mountPoint); err != nil {
				return fmt.Errorf("failed to mount %s: %v", fileSystem[0], err)
			}
			defer func() {
				utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting DMG %s", fileSystem[0]))
				if err := utils.Unmount(mountPoint, false); err != nil {
					utils.Indent(log.Fatal, 2)(fmt.Sprintf("failed to unmount %s: %v", mountPoint, err))
				}
			}()

			var files []string
			if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
				if !info.IsDir() {
					files = append(files, path)
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
			}

			entDB = make(map[string]string)

			for _, file := range files {
				if m, err := macho.Open(file); err == nil {
					if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
						entDB[strings.TrimPrefix(file, mountPoint)] = m.CodeSignature().Entitlements
					} else {
						entDB[strings.TrimPrefix(file, mountPoint)] = ""
					}
				}
			}

			if _, err := os.Stat(entDBPath); os.IsNotExist(err) {
				log.Info("Generating entitlement database file...")
				buff := new(bytes.Buffer)

				e := gob.NewEncoder(buff)

				// Encoding the map
				err := e.Encode(entDB)
				if err != nil {
					return fmt.Errorf("failed to encode entitlement db to binary: %v", err)
				}

				of, err := os.Create(entDBPath)
				if err != nil {
					return fmt.Errorf("failed to create file %s: %v", ipswPath+".entDB", err)
				}
				defer of.Close()

				gzw := gzip.NewWriter(of)
				defer gzw.Close()

				_, err = buff.WriteTo(gzw)
				if err != nil {
					return fmt.Errorf("failed to write entitlement db to gzip file: %v", err)
				}
			}

		} else {
			log.Info("Found ipsw entitlement database file...")
			edbFile, err := os.Open(entDBPath)
			if err != nil {
				return fmt.Errorf("failed to open entitlement database file %s; %v", entDBPath, err)
			}

			gzr, err := gzip.NewReader(edbFile)
			if err != nil {
				return fmt.Errorf("failed to create gzip reader: %v", err)
			}

			// Decoding the serialized data
			err = gob.NewDecoder(gzr).Decode(&entDB)
			if err != nil {
				return fmt.Errorf("failed to decode entitlement database; %v", err)
			}
			gzr.Close()
			edbFile.Close()
		}

		if len(searchFile) > 0 {
			for f, ent := range entDB {
				if strings.Contains(strings.ToLower(f), strings.ToLower(searchFile)) {
					log.Infof(f)
					if len(ent) > 0 {
						fmt.Printf("\n%s\n", ent)
					} else {
						fmt.Printf("\n\t- no entitlements\n")
					}
				}
			}
		} else {
			log.Infof("Files containing entitlement: %s", entitlement)
			fmt.Println()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for f, ent := range entDB {
				if strings.Contains(ent, entitlement) {
					fmt.Println(ent)
					ents := Entitlements{}
					if err := plist.NewDecoder(bytes.NewReader([]byte(ent))).Decode(&ents); err != nil {
						return fmt.Errorf("failed to decode entitlements plist for %s: %v", f, err)
					}
					for k, v := range ents {
						if strings.Contains(k, entitlement) {
							switch v := reflect.ValueOf(v); v.Kind() {
							case reflect.Bool:
								if v.Bool() {
									fmt.Fprintf(w, "%s\t%s\n", k, f)
								}
							default:
								log.Error(fmt.Sprintf("unhandled entitlement kind %s in %s", f, v.Kind()))
							}
						}
					}
				}
			}
			w.Flush()
		}

		return nil
	},
}
