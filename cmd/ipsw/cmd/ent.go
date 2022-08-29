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
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var haveChecked []string

type Entitlements map[string]any

func scanEnts(ipswPath, dmgPath, dmgType string) (map[string]string, error) {
	if utils.StrSliceHas(haveChecked, dmgPath) {
		return nil, nil // already checked
	}

	dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), dmgPath)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
	}
	if len(dmgs) == 0 {
		return nil, fmt.Errorf("failed to find %s in IPSW", dmgPath)
	}
	defer os.Remove(dmgs[0])

	utils.Indent(log.Info, 3)(fmt.Sprintf("Mounting %s %s", dmgType, dmgs[0]))
	mountPoint, err := utils.MountFS(dmgs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to mount DMG: %v", err)
	}
	defer func() {
		utils.Indent(log.Info, 3)(fmt.Sprintf("Unmounting %s", dmgs[0]))
		if err := utils.Unmount(mountPoint, true); err != nil {
			log.Errorf("failed to unmount DMG at %s: %v", dmgs[0], err)
		}
	}()

	var files []string
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("failed to walk mount %s: %v", mountPoint, err)
			return nil
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
	}

	entDB := make(map[string]string)

	for _, file := range files {
		if m, err := macho.Open(file); err == nil {
			if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
				entDB[strings.TrimPrefix(file, mountPoint)] = m.CodeSignature().Entitlements
			} else {
				entDB[strings.TrimPrefix(file, mountPoint)] = ""
			}
		}
	}

	haveChecked = append(haveChecked, dmgPath)

	return entDB, nil
}

func getEntitlementDatabase(ipswPath, entDBPath string) (map[string]string, error) {
	entDB := make(map[string]string)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
	}

	// create or load entitlement database
	if _, err := os.Stat(entDBPath); os.IsNotExist(err) {
		log.Info("Generating entitlement database file...")

		if appOS, err := i.GetAppOsDmg(); err == nil {
			if ents, err := scanEnts(ipswPath, appOS, "AppOS"); err != nil {
				return nil, fmt.Errorf("failed to scan files in AppOS %s: %v", appOS, err)
			} else {
				for k, v := range ents {
					entDB[k] = v
				}
			}
		}
		if systemOS, err := i.GetSystemOsDmg(); err == nil {
			if ents, err := scanEnts(ipswPath, systemOS, "SystemOS"); err != nil {
				return nil, fmt.Errorf("failed to scan files in SystemOS %s: %v", systemOS, err)
			} else {
				for k, v := range ents {
					entDB[k] = v
				}
			}
		}
		if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
			if ents, err := scanEnts(ipswPath, fsOS, "filesystem"); err != nil {
				return nil, fmt.Errorf("failed to scan files in filesystem %s: %v", fsOS, err)
			} else {
				for k, v := range ents {
					entDB[k] = v
				}
			}
		}

		buff := new(bytes.Buffer)

		e := gob.NewEncoder(buff)

		// Encoding the map
		err := e.Encode(entDB)
		if err != nil {
			return nil, fmt.Errorf("failed to encode entitlement db to binary: %v", err)
		}

		of, err := os.Create(entDBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file %s: %v", ipswPath+".entDB", err)
		}
		defer of.Close()

		gzw := gzip.NewWriter(of)
		defer gzw.Close()

		if _, err := buff.WriteTo(gzw); err != nil {
			return nil, fmt.Errorf("failed to write entitlement db to gzip file: %v", err)
		}
	} else {
		log.Info("Found ipsw entitlement database file...")

		edbFile, err := os.Open(entDBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open entitlement database file %s; %v", entDBPath, err)
		}
		defer edbFile.Close()

		gzr, err := gzip.NewReader(edbFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gzr.Close()

		// Decoding the serialized data
		if err := gob.NewDecoder(gzr).Decode(&entDB); err != nil {
			return nil, fmt.Errorf("failed to decode entitlement database; %v", err)
		}
	}

	return entDB, nil
}

func init() {
	rootCmd.AddCommand(entCmd)

	entCmd.Flags().StringP("ent", "e", "", "Entitlement to search for")
	entCmd.Flags().StringP("file", "f", "", "Dump entitlements for MachO")
	entCmd.Flags().String("output", "o", "Folder to r/w entitlement databases")
	entCmd.Flags().BoolP("diff", "d", false, "Diff entitlements")
	viper.BindPFlag("ent.ent", entCmd.Flags().Lookup("ent"))
	viper.BindPFlag("ent.file", entCmd.Flags().Lookup("file"))
	viper.BindPFlag("ent.ouput", entCmd.Flags().Lookup("ouput"))
	viper.BindPFlag("ent.diff", entCmd.Flags().Lookup("diff"))
}

// entCmd represents the ent command
var entCmd = &cobra.Command{
	Use:          "ent <IPSW>",
	Short:        "Search IPSW filesystem DMG for MachOs with a given entitlement",
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		entitlement := viper.GetString("ent.ent")
		searchFile := viper.GetString("ent.file")

		if len(entitlement) > 0 && len(searchFile) > 0 {
			log.Errorf("you can only use --ent OR --file (not both)")
			return nil
		} else if len(entitlement) > 0 && viper.GetBool("diff") {
			log.Errorf("you can only use --ent OR --diff (not both)")
			return nil
		}

		ipswPath := filepath.Clean(args[0])

		entDBPath := strings.TrimSuffix(ipswPath, filepath.Ext(ipswPath)) + ".entDB"
		if len(viper.GetString("ent.output")) > 0 {
			entDBPath = filepath.Join(viper.GetString("ent.output"), filepath.Base(entDBPath))
		}

		entDB, err := getEntitlementDatabase(ipswPath, entDBPath)
		if err != nil {
			return fmt.Errorf("failed to get entitlement database: %v", err)
		}

		if viper.GetBool("diff") { // DIFF ENTITLEMENTS
			if len(args) < 2 {
				return fmt.Errorf("you must specify two IPSWs to diff")
			}

			ipswPath2 := filepath.Clean(args[1])
			entDBPath2 := strings.TrimSuffix(ipswPath2, filepath.Ext(ipswPath2)) + ".entDB"

			entDB2, err := getEntitlementDatabase(ipswPath2, entDBPath2)
			if err != nil {
				return fmt.Errorf("failed to get entitlement database: %v", err)
			}

			dmp := diffmatchpatch.New()

			if len(searchFile) > 0 { // DIFF MACHO'S ENTITLEMENTS
				for f2, ent2 := range entDB2 {
					if strings.Contains(strings.ToLower(f2), strings.ToLower(searchFile)) {
						if e, ok := entDB[f2]; ok {
							log.Infof(f2)
							diffs := dmp.DiffMain(e, ent2, false)
							if len(diffs) > 2 {
								diffs = dmp.DiffCleanupSemantic(diffs)
								diffs = dmp.DiffCleanupEfficiency(diffs)
							}
							if len(diffs) == 0 {
								utils.Indent(log.Info, 2)("No differences found")
							} else if len(diffs) == 1 {
								if diffs[0].Type == diffmatchpatch.DiffEqual {
									utils.Indent(log.Info, 2)("No differences found")
								} else {
									fmt.Println(dmp.DiffPrettyText(diffs))
								}
							} else {
								fmt.Println(dmp.DiffPrettyText(diffs))
							}
						} else {
							log.Errorf("file %s is NEW and not found in first IPSW", f2)
							fmt.Println(ent2)
						}
					}
				}
			} else {
				for f2, e2 := range entDB2 { // DIFF ALL ENTITLEMENTS
					if e, ok := entDB[f2]; ok {
						diffs := dmp.DiffMain(e, e2, false)
						if len(diffs) > 2 {
							diffs = dmp.DiffCleanupSemantic(diffs)
							diffs = dmp.DiffCleanupEfficiency(diffs)
						}
						if len(diffs) == 0 {
							continue
						} else if len(diffs) == 1 {
							if diffs[0].Type == diffmatchpatch.DiffEqual {
								continue
							} else {
								fmt.Printf("\n%s\n\n", f2)
								fmt.Println(dmp.DiffPrettyText(diffs))
							}
						} else {
							fmt.Printf("\n%s\n\n", f2)
							fmt.Println(dmp.DiffPrettyText(diffs))
						}
					} else {
						fmt.Printf("\n🆕 %s 🆕\n\n%s", f2, e2)
					}
				}
			}
			return nil
		} else if len(searchFile) > 0 { // DUMP MACHO'S ENTITLEMENTS
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
		} else if len(entitlement) > 0 { // FIND ALL FILES WITH ENTITLEMENT
			log.Infof("Files containing entitlement: %s", entitlement)
			fmt.Println()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for f, ent := range entDB {
				if strings.Contains(ent, entitlement) {
					ents := Entitlements{}
					if err := plist.NewDecoder(bytes.NewReader([]byte(ent))).Decode(&ents); err != nil {
						return fmt.Errorf("failed to decode entitlements plist for %s: %v", f, err)
					}
					for k, v := range ents {
						if strings.Contains(k, entitlement) {
							switch v := v.(type) {
							case bool:
								if v {
									fmt.Fprintf(w, "%s\t%s\n", k, f)
								}
							case string:
								fmt.Fprintf(w, "%s\t%s\n", k, f)
								fmt.Fprintf(w, " - %s\n", v)
							case []any:
								fmt.Fprintf(w, "%s\t%s\n", k, f)
								for _, i := range v {
									fmt.Fprintf(w, " - %v\n", i)
								}
							default:
								log.Error(fmt.Sprintf("unhandled entitlement kind %T in %s", v, f))
							}
						}
					}
				}
			}
			w.Flush()
		} else { // DUMP ALL ENTITLEMENTS
			for f, ent := range entDB {
				fmt.Printf("%s\n\n%s\n", f, ent)
			}
		}

		return nil
	},
}
