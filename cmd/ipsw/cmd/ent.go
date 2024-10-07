/*
Copyright © 2018-2024 blacktop

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
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/fatih/color"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorBin = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorKey = color.New(color.Bold, color.FgHiGreen).SprintFunc()
var colorValue = color.New(color.Bold, color.FgHiBlue).SprintFunc()

func init() {
	rootCmd.AddCommand(entCmd)

	entCmd.Flags().StringArray("ipsw", []string{}, "IPSWs to analyze")
	entCmd.Flags().StringArray("input", []string{}, "Folders of MachOs to analyze")
	entCmd.MarkFlagDirname("input")
	entCmd.Flags().StringP("key", "k", "", "Entitlement KEY regex to search for")
	entCmd.Flags().StringP("val", "v", "", "Entitlement VALUE regex to search for (i.e. <array> strings)")
	entCmd.Flags().StringP("file", "f", "", "Dump entitlements for MachO as plist")
	entCmd.Flags().String("db", "", "Folder to r/w entitlement databases")
	entCmd.MarkFlagDirname("db")
	entCmd.Flags().Bool("file-only", false, "Only output the file path of matches")
	entCmd.Flags().BoolP("diff", "d", false, "Diff entitlements")
	entCmd.Flags().BoolP("md", "m", false, "Markdown style output")
	entCmd.Flags().Bool("ui", false, "Show entitlements Web UI")
	entCmd.Flags().String("ui-host", "localhost", "UI host to server on")
	entCmd.Flags().Int("ui-port", 3993, "UI port to server on")
	viper.BindPFlag("ent.ipsw", entCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("ent.input", entCmd.Flags().Lookup("input"))
	viper.BindPFlag("ent.key", entCmd.Flags().Lookup("key"))
	viper.BindPFlag("ent.val", entCmd.Flags().Lookup("val"))
	viper.BindPFlag("ent.file", entCmd.Flags().Lookup("file"))
	viper.BindPFlag("ent.db", entCmd.Flags().Lookup("db"))
	viper.BindPFlag("ent.file-only", entCmd.Flags().Lookup("file-only"))
	viper.BindPFlag("ent.diff", entCmd.Flags().Lookup("diff"))
	viper.BindPFlag("ent.md", entCmd.Flags().Lookup("md"))
	viper.BindPFlag("ent.ui", entCmd.Flags().Lookup("ui"))
	viper.BindPFlag("ent.ui-host", entCmd.Flags().Lookup("ui-host"))
	viper.BindPFlag("ent.ui-port", entCmd.Flags().Lookup("ui-port"))
	entCmd.MarkFlagsMutuallyExclusive("key", "val", "ui", "diff")
	entCmd.MarkFlagsMutuallyExclusive("ipsw", "input")
}

// entCmd represents the ent command
var entCmd = &cobra.Command{
	Use:   "ent",
	Short: "Search IPSW filesystem DMG or Folder for MachOs with a given entitlement",
	Example: heredoc.Doc(`
		# Search IPSW for entitlement key
		❯ ipsw ent --ipsw <IPSW> --db /tmp --key platform-application

		# Search local folder for entitlement key
		❯ ipsw ent --input /usr/bin --db /tmp --val platform-application

		# Search IPSW for entitlement value (i.e. one of the <array> strings)
		❯ ipsw ent --ipsw <IPSW> --db /tmp --val LockdownMode

		# Dump entitlements for MachO in IPSW
		❯ ipsw ent --ipsw <IPSW> --db /tmp --file WebContent

		# Diff two IPSWs
		❯ ipsw ent --diff --ipsw <PREV_IPSW> --ipsw <NEW_IPSW> --db /tmp

		# Launch Web UI (http://localhost:3993)
		❯ ipsw ent --ui --ipsw <IPSW>`),
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		entDBs := make([]map[string]string, 0, 2)

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		ipsws := viper.GetStringSlice("ent.ipsw")
		inputs := viper.GetStringSlice("ent.input")
		dbFolder := viper.GetString("ent.db")
		entitlementKey := viper.GetString("ent.key")
		entitlementValue := viper.GetString("ent.val")
		searchFile := viper.GetString("ent.file")
		onlyFiles := viper.GetBool("ent.file-only")
		doDiff := viper.GetBool("ent.diff")
		markdown := viper.GetBool("ent.md")
		showUI := viper.GetBool("ent.ui")
		// check flags
		if len(dbFolder) == 0 && len(ipsws) == 0 && len(inputs) == 0 {
			return fmt.Errorf("must supply either --db, --ipsw or --input")
		} else if showUI && doDiff {
			return fmt.Errorf("cannot use --ui and --diff together")
		} else if showUI && (len(ipsws) != 1 && len(inputs) != 1) {
			return fmt.Errorf("must supply only one --ipsw or --input with --ui")
		} else if doDiff && (len(ipsws) != 2 && len(inputs) != 2) {
			return fmt.Errorf("must supply two --ipsw or --input with --diff")
		}
		color.NoColor = viper.GetBool("no-color") || onlyFiles

		if len(dbFolder) > 0 && len(ipsws) == 0 && len(inputs) == 0 {
			// search preprocessed entitlement databases
			dbs, err := filepath.Glob(filepath.Join(dbFolder, "*.entDB"))
			if err != nil {
				return fmt.Errorf("failed to glob entitlement databases: %v", err)
			}
			if len(dbs) == 0 {
				return fmt.Errorf("no entitlement databases found in %s", dbFolder)
			}

			var choices []string
			for _, db := range dbs {
				choices = append(choices, strings.TrimSuffix(filepath.Base(db), ".entDB"))
			}

			dbIndices := []int{}
			prompt := &survey.MultiSelect{
				Message:  "Select DB(s):",
				Options:  choices,
				PageSize: 20,
			}
			if err := survey.AskOne(prompt, &dbIndices); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				os.Exit(0)
			}

			for _, idx := range dbIndices {
				entDB, err := ent.GetDatabase(&ent.Config{Database: dbs[idx]})
				if err != nil {
					return fmt.Errorf("failed to get entitlement database: %v", err)
				}
				entDBs = append(entDBs, entDB)
			}
		} else { // create NEW entitlement databases
			for _, ipswPath := range ipsws {
				entDBPath := strings.TrimSuffix(ipswPath, filepath.Ext(ipswPath)) + ".entDB"
				if len(dbFolder) > 0 {
					entDBPath = filepath.Join(dbFolder, filepath.Base(entDBPath))
				}
				entDB, err := ent.GetDatabase(&ent.Config{IPSW: ipswPath, Database: entDBPath})
				if err != nil {
					return fmt.Errorf("failed to get entitlement database: %v", err)
				}
				entDBs = append(entDBs, entDB)
			}
			for _, input := range inputs {
				md5Hash := md5.Sum([]byte(input))
				entDBPath := hex.EncodeToString(md5Hash[:]) + ".entDB"
				if len(dbFolder) > 0 {
					entDBPath = filepath.Join(dbFolder, filepath.Base(entDBPath))
				}
				entDB, err := ent.GetDatabase(&ent.Config{Folder: input, Database: entDBPath})
				if err != nil {
					return fmt.Errorf("failed to get entitlement database: %v", err)
				}
				entDBs = append(entDBs, entDB)
			}
		}

		if showUI {
			var version string
			if len(ipsws) == 1 {
				if i, err := info.Parse(ipsws[0]); err == nil {
					version = fmt.Sprintf("for %s (%s)",
						i.Plists.BuildManifest.ProductVersion,
						i.Plists.BuildManifest.ProductBuildVersion)
				}
			}
			db := make(map[string]string)
			for f, e := range entDBs[0] {
				if len(e) == 0 {
					continue
				}
				db[f] = e
			}
			return ent.UI(db, &ent.Config{
				Version: version,
				Host:    viper.GetString("ent.ui-host"),
				Port:    viper.GetInt("ent.ui-port"),
			})
		} else if doDiff { // DIFF ENTITLEMENTS
			if len(searchFile) > 0 { // DIFF MACHO'S ENTITLEMENTS
				dmp := diffmatchpatch.New()
				for f2, ent2 := range entDBs[1] {
					if strings.Contains(strings.ToLower(f2), strings.ToLower(searchFile)) {
						if e, ok := entDBs[0][f2]; ok {
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
			} else { // DIFF ENTITLEMENT DATABASES
				log.Info("Diffing entitlement databases...")
				out, err := ent.DiffDatabases(entDBs[0], entDBs[1], &ent.Config{Markdown: markdown, Color: viper.GetBool("color") && !viper.GetBool("no-color")})
				if err != nil {
					return fmt.Errorf("failed to diff entitlement databases: %v", err)
				}
				fmt.Println(out)
			}
			return nil
		} else if len(entitlementKey) > 0 { // FIND ALL FILES WITH ENTITLEMENT KEY
			re, err := regexp.Compile(entitlementKey)
			if err != nil {
				return fmt.Errorf("failed to compile regex '%s': %v", entitlementKey, err)
			}
			if !onlyFiles {
				log.Infof("Files matching entitlement: %s", entitlementKey)
				fmt.Println()
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, entDB := range entDBs {
				for f, ent := range entDB {
					if re.MatchString(ent) {
						ents := make(map[string]any)
						if err := plist.NewDecoder(bytes.NewReader([]byte(ent))).Decode(&ents); err != nil {
							return fmt.Errorf("failed to decode entitlements plist for %s: %v", f, err)
						}
						for k, v := range ents {
							if re.MatchString(k) {
								switch v := v.(type) {
								case bool:
									if v {
										if onlyFiles {
											fmt.Fprintf(w, "%s\n", colorBin(f))
										} else {
											fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
										}
									}
								case uint64:
									if onlyFiles {
										fmt.Fprintf(w, "%s\n", colorBin(f))
									} else {
										fmt.Fprintf(w, "%s=%s\t%s\n", colorKey(k), colorValue(fmt.Sprintf("%d", v)), colorBin(f))
									}
								case string:
									if onlyFiles {
										fmt.Fprintf(w, "%s\n", colorBin(f))
									} else {
										fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
										fmt.Fprintf(w, " - %s\n", colorValue(v))
									}
								case []any:
									if onlyFiles {
										fmt.Fprintf(w, "%s\n", colorBin(f))
									} else {
										fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
										for _, i := range v {
											fmt.Fprintf(w, " - %v\n", colorValue(i))
										}
									}
								case map[string]any:
									if onlyFiles {
										fmt.Fprintf(w, "%s\n", colorBin(f))
									} else {
										fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
										for kk, vv := range v {
											fmt.Fprintf(w, " - %s: %v\n", colorKey(kk), colorValue(vv))
										}
									}
								default:
									log.Error(fmt.Sprintf("unhandled entitlement kind %T in %s", v, f))
								}
							}
						}
					}
				}
			}
			w.Flush()
		} else if len(entitlementValue) > 0 { // FIND ALL FILES WITH ENTITLEMENT VALUE
			re, err := regexp.Compile(entitlementValue)
			if err != nil {
				return fmt.Errorf("failed to compile regex '%s': %v", entitlementValue, err)
			}
			if !onlyFiles {
				log.Infof("Files matching entitlement value: %s", entitlementValue)
				fmt.Println()
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, entDB := range entDBs {
				for f, ent := range entDB {
					ents := make(map[string]any)
					if err := plist.NewDecoder(bytes.NewReader([]byte(ent))).Decode(&ents); err != nil {
						return fmt.Errorf("failed to decode entitlements plist for %s: %v", f, err)
					}
					for k, v := range ents {
						switch v := v.(type) {
						case bool:
							continue // skip bools (prob too noisy)
						case uint64:
							continue // skip uint64 (prob too noisy)
						case string:
							if re.MatchString(v) {
								if onlyFiles {
									fmt.Fprintf(w, "%s\n", colorBin(f))
								} else {
									fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
									fmt.Fprintf(w, " - %s\n", colorValue(v))
								}
							}
						case []any:
							for _, i := range v {
								if iStr, ok := i.(string); ok {
									if re.MatchString(iStr) {
										if onlyFiles {
											fmt.Fprintf(w, "%s\n", colorBin(f))
										} else {
											fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
											for _, i := range v {
												fmt.Fprintf(w, " - %v\n", colorValue(i))
											}
										}
									}
								}
							}
						case map[string]any:
							for kk, vv := range v {
								if re.MatchString(kk) {
									if onlyFiles {
										fmt.Fprintf(w, "%s\n", colorBin(f))
									} else {
										fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
										fmt.Fprintf(w, " - %s: %v\n", colorKey(kk), colorValue(vv))
									}
								}
								if vvStr, ok := vv.(string); ok {
									if re.MatchString(vvStr) {
										if onlyFiles {
											fmt.Fprintf(w, "%s\n", colorBin(f))
										} else {
											fmt.Fprintf(w, "%s\t%s\n", colorKey(k), colorBin(f))
											fmt.Fprintf(w, " - %s: %v\n", colorKey(kk), colorValue(vv))
										}
									}
								}
							}
						default:
							log.Error(fmt.Sprintf("unhandled entitlement kind %T in %s", v, f))
						}
					}
				}
			}
			w.Flush()
		} else if len(searchFile) > 0 { // DUMP MACHO'S ENTITLEMENTS
			for _, entDB := range entDBs {
				for f, ent := range entDB {
					if strings.Contains(strings.ToLower(f), strings.ToLower(searchFile)) {
						if viper.GetBool("color") && !viper.GetBool("no-color") {
							fmt.Print(color.New(color.Bold).Sprintf("\n%s\n\n", f))
							if len(ent) > 0 {
								quick.Highlight(os.Stdout, ent, "xml", "terminal256", "nord")
							} else {
								fmt.Printf("\n\t- no entitlements\n")
							}
						} else {
							log.Infof(f)
							if len(ent) > 0 {
								fmt.Printf("\n%s\n", ent)
							} else {
								fmt.Printf("\n\t- no entitlements\n")
							}
						}
					}
				}
			}
		} else { // DUMP ALL ENTITLEMENTS
			for _, entDB := range entDBs {
				for f, ent := range entDB {
					if len(ent) == 0 {
						continue
					}
					if viper.GetBool("color") && !viper.GetBool("no-color") {
						fmt.Print(color.New(color.Bold).Sprintf("\n%s\n\n", f))
						quick.Highlight(os.Stdout, ent, "xml", "terminal256", "nord")
					} else {
						fmt.Printf("%s\n\n%s\n", f, ent)
					}
				}
			}
		}

		return nil
	},
}
