/*
Copyright © 2018-2023 blacktop

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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/alecthomas/chroma/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(entCmd)

	entCmd.Flags().StringP("ent", "e", "", "Entitlement to search for")
	entCmd.Flags().StringP("file", "f", "", "Dump entitlements for MachO")
	entCmd.Flags().StringP("output", "o", "", "Folder to r/w entitlement databases")
	entCmd.Flags().BoolP("diff", "d", false, "Diff entitlements")
	entCmd.Flags().BoolP("md", "m", false, "Markdown style output")
	viper.BindPFlag("ent.ent", entCmd.Flags().Lookup("ent"))
	viper.BindPFlag("ent.file", entCmd.Flags().Lookup("file"))
	viper.BindPFlag("ent.output", entCmd.Flags().Lookup("output"))
	viper.BindPFlag("ent.diff", entCmd.Flags().Lookup("diff"))
	viper.BindPFlag("ent.md", entCmd.Flags().Lookup("md"))
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
		color.NoColor = !viper.GetBool("color")

		entitlement := viper.GetString("ent.ent")
		searchFile := viper.GetString("ent.file")
		markdown := viper.GetBool("ent.md")

		if len(entitlement) > 0 && len(searchFile) > 0 {
			log.Errorf("you can only use --ent OR --file (not both)")
			return nil
		} else if len(entitlement) > 0 && viper.GetBool("ent.diff") {
			log.Errorf("you can only use --ent OR --diff (not both)")
			return nil
		}

		ipswPath := filepath.Clean(args[0])

		entDBPath := strings.TrimSuffix(ipswPath, filepath.Ext(ipswPath)) + ".entDB"
		if len(viper.GetString("ent.output")) > 0 {
			entDBPath = filepath.Join(viper.GetString("ent.output"), filepath.Base(entDBPath))
		}

		entDB, err := ent.GetDatabase(ipswPath, entDBPath)
		if err != nil {
			return fmt.Errorf("failed to get entitlement database: %v", err)
		}

		if viper.GetBool("ent.diff") { // DIFF ENTITLEMENTS
			if len(args) < 2 {
				return fmt.Errorf("you must specify two IPSWs to diff")
			}

			ipswPath2 := filepath.Clean(args[1])

			entDBPath2 := strings.TrimSuffix(ipswPath2, filepath.Ext(ipswPath2)) + ".entDB"
			if len(viper.GetString("ent.output")) > 0 {
				entDBPath2 = filepath.Join(viper.GetString("ent.output"), filepath.Base(entDBPath2))
			}

			entDB2, err := ent.GetDatabase(ipswPath2, entDBPath2)
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
			} else { // TODO: refactor this to use ent.DiffDatabases
				// sort latest entitlements DB's files
				var files []string
				for f := range entDB2 {
					files = append(files, f)
				}
				sort.Strings(files)

				found := false
				for _, f2 := range files { // DIFF ALL ENTITLEMENTS
					e2 := entDB2[f2]
					if e1, ok := entDB[f2]; ok {
						var out string
						if markdown {
							out, err = utils.GitDiff(e1+"\n", e2+"\n", &utils.GitDiffConfig{Color: false, Tool: "git"})
							if err != nil {
								return err
							}
						} else {
							out, err = utils.GitDiff(e1+"\n", e2+"\n", &utils.GitDiffConfig{Color: viper.GetBool("color"), Tool: viper.GetString("diff-tool")})
							if err != nil {
								return err
							}
						}
						if len(out) == 0 {
							continue
						}
						found = true
						if markdown {
							color.New(color.Bold).Printf("\n### `%s`\n\n", f2)
							fmt.Println("```diff")
							fmt.Println(out)
							fmt.Println("```")
						} else {
							color.New(color.Bold).Printf("\n%s\n\n", f2)
							fmt.Println(out)
						}
					} else {
						found = true
						if markdown {
							color.New(color.Bold).Printf("\n### 🆕 `%s`\n\n", f2)
						} else {
							color.New(color.Bold).Printf("\n🆕 %s 🆕\n\n", f2)
						}
						if len(e2) == 0 {
							if markdown {
								fmt.Println("- No entitlements *(yet)*")
							} else {
								log.Warn("No entitlements (yet)")
							}
						} else {
							if viper.GetBool("color") {
								if err := quick.Highlight(os.Stdout, e2, "xml", "terminal256", "nord"); err != nil {
									return err
								}
							} else {
								if markdown {
									fmt.Println("```xml")
									fmt.Println(e2)
									fmt.Println("```")
								} else {
									fmt.Println(e2)
								}
							}
						}
					}
				}
				if !found {
					log.Warn("No differences found")
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
					ents := make(map[string]any)
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
