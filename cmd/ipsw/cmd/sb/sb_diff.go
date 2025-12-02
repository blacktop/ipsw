//go:build sandbox

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
package sb

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	SbCmd.AddCommand(sbDiffCmd)

	sbDiffCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	sbDiffCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw", "*.zip")
	sbDiffCmd.MarkZshCompPositionalArgumentFile(2, "*.ipsw", "*.zip")
	sbDiffCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	}
	viper.BindPFlag("sb.diff.pem-db", sbDiffCmd.Flags().Lookup("pem-db"))
}

// sbDiffCmd represents the diff command
var sbDiffCmd = &cobra.Command{
	Use:           "diff <IPSW> <IPSW>",
	Short:         "Diff the sandbox profiles between two macOS IPSWs",
	Aliases:       []string{"d"},
	Args:          cobra.ExactArgs(2),
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		pemDB := viper.GetString("sb.diff.pem-db")

		var sbDBs []map[string]string

		log.Info("Parsing IPSWs")
		for _, ipswPath := range []string{filepath.Clean(args[0]), filepath.Clean(args[1])} {
			sbDB := make(map[string]string)

			i, err := info.Parse(ipswPath)
			if err != nil {
				return fmt.Errorf("failed to parse IPSW %s: %v", ipswPath, err)
			}

			var dmgs []string

			if appDMG, err := i.GetAppOsDmg(); err != nil {
				return fmt.Errorf("failed to get filesystem DMG path: %v", err)
			} else {
				dmgs = append(dmgs, appDMG)
			}
			if fsDMG, err := i.GetFileSystemOsDmg(); err != nil {
				return fmt.Errorf("failed to get filesystem DMG path: %v", err)
			} else {
				dmgs = append(dmgs, fsDMG)
			}
			if sysDMG, err := i.GetSystemOsDmg(); err != nil {
				return fmt.Errorf("failed to get filesystem DMG path: %v", err)
			} else {
				dmgs = append(dmgs, sysDMG)
			}

			for _, dmgPath := range dmgs {
				// check if filesystem DMG already exists (due to previous mount command)
				if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
					dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
						return strings.EqualFold(filepath.Base(f.Name), dmgPath)
					})
					if err != nil {
						return fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
					}
					if len(dmgs) == 0 {
						return fmt.Errorf("failed to find %s in IPSW", dmgPath)
					}
					defer os.Remove(dmgs[0])
				} else {
					utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", dmgPath))
				}

				if filepath.Ext(dmgPath) == ".aea" {
					dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
						Input:    dmgPath,
						Output:   filepath.Dir(dmgPath),
						PemDB:    pemDB,
						Proxy:    "",    // TODO: make proxy configurable
						Insecure: false, // TODO: make insecure configurable
					})
					if err != nil {
						return fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
					}
					defer os.Remove(dmgPath)
				}

				utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting FS %s", dmgPath))
				mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, "")
				if err != nil {
					return fmt.Errorf("failed to mount DMG: %v", err)
				}
				if alreadyMounted {
					utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
				} else {
					defer func() {
						utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
						if err := utils.Retry(3, 2*time.Second, func() error {
							return utils.Unmount(mountPoint, true)
						}); err != nil {
							utils.Indent(log.Error, 3)(fmt.Sprintf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err))
						}
					}()
				}

				var files []string
				if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						// utils.Indent(log.Error, 3)(fmt.Sprintf("failed to walk mount %s: %v", mountPoint, err))
						return nil
					}
					if !info.IsDir() && filepath.Ext(path) == ".sb" {
						files = append(files, path)
					}
					return nil
				}); err != nil {
					return fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
				}

				for _, file := range files {
					data, err := os.ReadFile(file)
					if err != nil {
						return fmt.Errorf("failed to read file %s: %v", file, err)
					}
					sbDB[strings.TrimPrefix(file, mountPoint)] = string(data)
				}
			}

			sbDBs = append(sbDBs, sbDB)
		}

		log.Info("Diffing SB Profiles")

		for f := range sbDBs[0] {
			if _, ok := sbDBs[1][f]; !ok {
				utils.Indent(log.WithFields(log.Fields{"profile": f}).Warn, 2)("Sandbox Profile Removed")
			}
		}

		var files []string
		for f := range sbDBs[1] {
			files = append(files, f)
		}
		sort.Strings(files)

		for _, f := range files {
			newSbData := sbDBs[1][f]
			if oldSbData, ok := sbDBs[0][f]; ok {
				out, err := utils.GitDiff(oldSbData+"\n", newSbData+"\n", &utils.GitDiffConfig{Color: colors.Active()})
				if err != nil {
					return fmt.Errorf("failed to diff %s: %v", f, err)
				}
				if len(out) == 0 {
					continue
				}
				fmt.Println(colors.Bold().Sprintf("\n%s\n", f))
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				fmt.Println(out)
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			} else { // NEW sandbox profile
				fmt.Println(colors.Bold().Sprintf("\n🆕 %s\n", f))
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				quick.Highlight(os.Stdout, newSbData, "scheme", "terminal256", "nord")
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			}

		}

		return nil
	},
}
