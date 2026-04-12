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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func selectKDKFolders() ([]string, error) {
	kdks, err := filepath.Glob("/Library/Developer/KDKs/KDK*")
	if err != nil {
		return nil, err
	}
	if len(kdks) < 2 {
		return nil, fmt.Errorf(
			"need at least 2 KDKs in /Library/Developer/KDKs; found %d",
			len(kdks),
		)
	}

	selected := []string{}
	prompt := &survey.MultiSelect{
		Message:  "Select 2 KDKs to diff:",
		Options:  kdks,
		PageSize: 15,
	}
	if err := survey.AskOne(
		prompt, &selected,
		survey.WithValidator(survey.MinItems(2)),
		survey.WithValidator(survey.MaxItems(2)),
	); err != nil {
		if err == terminal.InterruptErr {
			log.Warn("Exiting...")
			return nil, nil
		}
		return nil, err
	}

	return selected, nil
}

func collectFiles(root string) (map[string]os.FileInfo, error) {
	files := make(map[string]os.FileInfo)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warnf("skipping %s: %v", path, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[rel] = info
		return nil
	})
	return files, err
}

// isBinaryFile reads a file once and checks for Mach-O magic or null bytes.
func isBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	buf = buf[:n]

	if n >= 4 {
		if ok, _ := magic.IsMachOData(buf[:4]); ok {
			return true
		}
	}

	return slices.Contains(buf, byte(0))
}

type diffSection struct {
	title  string
	items  []string
	prefix string
	clr    *color.Color
}

func printSection(s diffSection) bool {
	if len(s.items) == 0 {
		return false
	}
	fmt.Println()
	color.New(color.Bold).Println(s.title)
	for _, item := range s.items {
		s.clr.Printf("  %s %s\n", s.prefix, item)
	}
	return true
}

type textDiff struct {
	file string
	diff string
}

var ignoredKDKPlistKeys = map[string]struct{}{
	"BuildMachineOSBuild":        {},
	"BuildVersion":               {},
	"CFBundleGetInfoString":      {},
	"CFBundleShortVersionString": {},
	"CFBundleVersion":            {},
	"DTCompiler":                 {},
	"DTPlatformBuild":            {},
	"DTPlatformName":             {},
	"DTPlatformVersion":          {},
	"DTSDKBuild":                 {},
	"DTSDKName":                  {},
	"DTXcode":                    {},
	"DTXcodeBuild":               {},
	"IOSourceVersion":            {},
	"NSHumanReadableCopyright":   {},
	"SourceVersion":              {},
}

func shouldNormalizeKDKPlist(rel string) bool {
	switch filepath.Base(rel) {
	case "Info.plist", "version.plist":
		return true
	default:
		return false
	}
}

func normalizeKDKTextDiffInput(rel string, data []byte) ([]byte, error) {
	if !shouldNormalizeKDKPlist(rel) {
		return data, nil
	}

	var document map[string]any
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&document); err != nil {
		return data, nil
	}

	stripIgnoredKDKPlistKeys(document)

	normalized, err := plist.MarshalIndent(document, plist.XMLFormat, "\t")
	if err != nil {
		return data, fmt.Errorf("failed to normalize plist %s: %w", rel, err)
	}

	return normalized, nil
}

func stripIgnoredKDKPlistKeys(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if _, ok := ignoredKDKPlistKeys[key]; ok {
				delete(node, key)
				continue
			}
			stripIgnoredKDKPlistKeys(child)
		}
	case []any:
		for _, item := range node {
			stripIgnoredKDKPlistKeys(item)
		}
	}
}

func init() {
	rootCmd.AddCommand(kdkDiffCmd)

	kdkDiffCmd.Flags().Bool(
		"binary-details", false,
		"Show size changes for modified binaries",
	)
	viper.BindPFlag(
		"kdk-diff.binary-details",
		kdkDiffCmd.Flags().Lookup("binary-details"),
	)
}

var kdkDiffCmd = &cobra.Command{
	Use:           "kdk-diff [KDK_FOLDER] [KDK_FOLDER]",
	Short:         "Diff two KDK folders",
	Args:          cobra.MaximumNArgs(2),
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		switch len(args) {
		case 0:
			if runtime.GOOS != "darwin" {
				return fmt.Errorf("provide 2 KDK folder paths as arguments")
			}
			selected, err := selectKDKFolders()
			if err != nil {
				return err
			}
			if selected == nil {
				return nil
			}
			args = selected
		case 1:
			return fmt.Errorf("provide 2 KDK folder paths (got 1)")
		}

		oldDir := filepath.Clean(args[0])
		newDir := filepath.Clean(args[1])

		for _, d := range []string{oldDir, newDir} {
			info, err := os.Stat(d)
			if err != nil {
				return fmt.Errorf("cannot access %s: %w", d, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", d)
			}
		}

		log.WithFields(log.Fields{
			"old": filepath.Base(oldDir),
			"new": filepath.Base(newDir),
		}).Info("Collecting files")

		oldFiles, err := collectFiles(oldDir)
		if err != nil {
			return fmt.Errorf("failed to walk %s: %w", oldDir, err)
		}
		newFiles, err := collectFiles(newDir)
		if err != nil {
			return fmt.Errorf("failed to walk %s: %w", newDir, err)
		}

		allPaths := make(map[string]bool)
		for p := range oldFiles {
			allPaths[p] = true
		}
		for p := range newFiles {
			allPaths[p] = true
		}

		var sorted []string
		for p := range allPaths {
			sorted = append(sorted, p)
		}
		sort.Strings(sorted)

		showBinaryDetails := viper.GetBool("kdk-diff.binary-details")
		diffTool := viper.GetString("diff-tool")
		useColor := viper.GetBool("color") && !viper.GetBool("no-color")

		var (
			addedBin, removedBin, modifiedBin []string
			addedText, removedText            []string
			textDiffs                         []textDiff
		)

		for _, rel := range sorted {
			oldInfo := oldFiles[rel]
			newInfo := newFiles[rel]
			oldPath := filepath.Join(oldDir, rel)
			newPath := filepath.Join(newDir, rel)

			switch {
			case oldInfo == nil:
				if isBinaryFile(newPath) {
					addedBin = append(addedBin, rel)
				} else {
					addedText = append(addedText, rel)
				}

			case newInfo == nil:
				if isBinaryFile(oldPath) {
					removedBin = append(removedBin, rel)
				} else {
					removedText = append(removedText, rel)
				}

			default:
				if isBinaryFile(oldPath) || isBinaryFile(newPath) {
					if oldInfo.Size() != newInfo.Size() {
						if showBinaryDetails {
							modifiedBin = append(modifiedBin,
								fmt.Sprintf("%s (%d -> %d bytes)",
									rel, oldInfo.Size(), newInfo.Size()))
						} else {
							modifiedBin = append(modifiedBin, rel)
						}
					} else {
						modifiedBin = append(modifiedBin, rel)
					}
					continue
				}

				oldData, err := os.ReadFile(oldPath)
				if err != nil {
					log.WithError(err).Warnf("failed to read %s", oldPath)
					continue
				}
				oldData, err = normalizeKDKTextDiffInput(rel, oldData)
				if err != nil {
					log.WithError(err).Warnf("failed to normalize %s", oldPath)
					continue
				}
				newData, err := os.ReadFile(newPath)
				if err != nil {
					log.WithError(err).Warnf("failed to read %s", newPath)
					continue
				}
				newData, err = normalizeKDKTextDiffInput(rel, newData)
				if err != nil {
					log.WithError(err).Warnf("failed to normalize %s", newPath)
					continue
				}

				if bytes.Equal(oldData, newData) {
					continue
				}

				out, err := utils.GitDiff(
					string(oldData),
					string(newData),
					&utils.GitDiffConfig{
						Color: useColor,
						Tool:  diffTool,
					},
				)
				if err != nil {
					log.WithError(err).Warnf("failed to diff %s", rel)
					continue
				}
				if len(out) > 0 {
					textDiffs = append(textDiffs, textDiff{rel, out})
				}
			}
		}

		hasOutput := false

		for _, s := range []diffSection{
			{"Removed Binaries:", removedBin, "-", color.New(color.FgRed)},
			{"Added Binaries:", addedBin, "+", color.New(color.FgGreen)},
			{"Modified Binaries:", modifiedBin, "~", color.New(color.FgYellow)},
			{"Removed Text Files:", removedText, "-", color.New(color.FgRed)},
			{"Added Text Files:", addedText, "+", color.New(color.FgGreen)},
		} {
			if printSection(s) {
				hasOutput = true
			}
		}

		if len(textDiffs) > 0 {
			hasOutput = true
			fmt.Println()
			color.New(color.Bold).Println("Modified Text Files:")
			cyan := color.New(color.FgCyan)
			separator := strings.Repeat("─", 60)
			for _, td := range textDiffs {
				fmt.Println()
				cyan.Printf("--- %s\n", td.file)
				fmt.Println(separator)
				fmt.Print(td.diff)
				fmt.Println(separator)
			}
		}

		if !hasOutput {
			log.Info("No differences found")
		}

		return nil
	},
}
