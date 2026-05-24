//go:build sandbox

/*
Copyright © 2026 blacktop

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
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	SbCmd.AddCommand(sbDiffCmd)

	sbDiffCmd.Flags().String("pem-db", "", "AEA pem DB JSON file")
	sbDiffCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	sbDiffCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	sbDiffCmd.Flags().String("profile", "", "Regex filter for sandbox profile path/name")
	sbDiffCmd.Flags().Bool("rules", false, "Show added/removed allow/deny rule classification")
	sbDiffCmd.MarkZshCompPositionalArgumentFile(1, "*.ipsw", "*.zip")
	sbDiffCmd.MarkZshCompPositionalArgumentFile(2, "*.ipsw", "*.zip")
	sbDiffCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	}
	viper.BindPFlag("sb.diff.pem-db", sbDiffCmd.Flags().Lookup("pem-db"))
	viper.BindPFlag("sb.diff.proxy", sbDiffCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("sb.diff.insecure", sbDiffCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("sb.diff.profile", sbDiffCmd.Flags().Lookup("profile"))
	viper.BindPFlag("sb.diff.rules", sbDiffCmd.Flags().Lookup("rules"))
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
		proxy := viper.GetString("sb.diff.proxy")
		insecure := viper.GetBool("sb.diff.insecure")
		profilePattern := viper.GetString("sb.diff.profile")
		profileFilter, err := compileSBDiffProfileFilter(profilePattern)
		if err != nil {
			return err
		}
		classifyRules := viper.GetBool("sb.diff.rules") || profilePattern != ""

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
						Proxy:    proxy,
						Insecure: insecure,
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
					profilePath := strings.TrimPrefix(file, mountPoint)
					if !sbDiffProfileMatches(profileFilter, profilePath) {
						continue
					}
					data, err := os.ReadFile(file)
					if err != nil {
						return fmt.Errorf("failed to read file %s: %v", file, err)
					}
					sbDB[profilePath] = string(data)
				}
			}

			sbDBs = append(sbDBs, sbDB)
		}

		log.Info("Diffing SB Profiles")

		for f, oldSbData := range sbDBs[0] {
			if _, ok := sbDBs[1][f]; !ok {
				utils.Indent(log.WithFields(log.Fields{"profile": f}).Warn, 2)("Sandbox Profile Removed")
				if classifyRules {
					printSandboxRuleClassificationDiff(f, oldSbData, "")
				}
			}
		}

		var files []string
		for f := range sbDBs[1] {
			files = append(files, f)
		}
		sort.Strings(files)

		if profilePattern != "" && len(sbDBs[0]) == 0 && len(sbDBs[1]) == 0 {
			log.Warnf("No sandbox profiles matched --profile %q", profilePattern)
		}

		for _, f := range files {
			newSbData := sbDBs[1][f]
			if oldSbData, ok := sbDBs[0][f]; ok {
				out, err := utils.GitDiff(oldSbData+"\n", newSbData+"\n", &utils.GitDiffConfig{Color: viper.GetBool("color") && !viper.GetBool("no-color")})
				if err != nil {
					return fmt.Errorf("failed to diff %s: %v", f, err)
				}
				if len(out) == 0 {
					continue
				}
				if classifyRules {
					printSandboxRuleClassificationDiff(f, oldSbData, newSbData)
				}
				fmt.Println(color.New(color.Bold).Sprintf("\n%s\n", f))
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				fmt.Println(out)
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			} else { // NEW sandbox profile
				if classifyRules {
					printSandboxRuleClassificationDiff(f, "", newSbData)
				}
				fmt.Println(color.New(color.Bold).Sprintf("\n🆕 %s\n", f))
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				quick.Highlight(os.Stdout, newSbData, "scheme", "terminal256", "nord")
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			}

		}

		return nil
	},
}

type sbDiffRule struct {
	Action    string
	Operation string
	Text      string
}

type sbDiffRuleDelta struct {
	Status    string
	Action    string
	Operation string
	Count     int
	Examples  []string
}

func compileSBDiffProfileFilter(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil
	}
	filter, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid --profile regex %q: %w", pattern, err)
	}
	return filter, nil
}

func sbDiffProfileMatches(filter *regexp.Regexp, profilePath string) bool {
	if filter == nil {
		return true
	}
	base := filepath.Base(profilePath)
	candidates := []string{
		profilePath,
		strings.TrimPrefix(profilePath, string(filepath.Separator)),
		base,
		strings.TrimSuffix(base, filepath.Ext(base)),
	}
	for _, candidate := range candidates {
		if filter.MatchString(candidate) {
			return true
		}
	}
	return false
}

func sandboxRuleClassificationDiff(oldData, newData string) []sbDiffRuleDelta {
	oldRules := countSBDiffRules(oldData)
	newRules := countSBDiffRules(newData)
	groups := make(map[string]*sbDiffRuleDelta)
	addGroup := func(status string, rule sbDiffRule, count int) {
		key := status + "\x00" + rule.Action + "\x00" + rule.Operation
		group := groups[key]
		if group == nil {
			group = &sbDiffRuleDelta{Status: status, Action: rule.Action, Operation: rule.Operation}
			groups[key] = group
		}
		group.Count += count
		if len(group.Examples) < 3 {
			group.Examples = append(group.Examples, rule.Text)
		}
	}

	for text, oldRule := range oldRules {
		newRule, ok := newRules[text]
		newCount := 0
		if ok {
			newCount = newRule.Count
		}
		if oldRule.Count > newCount {
			addGroup("-", oldRule.Rule, oldRule.Count-newCount)
		}
	}
	for text, newRule := range newRules {
		oldRule, ok := oldRules[text]
		oldCount := 0
		if ok {
			oldCount = oldRule.Count
		}
		if newRule.Count > oldCount {
			addGroup("+", newRule.Rule, newRule.Count-oldCount)
		}
	}

	deltas := make([]sbDiffRuleDelta, 0, len(groups))
	for _, group := range groups {
		deltas = append(deltas, *group)
	}
	sort.Slice(deltas, func(i, j int) bool {
		if deltas[i].Status != deltas[j].Status {
			return deltas[i].Status < deltas[j].Status
		}
		if deltas[i].Action != deltas[j].Action {
			return deltas[i].Action < deltas[j].Action
		}
		return deltas[i].Operation < deltas[j].Operation
	})
	return deltas
}

type sbDiffRuleCount struct {
	Rule  sbDiffRule
	Count int
}

func countSBDiffRules(data string) map[string]sbDiffRuleCount {
	counts := make(map[string]sbDiffRuleCount)
	for _, rule := range parseSBDiffRules(data) {
		count := counts[rule.Text]
		count.Rule = rule
		count.Count++
		counts[rule.Text] = count
	}
	return counts
}

func parseSBDiffRules(data string) []sbDiffRule {
	var rules []sbDiffRule
	var stack []int
	inString := false
	escaped := false
	inComment := false
	for idx := 0; idx < len(data); idx++ {
		ch := data[idx]
		if inComment {
			if ch == '\n' || ch == '\r' {
				inComment = false
			}
			continue
		}
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case ';':
			inComment = true
		case '"':
			inString = true
		case '(':
			stack = append(stack, idx)
		case ')':
			if len(stack) == 0 {
				continue
			}
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if rule, ok := sbDiffRuleFromForm(data[start : idx+1]); ok {
				rules = append(rules, rule)
			}
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Action != rules[j].Action {
			return rules[i].Action < rules[j].Action
		}
		if rules[i].Operation != rules[j].Operation {
			return rules[i].Operation < rules[j].Operation
		}
		return rules[i].Text < rules[j].Text
	})
	return rules
}

func sbDiffRuleFromForm(form string) (sbDiffRule, bool) {
	if len(form) < 2 || form[0] != '(' || form[len(form)-1] != ')' {
		return sbDiffRule{}, false
	}
	atoms := firstSBDiffAtoms(form[1:len(form)-1], 2)
	if len(atoms) < 2 {
		return sbDiffRule{}, false
	}
	action := strings.ToLower(atoms[0])
	if action != "allow" && action != "deny" {
		return sbDiffRule{}, false
	}
	operation := atoms[1]
	if operation == "" || strings.HasPrefix(operation, "(") || strings.HasPrefix(operation, "\"") {
		return sbDiffRule{}, false
	}
	return sbDiffRule{Action: action, Operation: operation, Text: normalizeSBDiffForm(form)}, true
}

func firstSBDiffAtoms(body string, limit int) []string {
	var atoms []string
	for idx := 0; idx < len(body) && len(atoms) < limit; {
		for idx < len(body) && isSBDiffSpace(body[idx]) {
			idx++
		}
		if idx >= len(body) {
			break
		}
		start := idx
		switch body[idx] {
		case '"':
			idx = scanSBDiffQuoted(body, idx)
		case '(':
			idx = scanSBDiffNestedForm(body, idx)
		default:
			for idx < len(body) && !isSBDiffSpace(body[idx]) && body[idx] != '(' && body[idx] != ')' {
				idx++
			}
		}
		atoms = append(atoms, body[start:idx])
	}
	return atoms
}

func scanSBDiffQuoted(text string, start int) int {
	idx := start + 1
	escaped := false
	for idx < len(text) {
		ch := text[idx]
		idx++
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			break
		}
	}
	return idx
}

func scanSBDiffNestedForm(text string, start int) int {
	depth := 0
	for idx := start; idx < len(text); idx++ {
		switch text[idx] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return idx + 1
			}
		}
	}
	return len(text)
}

func normalizeSBDiffForm(form string) string {
	var b strings.Builder
	inString := false
	escaped := false
	inComment := false
	pendingSpace := false
	for idx := 0; idx < len(form); idx++ {
		ch := form[idx]
		if inComment {
			if ch == '\n' || ch == '\r' {
				inComment = false
				pendingSpace = true
			}
			continue
		}
		if inString {
			b.WriteByte(ch)
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch {
		case ch == ';':
			inComment = true
		case ch == '"':
			writeSBDiffPendingSpace(&b, &pendingSpace, ch)
			b.WriteByte(ch)
			inString = true
		case isSBDiffSpace(ch):
			pendingSpace = true
		case ch == ')':
			pendingSpace = false
			b.WriteByte(ch)
		default:
			writeSBDiffPendingSpace(&b, &pendingSpace, ch)
			b.WriteByte(ch)
		}
	}
	return strings.TrimSpace(b.String())
}

func writeSBDiffPendingSpace(b *strings.Builder, pending *bool, next byte) {
	if !*pending || b.Len() == 0 || next == ')' {
		*pending = false
		return
	}
	value := b.String()
	if value[len(value)-1] != '(' {
		b.WriteByte(' ')
	}
	*pending = false
}

func isSBDiffSpace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func printSandboxRuleClassificationDiff(profile string, oldData string, newData string) {
	deltas := sandboxRuleClassificationDiff(oldData, newData)
	title := color.New(color.Bold).Sprintf("\nRule classification: %s\n", profile)
	fmt.Print(title)
	if len(deltas) == 0 {
		fmt.Println("  no added/removed allow/deny rules")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "change\taction\toperation\tcount\texample")
	for _, delta := range deltas {
		example := ""
		if len(delta.Examples) > 0 {
			example = trimSBDiffExample(delta.Examples[0])
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", delta.Status, delta.Action, delta.Operation, delta.Count, example)
	}
	_ = w.Flush()
}

func trimSBDiffExample(value string) string {
	const limit = 160
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
