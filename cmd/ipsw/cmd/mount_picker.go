package cmd

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/blacktop/ipsw/pkg/info"
)

func newMountSystemOSPrompt(dmgs []info.SystemOSDMG) *survey.Select {
	prompt := &survey.Select{Message: "Select a SystemOS image:"}
	var help strings.Builder
	help.WriteString("Filter by device, board, or filename. Ctrl+C cancels.\n\nTargets in this IPSW:\n")
	for _, dmg := range dmgs {
		prompt.Options = append(prompt.Options, mountSystemOSLabel(dmg))
		fmt.Fprintf(&help, "\n%s\n", dmg.Path)
		for _, group := range []struct {
			name   string
			values []string
		}{{"Models", dmg.Devices}, {"Boards", dmg.Boards}} {
			if len(group.values) == 0 {
				continue
			}
			fmt.Fprintf(&help, "  %s:\n", group.name)
			for start := 0; start < len(group.values); start += 4 {
				fmt.Fprintf(&help, "    %s\n", strings.Join(group.values[start:min(start+4, len(group.values))], ", "))
			}
		}
	}
	prompt.Help = strings.TrimSpace(help.String())
	// Survey passes the original option index, including after filtering.
	// Keep search metadata separate from the compact display labels.
	prompt.Filter = func(filter, _ string, index int) bool {
		return strings.Contains(strings.ToLower(dmgs[index].Path), strings.ToLower(filter)) ||
			mountSystemOSTargetMatch(dmgs[index], filter) != ""
	}
	prompt.Description = func(value string, index int) string {
		// FilterMessage is refreshed by Survey before each render, including
		// when the filter is cleared (when Filter itself is not called).
		match := mountSystemOSTargetMatch(dmgs[index], strings.TrimSpace(prompt.FilterMessage))
		if match == "" || strings.Contains(value, match) {
			return ""
		}
		return "matches " + match
	}
	return prompt
}

func mountSystemOSLabel(dmg info.SystemOSDMG) string {
	targets, unit := dmg.Devices, "models"
	if len(targets) == 0 {
		targets, unit = dmg.Boards, "boards"
	}
	if len(targets) == 0 {
		return dmg.Path
	}
	if len(targets) <= 3 {
		return dmg.Path + "  " + strings.Join(targets, ", ")
	}
	return fmt.Sprintf("%s  Shared · %d %s", dmg.Path, len(targets), unit)
}

func mountSystemOSTargetMatch(dmg info.SystemOSDMG, filter string) string {
	if filter == "" {
		return ""
	}
	filter = strings.ToLower(filter)
	for _, targets := range [][]string{dmg.Devices, dmg.Boards} {
		for _, target := range targets {
			if strings.Contains(strings.ToLower(target), filter) {
				return target
			}
		}
	}
	return ""
}
