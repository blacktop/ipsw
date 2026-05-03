package diff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
)

const (
	sandboxDiffSourceCollection = "collection"
	sandboxDiffSourceProtobox   = "protobox"
	sandboxDiffSourceProfile    = "profile"
)

var sandboxDiffSourceOrder = []string{
	sandboxDiffSourceCollection,
	sandboxDiffSourceProtobox,
	sandboxDiffSourceProfile,
}

type sandboxProfileDocuments map[string]map[string]string

func renderSandboxProfileDiffMarkdown(oldDocs, newDocs sandboxProfileDocuments) (string, error) {
	var b strings.Builder

	for _, source := range sandboxProfileSourceNames(oldDocs, newDocs) {
		oldProfiles := oldDocs[source]
		newProfiles := newDocs[source]
		section, err := renderSandboxSourceDiffMarkdown(source, oldProfiles, newProfiles)
		if err != nil {
			return "", err
		}
		if section == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(section)
	}

	return b.String(), nil
}

func sandboxProfileSourceNames(oldDocs, newDocs sandboxProfileDocuments) []string {
	seen := make(map[string]bool)
	var names []string
	for _, source := range sandboxDiffSourceOrder {
		if len(oldDocs[source]) > 0 || len(newDocs[source]) > 0 {
			names = append(names, source)
			seen[source] = true
		}
	}

	var extras []string
	for source := range oldDocs {
		if !seen[source] {
			extras = append(extras, source)
			seen[source] = true
		}
	}
	for source := range newDocs {
		if !seen[source] {
			extras = append(extras, source)
		}
	}
	slices.Sort(extras)
	return append(names, extras...)
}

func renderSandboxSourceDiffMarkdown(source string, oldProfiles, newProfiles map[string]string) (string, error) {
	var removed []string
	var added []string
	var changed []string

	for name := range oldProfiles {
		if _, ok := newProfiles[name]; !ok {
			removed = append(removed, name)
		}
	}
	for name := range newProfiles {
		oldText, ok := oldProfiles[name]
		newText := newProfiles[name]
		switch {
		case !ok:
			added = append(added, name)
		case oldText != newText:
			changed = append(changed, name)
		}
	}

	if len(removed) == 0 && len(added) == 0 && len(changed) == 0 {
		return "", nil
	}

	slices.Sort(removed)
	slices.Sort(added)
	slices.Sort(changed)

	var b strings.Builder
	fmt.Fprintf(&b, "### %s\n\n", sandboxSourceTitle(source))

	if len(added) > 0 {
		fmt.Fprintf(&b, "#### New (%d)\n\n", len(added))
		for _, name := range added {
			writeSandboxProfileDocument(&b, name, newProfiles[name])
		}
	}

	if len(removed) > 0 {
		fmt.Fprintf(&b, "#### Removed (%d)\n\n", len(removed))
		for _, name := range removed {
			writeSandboxProfileDocument(&b, name, oldProfiles[name])
		}
	}

	if len(changed) > 0 {
		fmt.Fprintf(&b, "#### Changed (%d)\n\n", len(changed))
		for _, name := range changed {
			out, err := utils.GitDiff(
				ensureTrailingNewline(oldProfiles[name]),
				ensureTrailingNewline(newProfiles[name]),
				&utils.GitDiffConfig{Color: false, Tool: "git"},
			)
			if err != nil {
				return "", fmt.Errorf("failed to diff sandbox profile %s: %w", name, err)
			}
			if strings.TrimSpace(out) == "" {
				continue
			}
			fmt.Fprintf(&b, "##### %s\n\n```diff\n%s\n```\n\n", name, strings.TrimRight(out, "\n"))
		}
	}

	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func sandboxSourceTitle(source string) string {
	switch source {
	case sandboxDiffSourceCollection:
		return "Collection"
	case sandboxDiffSourceProtobox:
		return "Protobox/Autobox"
	case sandboxDiffSourceProfile:
		return "Platform Profile"
	default:
		return source
	}
}

func writeSandboxProfileDocument(b *strings.Builder, name, body string) {
	fmt.Fprintf(b, "##### %s\n\n```scheme\n%s\n```\n\n", name, strings.TrimRight(body, "\n"))
}

func ensureTrailingNewline(value string) string {
	if strings.HasSuffix(value, "\n") {
		return value
	}
	return value + "\n"
}
