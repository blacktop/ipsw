package utils

import "strings"

func removeThink(content string) string {
	if strings.HasPrefix(content, "<think>") {
		if _, rest, found := strings.Cut(content, "</think>"); found {
			return rest
		}
	}
	return content
}

func Clean(content string) string {
	content = removeThink(content)
	content = strings.TrimSpace(content)
	// remove code block
	if strings.HasPrefix(content, "```") {
		_, content, _ = strings.Cut(content, "\n")
	}
	return strings.TrimSuffix(content, "```")
}
