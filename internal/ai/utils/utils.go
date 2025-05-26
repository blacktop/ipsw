package utils

import (
	"regexp"
	"strings"
)

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
	// Use regex to extract code from Markdown code blocks
	codeBlockRegex := regexp.MustCompile("(?s)```(?:[a-zA-Z0-9_+-]*\\n)?(.*?)\\n?```")
	matches := codeBlockRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return content
}
