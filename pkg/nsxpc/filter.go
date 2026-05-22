package nsxpc

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
)

func normalizeGlobPatterns(values []string) []string {
	seen := make(map[string]struct{})
	var patterns []string
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			pattern := strings.TrimSpace(part)
			if pattern == "" {
				continue
			}
			if _, ok := seen[pattern]; ok {
				continue
			}
			seen[pattern] = struct{}{}
			patterns = append(patterns, pattern)
		}
	}
	sort.Strings(patterns)
	return patterns
}

func (s *scanner) imageNameMatchesScope(name string) bool {
	if len(s.dylibPatterns) == 0 {
		return true
	}
	return imageNameMatchesAny(name, s.dylibPatterns)
}

func (s *scanner) hasScope() bool {
	return len(s.dylibPatterns) > 0 || len(s.servicePatterns) > 0
}

func (s *scanner) imageInScope(name string) bool {
	if !s.hasScope() {
		return true
	}
	_, ok := s.scopedImages[name]
	return ok
}

func (s *scanner) collectScopedImages() {
	if !s.hasScope() {
		return
	}
	s.scopedImages = make(map[string]struct{})
	for _, img := range s.f.Images {
		if !s.imageNameMatchesScope(img.Name) {
			continue
		}
		if len(s.servicePatterns) == 0 {
			s.scopedImages[img.Name] = struct{}{}
			continue
		}
		m, err := img.GetMacho()
		if err != nil {
			progress(s.stderr, "dsc: failed to parse %s during scope selection: %v\n", img.Name, err)
			img.Free()
			continue
		}
		if machoCStringsMatchAny(m, s.servicePatterns) {
			s.scopedImages[img.Name] = struct{}{}
		}
		img.Free()
	}
	progress(s.stderr, "dsc: scoped NSXPC scan to %d image(s)\n", len(s.scopedImages))
}

func imageNameMatchesAny(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	candidates := []string{
		name,
		filepath.Base(name),
		strings.TrimSuffix(filepath.Base(name), filepath.Ext(filepath.Base(name))),
	}
	if framework := frameworkName(name); framework != "" {
		candidates = append(candidates, framework)
	}
	for _, candidate := range candidates {
		if matchAnyGlob(candidate, patterns) {
			return true
		}
	}
	return false
}

func frameworkName(name string) string {
	for part := range strings.SplitSeq(filepath.ToSlash(name), "/") {
		if before, ok := strings.CutSuffix(part, ".framework"); ok {
			return before
		}
	}
	return ""
}

func machoCStringsMatchAny(m *macho.File, patterns []string) bool {
	if m == nil || len(patterns) == 0 {
		return false
	}
	stringsBySection, err := m.GetCStrings()
	if err != nil {
		return false
	}
	for _, sectionStrings := range stringsBySection {
		for value := range sectionStrings {
			if matchAnyGlob(value, patterns) {
				return true
			}
		}
	}
	return false
}

func matchAnyGlob(value string, patterns []string) bool {
	foldedValue := strings.ToLower(value)
	for _, pattern := range patterns {
		if strings.EqualFold(value, pattern) {
			return true
		}
		foldedPattern := strings.ToLower(pattern)
		matched, err := filepath.Match(foldedPattern, foldedValue)
		if err == nil && matched {
			return true
		}
		if !strings.ContainsAny(pattern, "*?[") && strings.Contains(foldedValue, foldedPattern) {
			return true
		}
	}
	return false
}
