package extract

import (
	"regexp"
	"testing"
)

func TestRangedPrefixMatcher(t *testing.T) {
	patterns := []string{`^/System/(Library|iOSSupport/System/Library)/(PrivateFrameworks|AccessibilityBundles)/(Chat|IM).*\.loctable$`, `^/?System/Library/IM[^/]+/.*$`, `^/System/Library/IM`, `loctable$`}
	candidates := []string{"/System/Library/PrivateFrameworks/IMCore.framework/Versions/A/Resources/Localizable.loctable", "/System/iOSSupport/System/Library/AccessibilityBundles/ChatKit.axbundle/Localizable.loctable", "System/Library/IMCore/a", "/other/loctable"}
	for _, pattern := range patterns {
		m := newPrefixMatcher(pattern)
		r := regexp.MustCompile(pattern)
		for _, candidate := range candidates {
			if !r.MatchString(candidate) {
				continue
			}
			for i, c := range candidate {
				if c == '/' && i > 0 {
					directory := candidate[:i]
					if directory[0] == '/' {
						directory = directory[1:]
					}
					if !m.directory(directory) {
						t.Fatalf("pruned matching path %q at %q for %q", candidate, directory, pattern)
					}
				}
			}
		}
	}
	// Only one branch is anchored, so nothing may be pruned.
	if !newPrefixMatcher(`^System/Library/Foo|\.loctable$`).directory("usr") {
		t.Fatal("pruned a directory an unanchored branch can match")
	}
	if newPrefixMatcher(`^/System/Library/IM.*`).directory("Applications") {
		t.Fatal("failed to prune unrelated directory")
	}
}
