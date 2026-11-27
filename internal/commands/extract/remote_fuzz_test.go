package extract

import (
	"path"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzPrefixMatcher checks that pruning never hides a match: every ancestor
// directory of a path the pattern matches must be walked.
func FuzzPrefixMatcher(f *testing.F) {
	f.Add(`^/System/(Library|iOSSupport/System/Library)/(Chat|IM).*\.loctable$`, "System/Library/IMCore/a.loctable")
	f.Add(`^System/Library/Foo|\.loctable$`, "usr/share/x.loctable")
	f.Add(`^/?usr/(lib|libexec)/`, "usr/libexec/amfid")
	f.Add(`(?m)^usr$`, "a/usr")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		re, err := regexp.Compile(pattern)
		if err != nil || !utf8.ValidString(name) || name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name {
			return
		}
		// The walk matches a file as either "rel" or "/rel".
		if !re.MatchString(name) && !re.MatchString("/"+name) {
			return
		}
		matcher := newPrefixMatcher(pattern)
		for i, c := range name {
			if c == '/' && !matcher.directory(name[:i]) {
				t.Fatalf("pattern %q matches %q but prunes %q", pattern, name, name[:i])
			}
		}
	})
}
