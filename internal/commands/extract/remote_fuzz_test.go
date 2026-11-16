package extract

import (
	"bytes"
	"encoding/binary"
	"path"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzAPFSPartition feeds arbitrary images to the GPT parser. A returned
// partition must lie inside the image.
func FuzzAPFSPartition(f *testing.F) {
	le := binary.LittleEndian
	image := make([]byte, 4*512) // small seeds keep input minimization fast
	f.Add(bytes.Clone(image))
	copy(image[512:], "EFI PART")
	le.PutUint64(image[512+72:], 2)
	le.PutUint32(image[512+80:], 2)
	le.PutUint32(image[512+84:], 128)
	f.Add(bytes.Clone(image))
	copy(image[2*512:], []byte{0xef, 0x57, 0x34, 0x7c, 0, 0, 0xaa, 0x11, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac})
	le.PutUint64(image[2*512+32:], 3)
	le.PutUint64(image[2*512+40:], 3)
	f.Add(image)
	f.Fuzz(func(t *testing.T, data []byte) {
		source, size, err := apfsPartition(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		if size <= 0 || size > int64(len(data)) {
			t.Fatalf("partition of %d bytes in an image of %d", size, len(data))
		}
		if _, err := source.ReadAt(make([]byte, 1), size-1); err != nil {
			t.Fatalf("partition end unreadable: %v", err)
		}
	})
}

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
