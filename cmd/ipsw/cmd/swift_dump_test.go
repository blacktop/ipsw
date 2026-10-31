package cmd

import (
	"errors"
	"reflect"
	"testing"

	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/dyld"
)

func TestRunSwiftDumpImages(t *testing.T) {
	first, last := errors.New("first malformed image"), errors.New("last malformed image")
	images := []*dyld.CacheImage{{Name: "no-swift"}, {Name: "first"}, {Name: "good"}, {Name: "last"}}
	for _, tc := range []struct {
		name string
		all  bool
		seen []string
	}{
		{"selected", false, []string{"no-swift", "first"}},
		{"all", true, []string{"no-swift", "first", "good", "last"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			err := runSwiftDumpImages(images, tc.all, func(image *dyld.CacheImage) error {
				seen = append(seen, image.Name)
				switch image.Name {
				case "no-swift":
					return mcmd.ErrNoSwift
				case "first":
					return first
				case "last":
					return last
				}
				return nil
			})
			if !reflect.DeepEqual(seen, tc.seen) || !errors.Is(err, first) || errors.Is(err, last) != tc.all || errors.Is(err, mcmd.ErrNoSwift) {
				t.Fatalf("visited %v, error %v; want visits %v", seen, err, tc.seen)
			}
		})
	}
}
