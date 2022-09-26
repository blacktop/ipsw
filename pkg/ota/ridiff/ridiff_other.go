//go:build !darwin

package ridiff

import "fmt"

// RawImagePatch takes a Raw Image Diff and converts it to an APFS volume.
func RawImagePatch(patch, output string) error {
	return fmt.Errorf("RawImagePatch: only supported on darwin")
}
