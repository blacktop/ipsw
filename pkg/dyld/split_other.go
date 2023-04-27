//go:build !darwin

package dyld

import "fmt"

// Split extracts all the dyld_shared_cache libraries
func Split(dyldSharedCachePath, destinationPath, xcodePath string, xcodeCache bool) error {
	return fmt.Errorf("splitting dyld_shared_cache is only supported on darwin")
}
