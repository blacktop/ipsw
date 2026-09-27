package utils

import (
	"errors"
	"fmt"
	"os"
)

// RemoveTempDir removes dir and folds a removal failure into *retErr, so a
// deferred cleanup neither hides the caller's own error nor is silently lost.
func RemoveTempDir(dir string, retErr *error) {
	if err := os.RemoveAll(dir); err != nil {
		*retErr = errors.Join(*retErr, fmt.Errorf("failed to remove temporary directory %s: %w", dir, err))
	}
}
