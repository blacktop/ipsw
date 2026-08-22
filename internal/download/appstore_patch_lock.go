//go:build !ios

package download

import "errors"

var errAppStorePatchLocked = errors.New("IPA creation locked by another process")
