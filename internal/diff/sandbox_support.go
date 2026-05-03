package diff

import "errors"

var ErrSandboxDiffUnavailable = errors.New("sandbox diff support is not built; rebuild with -tags sandbox")
