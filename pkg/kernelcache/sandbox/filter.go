package sandbox

import (
	_ "embed"
)

//go:embed data/libsandbox_12.3.0.gz
var libsandboxData []byte
