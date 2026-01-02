// go 1.25 dropped macOS Big Sur support by introducing dependency on macOS 12+ API,
// so neither toolchain nor software built with it can be run on Big Sur
//
// Reference: https://github.com/golang/go/blob/ea603eea37f1030cfeecbe03ec7660fbc0da7819/src/crypto/x509/internal/macos/security.s#L26
//
// This shim provides _SecTrustCopyCertificateChain symbol required by go 1.25 runtime
// to mitigate this.
//
// NOTE: unless macOS SDK 10.14 - 11.x is detected, this shim is DISABLED by default.
// To enable regardless of macOS SDK version, pass `sectrust_compat` build tag.

package utils

import (
	_ "github.com/ink-splatters/darwin-sectrust-compat"
)
