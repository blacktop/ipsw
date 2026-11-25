//go:build ipsw_ext && !ios

package download

import (
	ext "github.com/blacktop/ipsw/pkg/ext/register"
	"github.com/spf13/cobra"
)

// Package-level variables are initialized before any init function runs, so
// the hook is in place when download_ipa.go's init reaches it, whatever the
// order of the files.
var _ = func() bool {
	ipaExtension = func(cmd *cobra.Command) { ext.Register(cmd, pickApps) }
	return true
}()
