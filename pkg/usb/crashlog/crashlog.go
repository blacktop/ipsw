package crashlog

import (
	"github.com/blacktop/ipsw/pkg/usb/afc"
)

const (
	moverService      = "com.apple.mobile.diagnostics_relay"
	copyMobileService = "com.apple.crashreportcopymobile"
)

func NewClient(udid string) (*afc.Client, error) {
	return afc.NewClient(udid, copyMobileService)
}
