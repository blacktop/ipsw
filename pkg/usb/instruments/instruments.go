package instruments

import (
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName    = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
	oldServiceName = "com.apple.instruments.remoteserver"
)

const (
	deviceInfoChannel            = "com.apple.instruments.server.services.deviceinfo"
	xpcControlChannel            = "com.apple.instruments.server.services.device.xpccontrol"
	procControlChannel           = "com.apple.instruments.server.services.processcontrol"
	procControlPosixSpawnChannel = "com.apple.instruments.server.services.processcontrol.posixspawn"
	mobileNotificationsChannel   = "com.apple.instruments.server.services.mobilenotifications"
	appListingChannel            = "com.apple.instruments.server.services.device.applictionListing"
	watchProcessControlChannel   = "com.apple.dt.Xcode.WatchProcessControl"
	assetsChannel                = "com.apple.instruments.server.services.assets"
	activityTraceTapChannel      = "com.apple.instruments.server.services.activitytracetap"
)

type Client struct {
	c *usb.Client
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		c: c,
	}, nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
