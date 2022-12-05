package dvt

import (
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName    = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
	oldServiceName = "com.apple.instruments.remoteserver"
)

const (
	activityTraceTapChannel      = "com.apple.instruments.server.services.activitytracetap"
	assetsChannel                = "com.apple.instruments.server.services.assets"
	appListingChannel            = "com.apple.instruments.server.services.device.applictionListing"
	deviceInfoChannel            = "com.apple.instruments.server.services.deviceinfo"
	xpcControlChannel            = "com.apple.instruments.server.services.device.xpccontrol"
	mobileNotificationsChannel   = "com.apple.instruments.server.services.mobilenotifications"
	procControlChannel           = "com.apple.instruments.server.services.processcontrol"
	procControlPosixSpawnChannel = "com.apple.instruments.server.services.processcontrol.posixspawn"
	watchProcessControlChannel   = "com.apple.dt.Xcode.WatchProcessControl"
)

type Client struct {
	c *usb.Client
}

func NewSecureSocketProxy(udid string) (*Client, error) {
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
