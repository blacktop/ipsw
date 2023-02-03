package companion

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.companion_proxy"
)

type getDeviceRegResponse struct {
	PairedDevicesArray []string `plist:"PairedDevicesArray,omitempty"`
	Error              string   `plist:"Error,omitempty"`
}

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

func (c *Client) List() ([]string, error) {
	var resp getDeviceRegResponse
	if err := c.c.Request(&map[string]any{
		"Command": "GetDeviceRegistry",
	}, &resp); err != nil {
		return nil, err
	}

	if len(resp.Error) > 0 {
		return nil, fmt.Errorf("failed to get device registry: %s", resp.Error)
	}

	return resp.PairedDevicesArray, nil
}
