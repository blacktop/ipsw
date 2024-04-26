package heartbeat

import (
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const serviceName = "com.apple.mobile.heartbeat"

type Response struct {
	Command            string `plist:"Command,omitempty"`
	Interval           uint64 `plist:"Interval,omitempty"`
	SupportsSleepyTime bool   `plist:"SupportsSleepyTime,omitempty"`
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

func (c *Client) Beat() (*Response, error) {
	var resp Response
	if err := c.c.Request(&map[string]any{
		"Command": "Polo",
	}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
