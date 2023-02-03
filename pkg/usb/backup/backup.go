package backup

import (
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const serviceName = "com.apple.mobilebackup2"

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

func (c *Client) GetMsg() (any, error) {
	var resp any
	if err := c.c.Recv(resp); err != nil {
		return nil, err
	}
	return resp, nil
}
