package backup

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName    = "com.apple.mobilebackup2"
	rdpServiceName = "com.apple.mobilebackup2.shim.remote"
)

type Client struct {
	uuid string
	c    *usb.Client
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		uuid: udid,
		c:    c,
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

func (c *Client) WillEncrypt() (bool, error) {
	cli, err := lockdownd.NewClient(c.uuid)
	if err != nil {
		return false, fmt.Errorf("failed to create lockdownd client: %v", err)
	}
	defer cli.Close()
	will, err := cli.GetValue("com.apple.mobile.backup", "WillEncrypt")
	if err != nil {
		return false, fmt.Errorf("failed to get backup WillEncrypt: %v", err)
	}
	return will.(bool), nil
}
