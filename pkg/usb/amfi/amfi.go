package amfi

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const serviceName = "com.apple.amfi.lockdown"

type AmfiAction struct {
	Action int `plist:"action,omitempty"`
}

type Response map[string]any

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

func (c *Client) EnableDeveloperMode() error {
	req := &AmfiAction{Action: 1}
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}

	if err, ok := resp["Error"]; ok {
		return fmt.Errorf("failed to enable developer mode: %s", err)
	}

	if success, ok := resp["success"]; ok && !success.(bool) {
		return fmt.Errorf("failed to enable developer mode: success=%t", success)
	}

	return nil
}

func (c *Client) EnableDeveloperModePostRestart() error {
	req := &AmfiAction{Action: 2}
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}

	if err, ok := resp["Error"]; ok {
		return fmt.Errorf("failed to enable developer mode: %s", err)
	}

	if success, ok := resp["success"]; ok && !success.(bool) {
		return fmt.Errorf("failed to enable developer mode: success=%t", success)
	}

	return nil
}
