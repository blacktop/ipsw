package amfi

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const serviceName = "com.apple.amfi.lockdown"

var ErrPasscodeSet = fmt.Errorf("device has a passcode set")

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
	var resp Response
	if err := c.c.Request(&AmfiAction{Action: 1}, &resp); err != nil {
		return err
	}

	if err, ok := resp["Error"]; ok {
		if err == "Device has a passcode set" {
			return ErrPasscodeSet
		}
		return fmt.Errorf("failed to enable Developer Mode: %s", err)
	}

	if success, ok := resp["success"]; ok {
		switch v := success.(type) {
		case uint64:
			if v != 1 {
				return fmt.Errorf("failed to enable Developer Mode: success=%d", v)
			}
		case bool:
			if !v {
				return fmt.Errorf("failed to enable Developer Mode: success=%t", v)
			}
		}
	}

	return nil
}

func (c *Client) EnableDeveloperModePostRestart() error {
	var resp Response
	if err := c.c.Request(&AmfiAction{Action: 2}, &resp); err != nil {
		return err
	}

	if err, ok := resp["Error"]; ok {
		return fmt.Errorf("failed to enable Developer Mode: %s", err)
	}

	if success, ok := resp["success"]; ok {
		switch v := success.(type) {
		case uint64:
			if v != 1 {
				return fmt.Errorf("failed to enable Developer Mode: success=%d", v)
			}
		case bool:
			if !v {
				return fmt.Errorf("failed to enable Developer Mode: success=%t", v)
			}
		}
	}

	return nil
}
