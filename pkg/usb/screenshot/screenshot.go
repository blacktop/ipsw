package screenshot

import (
	"bytes"
	"image"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.mobile.screenshotr"
)

type Client struct {
	c *usb.Client
}

type ScreenShotRequest struct {
	MessageType string `plist:"MessageType"`
}

type ScreenShotResponse struct {
	ScreenShotData []byte `plist:"ScreenShotData"`
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}

	if _, err := c.DeviceLinkHandshake(); err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

func (c *Client) Screenshot() ([]byte, error) {
	req := ScreenShotRequest{
		MessageType: "ScreenShotRequest",
	}
	if err := c.c.DeviceLinkSend(req); err != nil {
		return nil, err
	}

	resp, err := c.c.DeviceLinkRecv()
	if err != nil {
		return nil, err
	}
	respMap := resp.(map[string]any)
	return respMap["ScreenShotData"].([]byte), nil
}

func (c *Client) ScreenshotImage() (image.Image, error) {
	data, err := c.Screenshot()
	if err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewBuffer(data))
	return img, err
}

func (c *Client) Close() error {
	return c.c.Close()
}
