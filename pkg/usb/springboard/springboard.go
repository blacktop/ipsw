package springboard

//go:generate go tool stringer -type=Orientation -output springboard_string.go

import (
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.springboardservices"
)

type Orientation uint32

const (
	Unknown             Orientation = 0
	Portrait            Orientation = 1
	PortraitUpsideDown  Orientation = 2
	Landscape           Orientation = 3
	LandscapeHomeToLeft Orientation = 4
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

type springboardRequest struct {
	Command  string `plist:"command,omitempty"`
	BundleID string `plist:"bundleId,omitempty"`
}

type getPngResponse struct {
	PngData []byte `plist:"pngData,omitempty"`
}

func (c *Client) GetIcon(bundleID string) ([]byte, error) {
	req := &springboardRequest{
		Command:  "getIconPNGData",
		BundleID: bundleID,
	}
	resp := &getPngResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp.PngData, nil
}

func (c *Client) GetWallpaper() ([]byte, error) {
	req := &springboardRequest{
		Command: "getHomeScreenWallpaperPNGData",
	}
	resp := &getPngResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp.PngData, nil
}

type getOrientationResponse struct {
	InterfaceOrientation Orientation `plist:"interfaceOrientation,omitempty"`
}

func (c *Client) GetInterfaceOrientation() (Orientation, error) {
	req := &springboardRequest{
		Command: "getInterfaceOrientation",
	}
	resp := &getOrientationResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return Unknown, err
	}
	return resp.InterfaceOrientation, nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
