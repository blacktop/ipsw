package image_mounter

import (
	"fmt"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.mobile.mobile_image_mounter"
)

const (
	ImageTypeDeveloper = "Developer"
)

type RequestBase struct {
	Command string `plist:"Command"`
}

type ResponseBase struct {
	Status string `plist:"Status"`
}

type LookupImageRequest struct {
	RequestBase
	ImageType string `plist:"ImageType"`
}

type LookupImageResponse struct {
	ResponseBase
	ImageSignature [][]byte `plist:"ImageSignature"`
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

func (c *Client) LookupImage(imageType string) (*LookupImageResponse, error) {
	req := &LookupImageRequest{
		RequestBase: RequestBase{"LookupImage"},
		ImageType:   imageType,
	}
	resp := &LookupImageResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) Mount(path, sig, imageType string) (*ResponseBase, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (c *Client) Hangup() error {
	req := &RequestBase{"Hangup"}
	resp := &ResponseBase{}
	return c.c.Request(req, resp)
}

func (c *Client) Close() error {
	c.Hangup()
	return c.c.Close()
}
