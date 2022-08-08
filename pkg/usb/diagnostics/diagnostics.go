package diagnostics

import (
	"crypto/md5"
	"encoding/base64"
	"strings"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.mobile.diagnostics_relay"
)

type Response map[string]interface{}

type Request struct {
	Request string `plist:"Request"`
}

type MobileGesaltRequest struct {
	Request
	MobileGestaltKeys []string `plist:"MobileGestaltKeys"`
}

type IORegistryRequest struct {
	Request
	CurrentPlane string `plist:"CurrentPlane,omitempty"`
	EntryName    string `plist:"EntryName,omitempty"`
	EntryClass   string `plist:"EntryClass,omitempty"`
}

type Client struct {
	c *usb.Client
}

func MobileGestaltEncrypt(key string) string {
	h := md5.Sum([]byte("MGCopyAnswer" + key))
	return base64.StdEncoding.EncodeToString(h[:])[:22]
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

func (c *Client) Diagnostics(diagnosticType string) error {
	req := &Request{
		Request: diagnosticType,
	}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) IORegistry(plane, entryName, entryClass string) error {
	req := &IORegistryRequest{
		Request:      Request{"IORegistry"},
		CurrentPlane: plane,
		EntryName:    entryName,
		EntryClass:   entryClass,
	}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) MobileGestalt(keys ...string) error {
	newKeys := make([]string, 0, len(keys))
	for _, key := range keys {
		if strings.HasPrefix(key, "!") {
			key = MobileGestaltEncrypt(key[1:])
		}
		newKeys = append(newKeys, key)
	}
	req := &MobileGesaltRequest{
		Request:           Request{"MobileGestalt"},
		MobileGestaltKeys: newKeys,
	}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) Goodbye() error {
	req := &Request{"Goodbye"}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) Sleep() error {
	req := &Request{"Sleep"}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) Restart() error {
	req := &Request{"Restart"}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) Shutdown() error {
	req := &Request{"Shutdown"}
	resp := &Response{}
	return c.c.Request(req, resp)
}

func (c *Client) Close() error {
	return c.c.Close()
}
