package diagnostics

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName    = "com.apple.mobile.diagnostics_relay"
	oldServiceName = "com.apple.iosdiagnostics.relay"
)

type Response map[string]any

type Request struct {
	Request string `plist:"Request"`
}

type MobileGesaltRequest struct {
	Request
	MobileGestaltKeys []string `plist:"MobileGestaltKeys"`
}

type DiagnosticsResponse struct {
	Status      string         `plist:"Status,omitempty" json:"status,omitempty"`
	Diagnostics map[string]any `plist:"Diagnostics,omitempty" json:"diagnostics,omitempty"`
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
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}
	if status, ok := resp["Status"]; ok && status != "Success" {
		return fmt.Errorf("failed to perform diagnostic type %s: %s", diagnosticType, status)
	}
	return nil
}

func (c *Client) IORegistry(plane, entryName, entryClass string) (*DiagnosticsResponse, error) {
	req := &IORegistryRequest{
		Request:      Request{"IORegistry"},
		CurrentPlane: plane,
		EntryName:    entryName,
		EntryClass:   entryClass,
	}
	resp := &DiagnosticsResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) MobileGestalt(keys ...string) (*DiagnosticsResponse, error) {
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
	resp := &DiagnosticsResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) Goodbye() error {
	req := &Request{"Goodbye"}
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}
	if status, ok := resp["Status"]; ok && status != "Success" {
		return fmt.Errorf("failed to goodbye: %s", status)
	}
	return nil
}

func (c *Client) Sleep() error {
	req := &Request{"Sleep"}
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}
	if status, ok := resp["Status"]; ok && status != "Success" {
		return fmt.Errorf("failed to sleep: %s", status)
	}
	return nil
}

func (c *Client) Restart() error {
	req := &Request{"Restart"}
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}
	if status, ok := resp["Status"]; ok && status != "Success" {
		return fmt.Errorf("failed to restart: %s", status)
	}
	return nil
}

func (c *Client) Shutdown() error {
	req := &Request{"Shutdown2"}
	var resp Response
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}
	if status, ok := resp["Status"]; ok && status != "Success" {
		return fmt.Errorf("failed to shutdown: %s", status)
	}
	return nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
