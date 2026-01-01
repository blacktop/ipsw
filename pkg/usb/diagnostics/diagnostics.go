package diagnostics

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName    = "com.apple.mobile.diagnostics_relay"
	oldServiceName = "com.apple.iosdiagnostics.relay"
)

var colorHeader = colors.HiBlue().SprintFunc()
var colorFaint = colors.FaintHiBlue().SprintFunc()
var colorBold = colors.Bold().SprintFunc()

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

type Diagnostics struct {
	GasGauge struct {
		CycleCount         int    `plist:"CycleCount,omitempty" json:"cycle_count,omitempty"`
		DesignCapacity     int    `plist:"DesignCapacity,omitempty" json:"design_capacity,omitempty"`
		FullChargeCapacity int    `plist:"FullChargeCapacity,omitempty" json:"full_charge_capacity,omitempty"`
		Status             string `plist:"Status,omitempty" json:"status,omitempty"`
	} `plist:"GasGauge,omitempty" json:"gas_gauge"`
	HDMI struct {
		Connection string `plist:"Connection,omitempty" json:"connection,omitempty"`
		Status     string `plist:"Status,omitempty" json:"status,omitempty"`
	} `plist:"HDMI,omitempty" json:"hdmi"`
	NAND struct {
		Status string `plist:"Status,omitempty" json:"status,omitempty"`
	} `plist:"NAND,omitempty" json:"nand"`
	WiFi struct {
		Active string `plist:"Active,omitempty" json:"active,omitempty"`
		Status string `plist:"Status,omitempty" json:"status,omitempty"`
	} `plist:"WiFi,omitempty" json:"wifi"`
}

func (d Diagnostics) String() string {
	return fmt.Sprintf(
		colorHeader("[DIAGNOSTICS]\n")+
			colorHeader("  GasGauge:\n")+
			colorFaint("    CycleCount:         ")+colorBold("%d\n")+
			colorFaint("    DesignCapacity:     ")+colorBold("%d\n")+
			colorFaint("    FullChargeCapacity: ")+colorBold("%d\n")+
			colorFaint("    Status:             ")+colorBold("%s\n")+
			colorHeader("  HDMI:\n")+
			colorFaint("    Connection: ")+colorBold("%s\n")+
			colorFaint("    Status:     ")+colorBold("%s\n")+
			colorHeader("  NAND:\n")+
			colorFaint("    Status: ")+colorBold("%s\n")+
			colorHeader("  WiFi:\n")+
			colorFaint("    Active: ")+colorBold("%s\n")+
			colorFaint("    Status: ")+colorBold("%s\n"),
		d.GasGauge.CycleCount,
		d.GasGauge.DesignCapacity,
		d.GasGauge.FullChargeCapacity,
		d.GasGauge.Status,
		d.HDMI.Connection,
		d.HDMI.Status,
		d.NAND.Status,
		d.WiFi.Active,
		d.WiFi.Status,
	)
}

type infoResponse struct {
	Diagnostics Diagnostics `plist:"Diagnostics,omitempty" json:"diagnostics"`
	Status      string      `plist:"Status,omitempty" json:"status,omitempty"`
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

func (c *Client) Info() (*Diagnostics, error) {
	req := &Request{"All"}
	var resp infoResponse
	if err := c.c.Request(req, &resp); err != nil {
		return nil, err
	}
	if resp.Status != "Success" {
		return nil, fmt.Errorf("failed to restart: %s", resp.Status)
	}
	return &resp.Diagnostics, nil
}

func (c *Client) Battery() (map[string]any, error) {
	bat, err := c.IORegistry("", "", "IOPMPowerSource")
	if err != nil {
		return nil, err
	}
	if bat.Status != "Success" {
		return nil, fmt.Errorf("failed to get battery info: %s", bat.Status)
	}
	return bat.Diagnostics, nil
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
	req := &Request{"Shutdown"}
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
