package mount

import (
	"encoding/binary"
	"encoding/hex"
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

type LookupImageRequest struct {
	Command   string `plist:"Command,omitempty"`
	ImageType string `plist:"ImageType,omitempty"`
}

type LookupImageResponse struct {
	Status         string   `plist:"Status,omitempty" json:"status,omitempty"`
	ImageSignature [][]byte `plist:"ImageSignature,omitempty" json:"image_signature,omitempty"`
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

type ListImageResponse struct {
	Status    string               `plist:"Status,omitempty" json:"status,omitempty"`
	EntryList []ListImageEntryList `plist:"EntryList,omitempty" json:"entry_list,omitempty"`
}

type ListImageEntryList struct {
	BackingImage              string `plist:"BackingImage,omitempty" json:"backing_image,omitempty"`
	ImageSignature            []byte `plist:"ImageSignature,omitempty" json:"image_signature,omitempty"`
	IsMounted                 bool   `plist:"IsMounted,omitempty" json:"is_mounted,omitempty"`
	IsReadOnly                bool   `plist:"IsReadOnly,omitempty" json:"is_read_only,omitempty"`
	MountPath                 string `plist:"MountPath,omitempty" json:"mount_path,omitempty"`
	SupportsContentProtection bool   `plist:"SupportsContentProtection,omitempty" json:"supports_content_protection,omitempty"`
	DeviceNode                string `plist:"DeviceNode,omitempty" json:"device_node,omitempty"`
	DeviceType                string `plist:"DeviceType,omitempty" json:"device_type,omitempty"`
	DiskImageType             string `plist:"DiskImageType,omitempty" json:"disk_image_type,omitempty"`
	FilesystemType            string `plist:"FilesystemType,omitempty" json:"filesystem_type,omitempty"`
}

func (e ListImageEntryList) String() string {
	return fmt.Sprintf(
		"BackingImage:              %s\n"+
			"ImageSignature:            %s\n"+
			"DiskImageType:             %s\n"+
			"DeviceType:                %s\n"+
			"DeviceNode:                %s\n"+
			"FilesystemType:            %s\n"+
			"MountPath:                 %s\n"+
			"IsMounted:                 %t\n"+
			"IsReadOnly:                %t\n"+
			"SupportsContentProtection: %t\n",
		e.BackingImage,
		hex.EncodeToString(e.ImageSignature),
		e.DeviceNode,
		e.DeviceType,
		e.DiskImageType,
		e.FilesystemType,
		e.MountPath,
		e.IsMounted,
		e.IsReadOnly,
		e.SupportsContentProtection,
	)
}

func (c *Client) ListImages(imageType string) ([]ListImageEntryList, error) {
	req := &LookupImageRequest{Command: "CopyDevices"}
	resp := &ListImageResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp.EntryList, nil
}

func (c *Client) LookupImage(imageType string) (*LookupImageResponse, error) {
	req := &LookupImageRequest{
		Command:   "LookupImage",
		ImageType: imageType,
	}
	resp := &LookupImageResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}

	if len(resp.ImageSignature) == 0 {
		return nil, fmt.Errorf("no image found")
	}

	return resp, nil
}

type MountRequest struct {
	Command        string `plist:"Command,omitempty"`
	ImageType      string `plist:"ImageType,omitempty"`
	ImageSize      int    `plist:"ImageSize,omitempty"`
	MountPath      string `plist:"MountPath,omitempty"`
	ImageSignature []byte `plist:"ImageSignature,omitempty"`
}

type MountResponse struct {
	Status        string `plist:"Status,omitempty" json:"status,omitempty"`
	DetailedError string `plist:"DetailedError,omitempty" json:"detailed_error,omitempty"`
	Error         string `plist:"Error,omitempty" json:"error,omitempty"`
}

func (c *Client) Upload(imageType string, imageData []byte, signature []byte) error {
	if _, err := c.LookupImage(imageType); err == nil {
		return fmt.Errorf("image already mounted")
	}

	req := &MountRequest{
		Command:        "ReceiveBytes",
		ImageType:      imageType,
		ImageSize:      len(imageData),
		ImageSignature: signature,
	}
	resp := &MountResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return err
	}

	if resp.Status != "ReceiveBytesAck" {
		return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
	}

	if err := binary.Write(c.c.Conn(), binary.BigEndian, imageData); err != nil {
		return fmt.Errorf("failed to write image data: %s", err)
	}

	if err := c.c.Recv(resp); err != nil {
		return fmt.Errorf("failed to receive response: %s", err)
	}

	if resp.Status != "Complete" {
		return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
	}

	return nil
}

func (c *Client) Mount(imageType string, signature []byte) error {
	if _, err := c.LookupImage(imageType); err == nil {
		return fmt.Errorf("image already mounted")
	}

	req := &MountRequest{
		Command:        "MountImage",
		ImageType:      imageType,
		ImageSignature: signature,
	}
	resp := &MountResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return err
	}

	if resp.Status != "Complete" {
		return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
	}

	return nil
}

func (c *Client) Unmount(imageType, mountPath string, signature []byte) error {
	req := &MountRequest{
		Command:        "UnmountImage",
		ImageType:      imageType,
		MountPath:      mountPath,
		ImageSignature: signature,
	}
	resp := &MountResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return err
	}

	if resp.Status != "Complete" {
		return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
	}

	return nil
}

type HangupResponse struct {
	Goodbye bool `plist:"Goodbye,omitempty" json:"goodbye,omitempty"`
}

func (c *Client) Hangup() (bool, error) {
	req := &LookupImageRequest{Command: "Hangup"}
	resp := &HangupResponse{}
	if err := c.c.Request(req, &resp); err != nil {
		return false, err
	}
	return resp.Goodbye, nil
}

func (c *Client) Close() error {
	c.Hangup()
	return c.c.Close()
}
