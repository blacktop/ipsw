package mount

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.mobile.mobile_image_mounter"
)

const (
	ImageTypeDeveloper = "Developer"
	ImageTypeCryptex   = "Cryptex"
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
		e.DiskImageType,
		e.DeviceType,
		e.DeviceNode,
		e.FilesystemType,
		e.MountPath,
		e.IsMounted,
		e.IsReadOnly,
		e.SupportsContentProtection,
	)
}

func (c *Client) ListImages() ([]ListImageEntryList, error) {
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
	Command               string `plist:"Command,omitempty"`
	ImageType             string `plist:"ImageType,omitempty"`
	ImageSize             int    `plist:"ImageSize,omitempty"`
	MountPath             string `plist:"MountPath,omitempty"`
	ImageSignature        []byte `plist:"ImageSignature,omitempty"`
	ImageTrustCache       []byte `plist:"ImageTrustCache,omitempty"`
	ImageInfoPlist        []byte `plist:"ImageInfoPlist,omitempty"`
	PersonalizedImageType string `plist:"PersonalizedImageType,omitempty"`
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
		if len(resp.DetailedError) > 0 {
			return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
		}
		return fmt.Errorf("%s", resp.Error)
	}

	if err := binary.Write(c.c.Conn(), binary.BigEndian, imageData); err != nil {
		return fmt.Errorf("failed to write image data: %s", err)
	}

	if err := c.c.Recv(resp); err != nil {
		return fmt.Errorf("failed to receive response: %s", err)
	}

	if resp.Status != "Complete" {
		if len(resp.DetailedError) > 0 {
			return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
		}
		return fmt.Errorf("%s", resp.Error)
	}

	return nil
}

func (c *Client) Mount(imageType string, signature []byte, trustCachePath, infoPlistPath string) error {
	if _, err := c.LookupImage(imageType); err == nil {
		return fmt.Errorf("image already mounted")
	}

	req := &MountRequest{
		Command:        "MountImage",
		ImageType:      imageType,
		ImageSignature: signature,
	}

	if trustCachePath != "" {
		trustCache, err := os.ReadFile(trustCachePath)
		if err != nil {
			return fmt.Errorf("failed to read trustcache %s: %v", trustCachePath, err)
		}
		req.ImageTrustCache = trustCache
	}
	if infoPlistPath != "" {
		infoPlist, err := os.ReadFile(infoPlistPath)
		if err != nil {
			return fmt.Errorf("failed to read info plist %s: %v", infoPlistPath, err)
		}
		req.ImageInfoPlist = infoPlist
	}

	resp := &MountResponse{}
	if err := c.c.Request(req, resp); err != nil {
		return err
	}

	if resp.Status != "Complete" {
		if len(resp.DetailedError) > 0 {
			return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
		}
		return fmt.Errorf("%s", resp.Error)
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
		if len(resp.DetailedError) > 0 {
			return fmt.Errorf("%s: %s", resp.Error, resp.DetailedError)
		}
		return fmt.Errorf("%s", resp.Error)
	}

	return nil
}

func (c *Client) DeveloperModeStatus() (bool, error) {
	req := &MountRequest{Command: "QueryDeveloperModeStatus"}
	var resp map[string]any
	if err := c.c.Request(req, &resp); err != nil {
		return false, err
	}

	status, ok := resp["DeveloperModeStatus"]
	if !ok {
		return false, fmt.Errorf("device does not support developer mode")
	}

	return status.(bool), nil
}

func (c *Client) Nonce(imageType string) (string, error) {
	req := &MountRequest{Command: "QueryNonce"}
	if len(imageType) > 0 {
		req.PersonalizedImageType = imageType
	}
	var resp map[string]any
	if err := c.c.Request(req, &resp); err != nil {
		return "", err
	}

	nonce, ok := resp["PersonalizationNonce"]
	if !ok {
		return "", fmt.Errorf("device does not support QueryNonce")
	}

	return hex.EncodeToString(nonce.([]byte)), nil
}

func (c *Client) PersonalizationIdentifiers(imageType string) (map[string]any, error) {
	req := &MountRequest{Command: "QueryPersonalizationIdentifiers"}
	if len(imageType) > 0 {
		req.PersonalizedImageType = imageType
	}
	var resp map[string]any
	if err := c.c.Request(req, &resp); err != nil {
		return nil, err
	}

	if err, ok := resp["Error"]; ok {
		if detail, ok := resp["DetailedError"]; ok {
			return nil, fmt.Errorf("%s: %s", err, detail)
		}
		return nil, fmt.Errorf("%s", err)
	}

	ids, ok := resp["PersonalizationIdentifiers"]
	if !ok {
		return nil, fmt.Errorf("device does not support QueryPersonalizationIdentifiers")
	}

	return ids.(map[string]any), nil
}

func (c *Client) PersonalizationManifest(imageType string, signature []byte) ([]byte, error) {
	var resp map[string]any
	if err := c.c.Request(&map[string]any{
		"Command":               "QueryPersonalizationManifest",
		"PersonalizedImageType": imageType,
		"ImageType":             imageType,
		"ImageSignature":        signature,
	}, &resp); err != nil {
		return nil, err
	}
	if err, ok := resp["Error"]; ok {
		if detail, ok := resp["DetailedError"]; ok {
			return nil, fmt.Errorf("%s: %s", err, detail)
		}
		return nil, fmt.Errorf("%s", err)
	}

	manifest, ok := resp["ImageSignature"]
	if !ok {
		return nil, fmt.Errorf("device does not support QueryPersonalizationManifest")
	}

	return manifest.([]byte), nil
}

func (c *Client) RollPersonalizationNonce() error {
	var resp map[string]any
	if err := c.c.Request(&map[string]any{
		"Command": "RollPersonalizationNonce",
	}, &resp); err != nil {
		return err
	}
	if err, ok := resp["Error"]; ok {
		return fmt.Errorf("failed to roll personalization nonce: %s", err)
	}
	return nil
}

func (c *Client) RollCryptexNonce() error {
	var resp map[string]any
	if err := c.c.Request(&map[string]any{
		"Command": "RollCryptexNonce",
	}, &resp); err != nil {
		return err
	}
	if err, ok := resp["Error"]; ok {
		return fmt.Errorf("failed to roll cryptex nonce: %s", err)
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
