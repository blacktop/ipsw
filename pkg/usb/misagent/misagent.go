package misagent

import (
	"fmt"
	"os"
	"time"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.misagent"
)

type provisionInstallRequest struct {
	MessageType string `plist:"MessageType,omitempty"`
	ProfileType string `plist:"ProfileType,omitempty"`
	Profile     []byte `plist:"Profile,omitempty"`
}

type provisionRemoveRequest struct {
	MessageType string `plist:"MessageType,omitempty"`
	ProfileID   string `plist:"ProfileID,omitempty"`
	ProfileType string `plist:"ProfileType,omitempty"`
}

type provisionListRequest struct {
	MessageType string `plist:"MessageType,omitempty"`
	ProfileType string `plist:"ProfileType,omitempty"`
}

type provisionResponse struct {
	MessageType string   `plist:"MessageType,omitempty"`
	Payloads    [][]byte `plist:"Payload,omitempty"`
	Status      int      `plist:"Status,omitempty"`
}

type provisionProfile struct {
	AppIDName                   string         `plist:"AppIDName,omitempty" json:"appid_name,omitempty"`
	ApplicationIdentifierPrefix []string       `plist:"ApplicationIdentifierPrefix,omitempty" json:"application_identifier_prefix,omitempty"`
	CreationDate                time.Time      `plist:"CreationDate,omitempty" json:"creation_date"`
	DerEncodedProfile           []byte         `plist:"DER-Encoded-Profile,omitempty" json:"der_encoded_profile,omitempty"`
	DeveloperCertificates       [][]byte       `plist:"DeveloperCertificates,omitempty" json:"developer_certificates,omitempty"`
	Entitlements                map[string]any `plist:"Entitlements,omitempty" json:"entitlements,omitempty"`
	ExpirationDate              time.Time      `plist:"ExpirationDate,omitempty" json:"expiration_date"`
	IsXcodeManaged              bool           `plist:"IsXcodeManaged,omitempty" json:"is_xcode_managed,omitempty"`
	Name                        string         `plist:"Name,omitempty" json:"name,omitempty"`
	Platform                    []string       `plist:"Platform,omitempty" json:"platform,omitempty"`
	ProvisionedDevices          []string       `plist:"ProvisionedDevices,omitempty" json:"provisioned_devices,omitempty"`
	TeamIdentifier              []string       `plist:"TeamIdentifier,omitempty" json:"team_identifier,omitempty"`
	TeamName                    string         `plist:"TeamName,omitempty" json:"team_name,omitempty"`
	TimeToLive                  int            `plist:"TimeToLive,omitempty" json:"time_to_live,omitempty"`
	UUID                        string         `plist:"UUID,omitempty" json:"uuid,omitempty"`
	Version                     int            `plist:"Version,omitempty" json:"version,omitempty"`
	Data                        []byte
}

func (pp provisionProfile) Bytes() []byte {
	return pp.Data
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

func (c *Client) Close() error {
	return c.c.Close()
}

func (c *Client) Install(profilePath string) error {
	dat, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile %s: %w", profilePath, err)
	}
	req := &provisionInstallRequest{
		MessageType: "Install",
		ProfileType: "Provisioning",
		Profile:     dat,
	}
	var resp provisionResponse
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}

	if resp.Status != 0 {
		return fmt.Errorf("failed to install profile %s: resp=%#v", profilePath, resp)
	}

	return nil
}

func (c *Client) Remove(profileID string) error {
	req := &provisionRemoveRequest{
		MessageType: "Remove",
		ProfileType: "Provisioning",
		ProfileID:   profileID,
	}
	var resp provisionResponse
	if err := c.c.Request(req, &resp); err != nil {
		return err
	}

	if resp.Status != 0 {
		return fmt.Errorf("failed to remove profile ID %s: resp=%#v", profileID, resp)
	}

	return nil
}

func (c *Client) List() ([]provisionProfile, error) {
	req := &provisionListRequest{
		MessageType: "CopyAll",
		ProfileType: "Provisioning",
	}
	var resp provisionResponse
	if err := c.c.Request(req, &resp); err != nil {
		return nil, err
	}

	if resp.Status != 0 {
		return nil, fmt.Errorf("failed to list profiles: resp=%#v", resp)
	}

	var prof provisionProfile
	var profs []provisionProfile

	for _, p := range resp.Payloads {
		if fmt, err := plist.Unmarshal(p[62:], &prof); err != nil {
			println(fmt)
			return nil, err
		}
		prof.Data = p
		profs = append(profs, prof)
	}

	return profs, nil
}
