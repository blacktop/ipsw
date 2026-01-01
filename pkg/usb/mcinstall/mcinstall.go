package mcinstall

import (
	"fmt"
	"os"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.mobile.MCInstall"
)

var colorHeader = colors.HiBlue().SprintFunc()
var colorFaint = colors.FaintHiBlue().SprintFunc()
var colorBold = colors.Bold().SprintFunc()

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

type ProfileInfo struct {
	profileSendResponse
	IDs       []string                   `plist:"OrderedIdentifiers,omitempty" json:"ids,omitempty"`
	Manifests map[string]ProfileManifest `plist:"ProfileManifest,omitempty" json:"manifests,omitempty"`
	Metadatas map[string]ProfileMetadata `plist:"ProfileMetadata,omitempty" json:"metadatas,omitempty"`
	Status    string                     `plist:"Status,omitempty" json:"status,omitempty"`
}

func (p ProfileInfo) String() string {
	var out string
	for _, id := range p.IDs {
		out += fmt.Sprintf(colorHeader("[ %s ]\n"), id)
		out += colorHeader("  Manifest:\n")
		out += fmt.Sprintf(colorFaint("    Description: ")+colorBold("%s\n"), p.Manifests[id].Description)
		out += fmt.Sprintf(colorFaint("    Active:      ")+colorBold("%t\n"), p.Manifests[id].IsActive)
		out += colorHeader("  Metadata:\n")
		out += fmt.Sprintf(colorFaint("    UUID:              ")+colorBold("%s\n"), p.Metadatas[id].UUID)
		out += fmt.Sprintf(colorFaint("    Version:           ")+colorBold("%d\n"), p.Metadatas[id].Version)
		out += fmt.Sprintf(colorFaint("    Name:              ")+colorBold("%s\n"), p.Metadatas[id].Name)
		out += fmt.Sprintf(colorFaint("    Description:       ")+colorBold("%s\n"), p.Metadatas[id].Description)
		out += fmt.Sprintf(colorFaint("    Organization:      ")+colorBold("%s\n"), p.Metadatas[id].Organization)
		out += fmt.Sprintf(colorFaint("    RemovalDisallowed: ")+colorBold("%t\n"), p.Metadatas[id].RemovalDisallowed)
	}
	return out
}

type ProfileMetadata struct {
	Description       string `plist:"PayloadDescription,omitempty" json:"desc,omitempty"`
	Name              string `plist:"PayloadDisplayName,omitempty" json:"name,omitempty"`
	Organization      string `plist:"PayloadOrganization,omitempty" json:"org,omitempty"`
	RemovalDisallowed bool   `plist:"PayloadRemovalDisallowed,omitempty" json:"removal_disallowed,omitempty"`
	UUID              string `plist:"PayloadUUID,omitempty" json:"uuid,omitempty"`
	Version           int    `plist:"PayloadVersion,omitempty" json:"version,omitempty"`
}

type ProfileManifest struct {
	Description string `plist:"Description,omitempty" json:"desc,omitempty"`
	IsActive    bool   `plist:"IsActive,omitempty" json:"active,omitempty"`
}

type profileSendResponse struct {
	CommandErrorArchive []byte `plist:"CommandErrorArchive,omitempty" json:"command_error_archive,omitempty"`
	ErrorChain          []struct {
		ErrorCode            int    `plist:"ErrorCode,omitempty" json:"error_code,omitempty"`
		ErrorDomain          string `plist:"ErrorDomain,omitempty" json:"error_domain,omitempty"`
		LocalizedDescription string `plist:"LocalizedDescription,omitempty" json:"localized_description,omitempty"`
		USEnglishDescription string `plist:"USEnglishDescription,omitempty" json:"us_english_description,omitempty"`
	} `plist:"ErrorChain,omitempty" json:"error_chain,omitempty"`
	Status string `plist:"Status,omitempty" json:"status,omitempty"`
}

type profileRemoveRequest struct {
	PayloadType       string `plist:"PayloadType,omitempty"`
	PayloadIdentifier string `plist:"PayloadIdentifier,omitempty"`
	PayloadUUID       string `plist:"PayloadUUID,omitempty"`
	PayloadVersion    int    `plist:"PayloadVersion,omitempty"`
}

func (c *Client) Install(profilePath string) error {
	dat, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %s", err)
	}

	var resp profileSendResponse
	if err := c.c.Request(&map[string]any{
		"RequestType": "InstallProfile",
		"Payload":     dat,
	}, &resp); err != nil {
		return err
	}

	if resp.Status != "Acknowledged" {
		return fmt.Errorf("failed to get cloud config: %#v", resp.ErrorChain)
	}

	return nil
}

func (c *Client) Upload(profilePath string) error { // FIXME: I'm not sure what this is for, but fails if I use it like Install
	dat, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %s", err)
	}

	var resp map[string]any
	if err := c.c.Request(&map[string]any{
		"RequestType": "StoreProfile",
		"ProfileData": dat,
		"Purpose":     "PostSetupInstallation",
	}, &resp); err != nil {
		return err
	}

	if status, ok := resp["Status"]; !ok || status != "Acknowledged" {
		return fmt.Errorf("failed to get cloud config: resp = %#v", resp)
	}

	return nil
}

func (c *Client) Remove(identifier string) error {
	profiles, err := c.List()
	if err != nil {
		return err
	}
	for id, meta := range profiles.Metadatas {
		if identifier == id {
			dat, err := plist.Marshal(profileRemoveRequest{
				PayloadType:       "Configuration",
				PayloadIdentifier: id,
				PayloadUUID:       meta.UUID,
				PayloadVersion:    meta.Version,
			}, plist.XMLFormat)
			if err != nil {
				return err
			}

			var resp map[string]any
			if err := c.c.Request(&map[string]any{
				"RequestType":       "RemoveProfile",
				"ProfileIdentifier": dat,
			}, &resp); err != nil {
				return err
			}

			if status, ok := resp["Status"]; !ok || status != "Acknowledged" {
				return fmt.Errorf("failed to get cloud config: resp=%#v", resp)
			}

			return nil
		}
	}

	return fmt.Errorf("profile %s not found", identifier)
}

func (c *Client) List() (*ProfileInfo, error) {
	var resp ProfileInfo

	if err := c.c.Request(&map[string]any{
		"RequestType": "GetProfileList",
	}, &resp); err != nil {
		return nil, err
	}

	if resp.Status != "Acknowledged" {
		return nil, fmt.Errorf("failed to list profiles: resp=%#v", resp)
	}

	return &resp, nil
}

type CloudConfiguration struct {
	AllowPairing                 bool `plist:"AllowPairing,omitempty" json:"allow_pairing,omitempty"`
	CloudConfigurationUIComplete bool `plist:"CloudConfigurationUIComplete,omitempty" json:"cloud_conf_ui_complete,omitempty"`
	ConfigurationSource          int  `plist:"ConfigurationSource,omitempty" json:"conf_source"`
	ConfigurationWasApplied      bool `plist:"ConfigurationWasApplied,omitempty" json:"conf_was_applied,omitempty"`
	IsSupervised                 bool `plist:"IsSupervised,omitempty" json:"is_supervised,omitempty"`
	PostSetupProfileWasInstalled bool `plist:"PostSetupProfileWasInstalled,omitempty" json:"post_setup_profile_was_installed,omitempty"`
}

func (cc *CloudConfiguration) String() string {
	return fmt.Sprintf(
		colorFaint("CloudConfiguration:           ")+colorBold("%t\n")+
			colorFaint("CloudConfigurationUIComplete: ")+colorBold("%t\n")+
			colorFaint("ConfigurationSource:          ")+colorBold("%d\n")+
			colorFaint("ConfigurationWasApplied:      ")+colorBold("%t\n")+
			colorFaint("IsSupervised:                 ")+colorBold("%t\n")+
			colorFaint("PostSetupProfileWasInstalled: ")+colorBold("%t\n"),
		cc.AllowPairing,
		cc.CloudConfigurationUIComplete,
		cc.ConfigurationSource,
		cc.ConfigurationWasApplied,
		cc.IsSupervised,
		cc.PostSetupProfileWasInstalled,
	)
}

type cloudConfigurationResponse struct {
	CloudConfiguration CloudConfiguration `plist:"CloudConfiguration,omitempty" json:"cloud_conf"`
	Status             string             `plist:"Status,omitempty" json:"status,omitempty"`
}

func (c *Client) GetCloudConfig() (*CloudConfiguration, error) {
	var resp cloudConfigurationResponse

	if err := c.c.Request(&map[string]any{
		"RequestType": "GetCloudConfiguration",
	}, &resp); err != nil {
		return nil, err
	}

	if resp.Status != "Acknowledged" {
		return nil, fmt.Errorf("failed to get cloud config: resp=%#v", resp)
	}

	return &resp.CloudConfiguration, nil
}

func (c *Client) SetWifiPowerState(turnON bool) error {
	var resp map[string]any

	if err := c.c.Request(&map[string]any{
		"RequestType": "SetWiFiPowerState",
		"PowerState":  turnON,
	}, &resp); err != nil {
		return err
	}

	if status, ok := resp["Status"]; !ok || status != "Acknowledged" {
		return fmt.Errorf("failed to get cloud config: resp=%#v", resp)
	}

	return nil
}
