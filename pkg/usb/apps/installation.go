package apps

import (
	"fmt"
	"os"
	"path"

	"github.com/mitchellh/mapstructure"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/afc"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.mobile.installation_proxy"
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

func (c *Client) Lookup() (map[string]*AppBundle, error) {
	req := &Lookup{
		Command: NewCommand("Lookup"),
	}
	resp := &LookupResult{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp.LookupResult, nil
}

func (c *Client) LookupRaw(keys ...string) (map[string]any, error) {
	req := &Lookup{
		Command: NewCommand("Lookup", keys...),
	}
	resp := &struct {
		LookupResult map[string]any
	}{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp.LookupResult, nil
}

func (c *Client) LookupExePath(bundleId string) (string, error) {
	apps, err := c.LookupRaw("CFBundleExecutable", "Path")
	if err != nil {
		return "", err
	}
	if d, ok := apps[bundleId]; ok {
		values := d.(map[string]any)
		exePath := values["Path"].(string) + "/" + values["CFBundleExecutable"].(string)
		return exePath, nil
	}
	return "", nil
}

func (c *Client) LookupDisplayName(bundleId string) (string, error) {
	apps, err := c.LookupRaw("CFBundleDisplayName")
	if err != nil {
		return "", err
	}
	if d, ok := apps[bundleId]; ok {
		values := d.(map[string]any)
		return values["CFBundleDisplayName"].(string), nil
	}
	return "", nil
}

func (c *Client) LookupContainer(bundleId string) (string, error) {
	apps, err := c.LookupRaw("Container")
	if err != nil {
		return "", err
	}

	if val, ok := apps[bundleId]; ok {
		values := val.(map[string]any)
		if container, ok := values["Container"].(string); ok {
			return container, nil
		}
	}

	return "", nil
}

type AppInfo struct {
	ApplicationDSID              int
	ApplicationType              string
	CFBundleDisplayName          string
	CFBundleExecutable           string
	CFBundleIdentifier           string
	CFBundleName                 string
	CFBundleShortVersionString   string
	CFBundleVersion              string
	Container                    string
	Entitlements                 map[string]any
	EnvironmentVariables         map[string]any
	MinimumOSVersion             string
	Path                         string
	ProfileValidated             bool
	SBAppTags                    []string
	SignerIdentity               string
	UIDeviceFamily               []int
	UIRequiredDeviceCapabilities []string
}

func (i AppInfo) String() string {
	return fmt.Sprintf("%s\t%s\t(%s)\t%s", i.CFBundleDisplayName, i.CFBundleShortVersionString, i.CFBundleIdentifier, i.Path)
}

func (c *Client) InstalledApps() ([]AppInfo, error) {
	apps, err := c.LookupRaw(
		"ApplicationDSID",
		"ApplicationType",
		"CFBundleDisplayName",
		"CFBundleExecutable",
		"CFBundleIdentifier",
		"CFBundleName",
		"CFBundleShortVersionString",
		"CFBundleVersion",
		"Container",
		"Entitlements",
		"EnvironmentVariables",
		"MinimumOSVersion",
		"Path",
		"ProfileValidated",
		"SBAppTags",
		"SignerIdentity",
		"UIDeviceFamily",
		"UIRequiredDeviceCapabilities",
	)
	if err != nil {
		return nil, err
	}

	result := make([]AppInfo, len(apps))

	var app AppInfo
	if err := mapstructure.Decode(apps, &app); err != nil {
		return nil, err
	}

	for _, a := range apps {
		var app AppInfo
		if err := mapstructure.Decode(a, &app); err != nil {
			return nil, err
		}
		result = append(result, app)
	}

	return result, nil
}

func (c *Client) Browse() (any, error) {
	req := &Browse{
		Command: NewCommand("Browse"),
	}
	resp := map[string]any{}
	if err := c.c.Request(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type ProgressFunc func(*ProgressEvent)

func (c *Client) watchProgress(cb ProgressFunc) error {
	for {
		ev := &ProgressEvent{}
		if err := c.c.Recv(ev); err != nil {
			return err
		}
		if ev.Status == "Complete" {
			ev.PercentComplete = 100
		}
		if cb != nil {
			cb(ev)
		}
		if ev.Status == "Complete" {
			return nil
		}
	}
}

func (c *Client) installOrUpgrade(cmd, packagePath string, progressCb ProgressFunc) error {
	req := &InstallOrUpgradeRequest{
		Command:     NewCommand(cmd),
		PackagePath: packagePath,
	}
	if err := c.c.Send(req); err != nil {
		return err
	}
	return c.watchProgress(progressCb)
}

func (c *Client) Install(packagePath string, progressCb ProgressFunc) error {
	return c.installOrUpgrade("Install", packagePath, progressCb)
}

func (c *Client) Upgrade(packagePath string, progressCb ProgressFunc) error {
	return c.installOrUpgrade("Upgrade", packagePath, progressCb)
}

func (c *Client) commandForBundle(cmd, bundleId string, progressCb ProgressFunc) error {
	req := &ApplicationIdentifierRequest{
		Command:               NewCommand(cmd),
		ApplicationIdentifier: bundleId,
	}
	if err := c.c.Send(req); err != nil {
		return err
	}
	return c.watchProgress(progressCb)
}

func (c *Client) Uninstall(bundleId string, progressCb ProgressFunc) error {
	return c.commandForBundle("Uninstall", bundleId, progressCb)
}

func (c *Client) Archive(bundleId string, progressCb ProgressFunc) error {
	return c.commandForBundle("Archive", bundleId, progressCb)
}

func (c *Client) RestoreArchive(bundleId string, progressCb ProgressFunc) error {
	return c.commandForBundle("RestoreArchive", bundleId, progressCb)
}

func (c *Client) RemoveArchive(bundleId string, progressCb ProgressFunc) error {
	return c.commandForBundle("RemoveArchive", bundleId, progressCb)
}

func (c *Client) LookupArchives() error {
	req := &LookupArchivesRequest{
		Command: NewCommand("LookupArchives"),
	}
	_ = req
	return nil
}

func (c *Client) CopyAndInstall(pkgPath string, progressCb ProgressFunc) error {
	afcClient, err := afc.NewClient(c.c.UDID())
	if err != nil {
		return err
	}
	defer afcClient.Close()

	if err := afcClient.CopyToDevice("/", pkgPath, func(dst, src string, info os.FileInfo) {
		fmt.Println(src, "->", dst)
	}); err != nil {
		return err
	}
	return c.Install(path.Join("/", path.Base(pkgPath)), progressCb)
}

func (c *Client) Close() error {
	return c.c.Close()
}
