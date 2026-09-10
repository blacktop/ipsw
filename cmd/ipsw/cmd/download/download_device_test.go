package download

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gplist "github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/spf13/viper"
)

type ipswFeedTransport func(*http.Request) (*http.Response, error)

func (f ipswFeedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestUSBExtractionDevice(t *testing.T) {
	manifest := &plist.BuildManifest{
		ProductVersion: "99.0", ProductBuildVersion: "99A1",
		SupportedProductTypes: []string{"iPhone99,1", "iPhone99,2"},
	}
	for _, product := range manifest.SupportedProductTypes {
		manifest.BuildIdentities = append(manifest.BuildIdentities, plist.BuildIdentity{
			ApProductType: product,
			Manifest: map[string]plist.IdentityManifest{
				"Cryptex1,SystemOS": {Info: map[string]any{"Path": product + ".dmg"}},
			},
		})
	}
	data, err := gplist.Marshal(manifest, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("BuildManifest.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"synthetic-usb-selection"`)
		http.ServeContent(w, r, "synthetic.ipsw", time.Time{}, bytes.NewReader(archive.Bytes()))
	}))
	t.Cleanup(server.Close)

	feed := map[string]any{"MobileDeviceSoftwareVersionsByVersion": map[string]any{
		"99": map[string]any{"MobileDeviceSoftwareVersions": map[string]any{
			"iPhone99,2": map[string]any{"99A1": map[string]any{"Restore": map[string]string{
				"BuildVersion": "99A1", "ProductVersion": "99.0", "FirmwareURL": server.URL + "/synthetic.ipsw",
			}}},
		}},
	}}
	feedData, err := gplist.Marshal(feed, gplist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	oldClient, oldPick := http.DefaultClient, pickIPSWDevice
	t.Cleanup(func() { http.DefaultClient, pickIPSWDevice = oldClient, oldPick })
	http.DefaultClient = &http.Client{Transport: ipswFeedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "itunes.apple.com" {
			return nil, fmt.Errorf("unexpected feed request: %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(feedData)), Request: r}, nil
	})}
	pickIPSWDevice = func() (*lockdownd.DeviceValues, error) {
		return &lockdownd.DeviceValues{ProductType: "iPhone99,2", BuildVersion: "98A1"}, nil
	}

	for _, tc := range []struct {
		name, device, extractDevice, want string
	}{
		{"USB default", "", "", "iPhone99,2"},
		{"USB replaces feed device", "iPhone99,1", "", "iPhone99,2"},
		{"explicit extraction override", "", "iPhone99,1", "iPhone99,1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range map[string]any{
				"usb": true, "latest": true, "dyld": true, "kernel": false,
				"device": tc.device, "extract-device": tc.extractDevice,
				"version": "", "build": "", "macos": false, "ibridge": false,
				"show-latest-version": false, "show-latest-build": false, "urls": false,
				"fcs-keys": false, "fcs-keys-json": false, "dyld-arch": []string{},
				"white-list": []string{}, "black-list": []string{}, "pattern": "",
				"confirm": true, "proxy": "", "output": t.TempDir(),
			} {
				key = "download.ipsw." + key
				viper.Set(key, value)
				t.Cleanup(func() { viper.Set(key, nil) })
			}
			// The selected DMG is deliberately absent: reaching its lookup proves
			// the selector reached extraction without mounting or using a device.
			err := downloadIpswCmd.RunE(downloadIpswCmd, nil)
			if err == nil || !strings.Contains(err.Error(), "failed to extract "+tc.want+".dmg from remote IPSW: no files found matching") {
				t.Fatalf("expected extraction to select %s.dmg, got %v", tc.want, err)
			}
		})
	}
}

func TestExtractionDeviceDoesNotSelectFirmwareFeed(t *testing.T) {
	for key, value := range map[string]any{
		"extract-device": "Mac99,2", "device": "", "version": "", "build": "",
		"latest": false, "show-latest-version": false, "show-latest-build": false,
		"urls": false, "kernel": false, "dyld": false, "fcs-keys": false, "fcs-keys-json": false,
	} {
		key = "download.ipsw." + key
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, nil) })
	}
	if downloadIpswCmd.Flags().Lookup("extract-device") == nil {
		t.Fatal("missing extraction selector flag")
	}
	err := downloadIpswCmd.RunE(downloadIpswCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--extract-device requires") {
		t.Fatalf("unused selector accepted: %v", err)
	}
	for _, mode := range []string{"kernel", "dyld", "fcs-keys", "fcs-keys-json"} {
		viper.Set("download.ipsw."+mode, true)
		err := downloadIpswCmd.RunE(downloadIpswCmd, nil)
		viper.Set("download.ipsw."+mode, false)
		// No feed arguments: stop before networking. An extraction selector
		// must not satisfy the firmware feed's --device requirement.
		if err == nil || !strings.Contains(err.Error(), "you must also supply") {
			t.Fatalf("%s: extraction device changed feed validation: %v", mode, err)
		}
	}
}
