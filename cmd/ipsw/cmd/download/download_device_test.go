package download

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

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
