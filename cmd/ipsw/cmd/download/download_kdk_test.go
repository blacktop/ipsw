package download

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestDownloadKDKNoninteractiveRequiresSelectorBeforeRequest(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previousInput := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = previousInput })
	for key, value := range map[string]any{
		"download.kdk.host": false, "download.kdk.build": "", "download.kdk.latest": false, "download.kdk.all": false,
	} {
		previous := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, previous) })
	}
	if err := downloadKdkCmd.RunE(downloadKdkCmd, nil); err == nil || !strings.Contains(err.Error(), "--host, --build, --latest, or --all") {
		t.Fatalf("expected local selector error, got %v", err)
	}
}
