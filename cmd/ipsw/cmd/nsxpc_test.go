package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestNSXPCRejectsNonJSONLFormat(t *testing.T) {
	viperKey := "nsxpc.format"
	t.Setenv("IPSW_NO_UPDATE_CHECK", "1")
	old := viper.GetString(viperKey)
	t.Cleanup(func() { viper.Set(viperKey, old) })
	viper.Set(viperKey, "json")

	err := nsxpcCmd.RunE(nsxpcCmd, []string{"dyld_shared_cache_arm64e"})
	if err == nil || !strings.Contains(err.Error(), `only "jsonl" is supported`) {
		t.Fatalf("err=%v", err)
	}
}
