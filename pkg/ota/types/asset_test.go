package types_test

import (
	"encoding/json"
	"testing"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/ota/types"
)

func TestRestoreVersionInfoIsSeedRemainsBool(t *testing.T) {
	var asset types.Asset
	asset.RestoreVersionInfo.IsSeed = true
	if !asset.RestoreVersionInfo.IsSeed {
		t.Fatal("RestoreVersionInfo.IsSeed must remain an assignable bool")
	}
}

func TestRestoreVersionInfoTracksIsSeedPresence(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantPresent bool
		wantSeed    bool
	}{
		{name: "missing", payload: `{}`, wantPresent: false, wantSeed: false},
		{name: "null", payload: `{"RestoreVersionInfo":{"IsSeed":null}}`, wantPresent: false, wantSeed: false},
		{name: "explicit false", payload: `{"RestoreVersionInfo":{"IsSeed":false}}`, wantPresent: true, wantSeed: false},
		{name: "explicit true", payload: `{"RestoreVersionInfo":{"IsSeed":true}}`, wantPresent: true, wantSeed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var asset types.Asset
			if err := json.Unmarshal([]byte(test.payload), &asset); err != nil {
				t.Fatalf("unmarshal asset: %v", err)
			}
			if got := asset.RestoreVersionInfo.IsSeedPresent(); got != test.wantPresent {
				t.Fatalf("IsSeedPresent() = %t, want %t", got, test.wantPresent)
			}
			if asset.RestoreVersionInfo.IsSeed != test.wantSeed {
				t.Fatalf("IsSeed = %t, want %t", asset.RestoreVersionInfo.IsSeed, test.wantSeed)
			}
		})
	}
}

func TestRestoreVersionInfoTracksPlistIsSeedPresence(t *testing.T) {
	payload, err := plist.Marshal(map[string]any{
		"RestoreVersionInfo": map[string]any{"IsSeed": false},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}
	var asset types.Asset
	if _, err := plist.Unmarshal(payload, &asset); err != nil {
		t.Fatalf("unmarshal plist: %v", err)
	}
	if !asset.RestoreVersionInfo.IsSeedPresent() || asset.RestoreVersionInfo.IsSeed {
		t.Fatalf("plist seed presence/value = %t/%t, want true/false",
			asset.RestoreVersionInfo.IsSeedPresent(), asset.RestoreVersionInfo.IsSeed)
	}
}
