package tss

import (
	"os"
	"reflect"
	"testing"

	"github.com/blacktop/ipsw/pkg/plist"
)

func TestPersonalize(t *testing.T) {
	type args struct {
		conf *PersonalConfig
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				conf: &PersonalConfig{
					PersonlID: map[string]any{
						"BoardId":      uint64(8),
						"ChipID":       uint64(33040),
						"UniqueChipID": uint64(6303405673529390),
						"ApNonce":      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					},
					BuildManifest: &plist.BuildManifest{},
				},
			},
			want:    []byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifestData, err := os.ReadFile("/private/tmp/iOS_DDI.dmg.mount/Restore/BuildManifest.plist")
			// manifestData, err := os.ReadFile("/Volumes/Xcode_iOS_DDI_Personalized/Restore/BuildManifest.plist")
			if err != nil {
				t.Errorf("failed to read BuildManifest.plist: %v", err)
			}
			bman, err := plist.ParseBuildManifest(manifestData)
			if err != nil {
				t.Errorf("failed to parse BuildManifest.plist: %v", err)
			}
			tt.args.conf.BuildManifest = bman
			got, err := Personalize(tt.args.conf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Personalize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Personalize() = %v, want %v", got, tt.want)
			}
		})
	}
}
