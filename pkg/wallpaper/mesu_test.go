package wallpaper

import (
	"reflect"
	"testing"
)

func TestExtractThumbnailBytes(t *testing.T) {
	type args struct {
		url      string
		proxy    string
		insecure bool
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
				url:      "https://updates.cdn-apple.com/2022/mobileassets/012-19617/B488E2A1-B291-4E42-AD9A-7111CB03A2AB/com_apple_MobileAsset_Wallpaper/605957001046c16663cb44a4b4ba12c3bcc9281b.zip",
				proxy:    "",
				insecure: false,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractThumbnailBytes(tt.args.url, tt.args.proxy, tt.args.insecure)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractThumbnailBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractThumbnailBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
