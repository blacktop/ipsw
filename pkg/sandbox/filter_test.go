package sandbox

import (
	_ "embed"
	"reflect"
	"testing"
)

func TestFilterInfo_GetArgument(t *testing.T) {
	type fields struct {
		ID         int
		Name       string
		Category   string
		Aliases    Aliases
		filterInfo filterInfo
	}
	type args struct {
		sb  *Sandbox
		id  uint16
		alt bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    any
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &FilterInfo{
				ID:         tt.fields.ID,
				Name:       tt.fields.Name,
				Category:   tt.fields.Category,
				Aliases:    tt.fields.Aliases,
				filterInfo: tt.fields.filterInfo,
			}
			got, err := f.GetArgument(tt.args.sb, tt.args.id, tt.args.alt)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilterInfo.GetArgument() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterInfo.GetArgument() = %v, want %v", got, tt.want)
			}
		})
	}
}
