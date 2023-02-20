//go:build darwin

package swift

import (
	"testing"
)

func TestDemangle(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "test1", args: args{input: "_TtC9BlastDoor12EncoderUtils"}, want: "BlastDoor.EncoderUtils", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Demangle(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Demangle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Demangle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDemangleSimple(t *testing.T) {
	type args struct {
		input string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "test1", args: args{input: "_TtC9BlastDoor16SandboxExtension"}, want: "SandboxExtension", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DemangleSimple(tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DemangleSimple() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DemangleSimple() = %v, want %v", got, tt.want)
			}
		})
	}
}
