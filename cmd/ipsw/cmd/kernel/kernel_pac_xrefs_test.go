package kernel

import "testing"

func TestValidatePacXrefsFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{name: "jsonl", format: "jsonl", wantErr: false},
		{name: "uppercase", format: "JSONL", wantErr: false},
		{name: "padded", format: "  jsonl  ", wantErr: false},
		{name: "json", format: "json", wantErr: true},
		{name: "empty", format: "", wantErr: true},
		{name: "csv", format: "csv", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePacXrefsFormat(tt.format)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePacXrefsFormat(%q) err=%v, wantErr=%v", tt.format, err, tt.wantErr)
			}
		})
	}
}

func TestParseOptionalAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		wantAddr uint64
		wantSet  bool
		wantErr  bool
	}{
		{name: "empty", raw: "", wantAddr: 0, wantSet: false, wantErr: false},
		{name: "hex", raw: "0xfffffe0007123456", wantAddr: 0xfffffe0007123456, wantSet: true, wantErr: false},
		{name: "decimal", raw: "4096", wantAddr: 4096, wantSet: true, wantErr: false},
		{name: "padded hex", raw: "  0x10  ", wantAddr: 0x10, wantSet: true, wantErr: false},
		{name: "garbage", raw: "0xnothex", wantAddr: 0, wantSet: false, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			addr, set, err := parseOptionalAddr(tt.raw, "--func")
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseOptionalAddr(%q) err=%v, wantErr=%v", tt.raw, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if addr != tt.wantAddr || set != tt.wantSet {
				t.Fatalf("parseOptionalAddr(%q) = (%#x, %v), want (%#x, %v)", tt.raw, addr, set, tt.wantAddr, tt.wantSet)
			}
		})
	}
}
