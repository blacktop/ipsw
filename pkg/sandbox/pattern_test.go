package sandbox

import (
	"reflect"
	"testing"
)

func TestParseRSS(t *testing.T) {
	type args struct {
		dat     []byte
		globals []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "test_string",
			args: args{
				dat:     []byte{73, 47, 100, 101, 118, 47, 97, 101, 115, 95, 48, 15, 0, 15, 10},
				globals: []string{"HOME", "FRONT_USER_HOME", "PROCESS_TEMP_DIR", "ENTITLEMENT:com.apple.security.exception.nano-preference.read-write", "ANY_UUID", "ENTITLEMENT:com.apple.security.exception.nano-paired-storage.subpath.read-write", "ENTITLEMENT:com.apple.security.exception.nano-preference.read-only", "ENTITLEMENT:com.apple.security.exception.nano-paired-storage.subpath.read-only", "ENTITLEMENT:com.apple.security.ts.nano-paired-storage.subpath.read-only", "ENTITLEMENT:com.apple.security.ts.nano-paired-storage.subpath.read-write", "ENTITLEMENT:com.apple.security.ts.nano-preference.read-only", "ENTITLEMENT:com.apple.security.ts.nano-preference.read-write", "ENTITLEMENT:com.apple.security.ts.ipc-posix-sem", "ENTITLEMENT:com.apple.security.ts.ipc-posix-shm", "ENTITLEMENT:com.apple.security.ts.ipc-posix-shm.read-only", "ENTITLEMENT:com.apple.security.ts.tmpdir", "ENTITLEMENT:com.apple.security.ts.system-info", "ENTITLEMENT:com.apple.security.ts.nvram-read"},
			},
			want:    []string{"/dev/aes_0"},
			wantErr: false,
		},
		{
			name: "test_global",
			args: args{
				dat:     []byte{17, 15, 82, 47, 88, 99, 111, 100, 101, 66, 117, 105, 108, 116, 80, 114, 111, 100, 117, 99, 116, 115, 15, 64, 47, 128, 10, 0, 15, 10},
				globals: []string{"HOME", "FRONT_USER_HOME", "PROCESS_TEMP_DIR", "ENTITLEMENT:com.apple.security.exception.nano-preference.read-write", "ANY_UUID", "ENTITLEMENT:com.apple.security.exception.nano-paired-storage.subpath.read-write", "ENTITLEMENT:com.apple.security.exception.nano-preference.read-only", "ENTITLEMENT:com.apple.security.exception.nano-paired-storage.subpath.read-only", "ENTITLEMENT:com.apple.security.ts.nano-paired-storage.subpath.read-only", "ENTITLEMENT:com.apple.security.ts.nano-paired-storage.subpath.read-write", "ENTITLEMENT:com.apple.security.ts.nano-preference.read-only", "ENTITLEMENT:com.apple.security.ts.nano-preference.read-write", "ENTITLEMENT:com.apple.security.ts.ipc-posix-sem", "ENTITLEMENT:com.apple.security.ts.ipc-posix-shm", "ENTITLEMENT:com.apple.security.ts.ipc-posix-shm.read-only", "ENTITLEMENT:com.apple.security.ts.tmpdir", "ENTITLEMENT:com.apple.security.ts.system-info", "ENTITLEMENT:com.apple.security.ts.nvram-read"},
			},
			want:    []string{"${FRONT_USER_HOME}/XcodeBuiltProducts/", "${FRONT_USER_HOME}/XcodeBuiltProducts"},
			wantErr: false,
		},
		{
			name: "test_regex",
			args: args{
				dat:     []byte{3, 47, 15, 11, 1, 48, 255, 0, 46, 15, 2, 47, 15, 71, 83, 67, 95, 73, 110, 102, 111, 47, 15, 10},
				globals: []string{"HOME", "FRONT_USER_HOME", "PROCESS_TEMP_DIR", "ENTITLEMENT:com.apple.security.exception.nano-preference.read-write", "ANY_UUID", "ENTITLEMENT:com.apple.security.exception.nano-paired-storage.subpath.read-write", "ENTITLEMENT:com.apple.security.exception.nano-preference.read-only", "ENTITLEMENT:com.apple.security.exception.nano-paired-storage.subpath.read-only", "ENTITLEMENT:com.apple.security.ts.nano-paired-storage.subpath.read-only", "ENTITLEMENT:com.apple.security.ts.nano-paired-storage.subpath.read-write", "ENTITLEMENT:com.apple.security.ts.nano-preference.read-only", "ENTITLEMENT:com.apple.security.ts.nano-preference.read-write", "ENTITLEMENT:com.apple.security.ts.ipc-posix-sem", "ENTITLEMENT:com.apple.security.ts.ipc-posix-shm", "ENTITLEMENT:com.apple.security.ts.ipc-posix-shm.read-only", "ENTITLEMENT:com.apple.security.ts.tmpdir", "ENTITLEMENT:com.apple.security.ts.system-info", "ENTITLEMENT:com.apple.security.ts.nvram-read"},
			},
			want:    []string{"/[^/]+/SC_Info/"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRSS(tt.args.dat, tt.args.globals)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRSS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRSS() = %v, want %v", got, tt.want)
			}
		})
	}
}
