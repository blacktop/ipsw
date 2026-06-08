package kernelcache

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSyscallArgumentsUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []string
		wantErr bool
	}{
		{
			name: "argument array",
			data: `["int fd","char *path"]`,
			want: []string{"int fd", "char *path"},
		},
		{
			name: "empty object",
			data: `{}`,
		},
		{
			name: "whitespace empty object",
			data: ` { } `,
		},
		{
			name:    "non-empty object",
			data:    `{"unexpected":true}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got syscallArguments
			err := json.Unmarshal([]byte(tt.data), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("json.Unmarshal(%s) error = nil, want error", tt.data)
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal(%s) error = %v", tt.data, err)
			}
			if !slices.Equal([]string(got), tt.want) {
				t.Fatalf("json.Unmarshal(%s) = %#v, want %#v", tt.data, got, tt.want)
			}
		})
	}
}

func TestSyscallsDataIncludesMacOS27IPSWSlots(t *testing.T) {
	scdata, err := getSyscallsData()
	if err != nil {
		t.Fatalf("getSyscallsData() error = %v", err)
	}

	bsdTests := []struct {
		number int
		name   string
		args   []string
	}{
		{148, "pipe2", []string{"int *fildes", "int flags"}},
		{149, "sys_dup3", []string{"u_int from", "u_int to", "int flags"}},
		{214, "fchflagsat", []string{"int fd", "char *path", "int flags", "int flag"}},
		{215, "getumask", []string{"void"}},
		{246, "aio_readv", []string{"user_addr_t aiocbp"}},
		{247, "aio_writev", []string{"user_addr_t aiocbp"}},
		{249, "fsctlat", []string{"int fd", "const char *path", "u_long cmd", "caddr_t data", "u_int options"}},
		{352, "guarded_ftruncate_np", []string{"int fd", "const guardid_t *guard", "off_t length"}},
	}

	for _, tt := range bsdTests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scdata.GetBsdSyscallByNumber(tt.number)
			if err != nil {
				t.Fatalf("GetBsdSyscallByNumber(%d) error = %v", tt.number, err)
			}
			if got.Name != tt.name {
				t.Fatalf("GetBsdSyscallByNumber(%d).Name = %q, want %q", tt.number, got.Name, tt.name)
			}
			if got.Old {
				t.Fatalf("GetBsdSyscallByNumber(%d).Old = true, want false", tt.number)
			}
			if !slices.Equal([]string(got.Arguments), tt.args) {
				t.Fatalf("GetBsdSyscallByNumber(%d).Arguments = %#v, want %#v", tt.number, got.Arguments, tt.args)
			}
		})
	}

	got, err := scdata.GetMachSyscallByNumber(108)
	if err != nil {
		t.Fatalf("GetMachSyscallByNumber(108) error = %v", err)
	}
	if got.Name != "thread_set_x86_64_compat" {
		t.Fatalf("GetMachSyscallByNumber(108).Name = %q, want %q", got.Name, "thread_set_x86_64_compat")
	}
	if !slices.Equal([]string(got.Arguments), []string{"uint32_t enable"}) {
		t.Fatalf("GetMachSyscallByNumber(108).Arguments = %#v, want %#v", got.Arguments, []string{"uint32_t enable"})
	}
}

func TestMaxBsdSyscallCount(t *testing.T) {
	scdata, err := getSyscallsData()
	if err != nil {
		t.Fatalf("getSyscallsData() error = %v", err)
	}

	if got, want := maxBsdSyscallCount(scdata.BsdSyscalls), 558; got != want {
		t.Fatalf("maxBsdSyscallCount() = %d, want %d", got, want)
	}

	if got := maxBsdSyscallCount(nil); got != 0 {
		t.Fatalf("maxBsdSyscallCount(nil) = %d, want 0", got)
	}
}

func TestShouldStopSysentScan(t *testing.T) {
	tests := []struct {
		name       string
		idx        int
		maxSyscall int
		sysent     sysent
		want       bool
	}{
		{
			name:       "known range does not stop",
			idx:        557,
			maxSyscall: 558,
			sysent:     sysent{Call: 0x1000, ReturnType: RET_NONE},
			want:       false,
		},
		{
			name:       "zero call after known max stops",
			idx:        558,
			maxSyscall: 558,
			sysent:     sysent{Call: 0, ReturnType: RET_NONE},
			want:       true,
		},
		{
			name:       "future nonzero entry remains detectable",
			idx:        558,
			maxSyscall: 558,
			sysent:     sysent{Call: 0x1000, ReturnType: RET_INT_T},
			want:       false,
		},
		{
			name:       "invalid return type stops",
			idx:        100,
			maxSyscall: 558,
			sysent:     sysent{Call: 0x1000, ReturnType: RET_UINT64_T + 1},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldStopSysentScan(tt.idx, tt.maxSyscall, tt.sysent); got != tt.want {
				t.Fatalf("shouldStopSysentScan() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMatchEnosysARM64(t *testing.T) {
	// mov w0, #0x4e ; ret
	plain := []byte{0xC0, 0x09, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x00, 0x00}
	// bti c ; mov w0, #0x4e ; ret
	bti := []byte{0x5F, 0x24, 0x03, 0xD5, 0xC0, 0x09, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}
	// pacibsp ; mov w0, #0x4e ; ret  (something else)
	pacib := []byte{0x7F, 0x23, 0x03, 0xD5, 0xC0, 0x09, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6}
	// mov w1, #0x4e ; ret  (wrong register)
	wrongReg := []byte{0xC1, 0x09, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x00, 0x00}
	// mov w0, #0x4f ; ret  (wrong errno)
	wrongErrno := []byte{0xE0, 0x09, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x00, 0x00}

	cases := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"plain mov+ret", plain, true},
		{"bti+mov+ret", bti, true},
		{"pacibsp prefix not matched", pacib, false},
		{"wrong register w1", wrongReg, false},
		{"wrong errno", wrongErrno, false},
		{"too short", plain[:7], false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchEnosysARM64(tc.buf); got != tc.want {
				t.Errorf("matchEnosysARM64(%x) = %v, want %v", tc.buf, got, tc.want)
			}
		})
	}
}

func TestMatchEnosysX86(t *testing.T) {
	// push rbp; mov rbp,rsp; mov eax,0x4e; pop rbp; ret
	plain := []byte{0x55, 0x48, 0x89, 0xE5, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0, 0, 0, 0}
	// endbr64 ; <plain>
	endbr := []byte{0xF3, 0x0F, 0x1E, 0xFA, 0x55, 0x48, 0x89, 0xE5, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x5D, 0xC3}
	// wrong errno (0x4F)
	wrongErrno := []byte{0x55, 0x48, 0x89, 0xE5, 0xB8, 0x4F, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0, 0, 0, 0}
	// missing pop rbp (replaced with nop)
	wrongEpilogue := []byte{0x55, 0x48, 0x89, 0xE5, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x90, 0xC3, 0, 0, 0, 0}

	cases := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"plain", plain, true},
		{"endbr64+plain", endbr, true},
		{"wrong errno", wrongErrno, false},
		{"wrong epilogue", wrongEpilogue, false},
		{"too short for plain", plain[:10], false},
		{"endbr but truncated body", endbr[:14], false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchEnosysX86(tc.buf); got != tc.want {
				t.Errorf("matchEnosysX86(%x) = %v, want %v", tc.buf, got, tc.want)
			}
		})
	}
}
