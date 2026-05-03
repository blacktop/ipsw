package kernelcache

import "testing"

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
