package disass

import (
	"bytes"
	"encoding/binary"
	"maps"
	"testing"
)

func movz(rd, hw, imm uint32) uint32 { return 0xd2800000 | hw<<21 | imm<<5 | rd }
func movk(rd, hw, imm uint32) uint32 { return 0xf2800000 | hw<<21 | imm<<5 | rd }

const nop = 0xd503201f

// smallStringCode builds "hello" as a Swift small string: its bytes in x0 and
// the ASCII discriminator (0xE0) with count 5 in the top byte of x1, followed
// by a NOP that ends the sequence.
func smallStringCode() []byte {
	var code []byte
	for _, w := range []uint32{
		movz(0, 0, 0x6568), // "he"
		movk(0, 1, 0x6c6c), // "ll"
		movk(0, 2, 0x006f), // "o"
		movz(1, 0, 0),
		movk(1, 3, 0xe500),
		nop,
	} {
		code = binary.LittleEndian.AppendUint32(code, w)
	}
	return code
}

func findSwiftStrings(t *testing.T, code []byte) map[uint64]string {
	t.Helper()
	d := NewMachoDisass(nil, &Config{Data: code, StartAddress: 0x1000})
	out, err := d.FindSwiftStrings()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFindSwiftStringsSmallString(t *testing.T) {
	want := map[uint64]string{0x1000: "hello"}
	if got := findSwiftStrings(t, smallStringCode()); !maps.Equal(got, want) {
		t.Fatalf("FindSwiftStrings = %v, want %v", got, want)
	}
}

func TestFindSwiftStringsIgnoresTrailingBytes(t *testing.T) {
	want := findSwiftStrings(t, smallStringCode())
	for extra := 1; extra <= 3; extra++ {
		code := append(smallStringCode(), make([]byte, extra)...)
		if got := findSwiftStrings(t, code); !maps.Equal(got, want) {
			t.Errorf("with %d trailing bytes: FindSwiftStrings = %v, want %v", extra, got, want)
		}
	}
	// Without its terminating NOP the string is still pending; a partial word
	// must not be decoded as the instruction that ends it.
	pending := smallStringCode()[:5*4]
	for extra := 1; extra <= 3; extra++ {
		code := append(bytes.Clone(pending), make([]byte, extra)...)
		if got := findSwiftStrings(t, code); len(got) != 0 {
			t.Errorf("a %d-byte partial word ended a pending string: %v", extra, got)
		}
	}
	if got := findSwiftStrings(t, []byte{1, 2, 3}); len(got) != 0 {
		t.Errorf("code shorter than one instruction yielded %v", got)
	}
}
