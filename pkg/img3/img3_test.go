package img3

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestStringBinaryTags(t *testing.T) {
	for _, magic := range []string{"CERT", "SHSH", "TEST", "KBAG"} {
		t.Run(magic, func(t *testing.T) {
			// Invalid KBAG AES type also exercises the binary fallback.
			data := bytes.Repeat([]byte{0xff}, 4097)
			var tagMagic [4]byte
			copy(tagMagic[:], reverseBytes([]byte(magic)))
			img := Img3{Tags: []Tag{{TagHeader: TagHeader{Magic: tagMagic}, Data: data}}}
			out := img.String()
			rows := 0
			for line := range strings.SplitSeq(out, "\n") {
				if len(line) > 120 {
					t.Fatalf("output line too long: %d characters", len(line))
				}
				if strings.HasPrefix(line, "0000") {
					rows++
				}
			}
			if !strings.Contains(out, magic+": (length: 4097") {
				t.Fatal("missing tag name or length")
			}
			if magic == "KBAG" && !strings.Contains(out, "parse error:") {
				t.Fatal("missing KBAG parse error")
			}
			if rows != 257 || !strings.Contains(out, "00001000  ff") {
				t.Fatal("hex dump did not preserve the full payload")
			}
		})
	}
}

func TestStringDataPreview(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 17, 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			img := Img3{Tags: []Tag{{
				TagHeader: TagHeader{Magic: [4]byte{'A', 'T', 'A', 'D'}},
				Data:      bytes.Repeat([]byte{0xab}, size),
			}}}
			want := fmt.Sprintf("DATA: %s (length: %d)\n", strings.Repeat("ab", min(size, 16)), size)
			if out := img.String(); !strings.HasSuffix(out, want) {
				t.Fatalf("output %q does not end with %q", out, want)
			}
		})
	}
}

func TestStringDoesNotMutateType(t *testing.T) {
	data := []byte("tobi")
	img := Img3{Tags: []Tag{{
		TagHeader: TagHeader{Magic: [4]byte{'E', 'P', 'Y', 'T'}},
		Data:      data,
	}}}
	first := img.String()
	if !strings.Contains(first, "TYPE: ibot\n") {
		t.Fatal("incorrect TYPE output")
	}
	if string(data) != "tobi" {
		t.Fatal("formatting mutated TYPE data")
	}
	if second := img.String(); second != first {
		t.Fatal("formatting changed between calls")
	}
}

func TestStringScalarTags(t *testing.T) {
	for _, magic := range []string{"SEPO", "CHIP", "BORD"} {
		for size := 0; size <= 4; size++ {
			t.Run(fmt.Sprintf("%s/%d", magic, size), func(t *testing.T) {
				var tagMagic [4]byte
				copy(tagMagic[:], reverseBytes([]byte(magic)))
				img := Img3{Tags: []Tag{{
					TagHeader: TagHeader{Magic: tagMagic},
					Data:      []byte{0x34, 0x12, 0, 0}[:size],
				}}}
				out := img.String()
				want := fmt.Sprintf("%s: (length: %d, invalid uint32)\n", magic, size)
				if size == 4 {
					want = magic + ": 0x1234\n"
					if magic == "SEPO" {
						want = "SEPO: 4660\n"
					}
				}
				if !strings.Contains(out, want) {
					t.Fatalf("output %q does not contain %q", out, want)
				}
			})
		}
	}
}
