package img3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestDecryptDataExtent(t *testing.T) {
	iv := bytes.Repeat([]byte{0x11}, aes.BlockSize)
	key := bytes.Repeat([]byte{0x22}, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ data, stored int }{{1, 4}, {16, 16}, {17, 20}, {28, 32}, {32, 48}} {
		t.Run(fmt.Sprintf("%d/%d", tc.data, tc.stored), func(t *testing.T) {
			plain := bytes.Repeat([]byte{0x42}, tc.stored)
			plain[tc.data-1] = 1 // A real payload byte, not PKCS#7 padding.
			encrypted := bytes.Clone(plain)
			end := len(encrypted) / aes.BlockSize * aes.BlockSize
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted[:end], encrypted[:end])
			var image bytes.Buffer
			for _, value := range []any{
				Header{Magic: [4]byte{'3', 'g', 'm', 'I'}, FullSize: uint32(32 + tc.stored), SizeNoPack: uint32(12 + tc.stored)},
				TagHeader{Magic: [4]byte{'A', 'T', 'A', 'D'}, TotalLength: uint32(12 + tc.stored), DataLength: uint32(tc.data)},
				encrypted,
			} {
				if err := binary.Write(&image, binary.LittleEndian, value); err != nil {
					t.Fatal(err)
				}
			}
			before := bytes.Clone(image.Bytes())
			got, err := Decrypt(image.Bytes(), iv, key)
			if err != nil || !bytes.Equal(got, plain[:tc.data]) {
				t.Fatalf("Decrypt = %x, %v; want %x", got, err, plain[:tc.data])
			}
			if !bytes.Equal(image.Bytes(), before) {
				t.Fatal("Decrypt mutated its input")
			}
			encryptedBefore := bytes.Clone(encrypted)
			got, err = DecryptData(encrypted, iv, key)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("package DecryptData = %x, %v; want %x", got, err, plain)
			}
			if !bytes.Equal(encrypted, encryptedBefore) {
				t.Fatal("package DecryptData mutated its input")
			}
			parsed, err := ParseImg3(image.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			got, err = parsed.DecryptData(iv, key)
			if err != nil || !bytes.Equal(got, plain[:tc.data]) {
				t.Fatalf("DecryptData = %x, %v; want %x", got, err, plain[:tc.data])
			}
			if _, err := parsed.DecryptData(iv[:15], key); err == nil {
				t.Fatal("accepted short IV")
			}
		})
	}
	if _, err := DecryptData(make([]byte, aes.BlockSize), iv[:15], key); err == nil {
		t.Fatal("package DecryptData accepted a short IV")
	}
}

func TestParseImg3RejectsInvalidTagLengths(t *testing.T) {
	for _, tag := range []TagHeader{
		{TotalLength: 11},
		{TotalLength: 12, DataLength: 1},
		{TotalLength: 16, DataLength: 4},
		{TotalLength: ^uint32(0), DataLength: 1},
	} {
		var image bytes.Buffer
		for _, value := range []any{Header{Magic: [4]byte{'3', 'g', 'm', 'I'}}, tag} {
			if err := binary.Write(&image, binary.LittleEndian, value); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := ParseImg3(image.Bytes()); err == nil {
			t.Fatalf("accepted invalid tag: %+v", tag)
		}
	}
}

func TestStringBinaryTags(t *testing.T) {
	for _, magic := range []string{"CERT", "SHSH", "TEST", "KBAG"} {
		t.Run(magic, func(t *testing.T) {
			// Invalid KBAG AES type also exercises the binary fallback.
			data := bytes.Repeat([]byte{0xff}, 4097)
			var tagMagic [4]byte
			copy(tagMagic[:], reverseBytes([]byte(magic)))
			img := Img3{Tags: []Tag{{Magic: tagMagic, Data: data}}}
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
				Magic: [4]byte{'A', 'T', 'A', 'D'},
				Data:  bytes.Repeat([]byte{0xab}, size),
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
		Magic: [4]byte{'E', 'P', 'Y', 'T'},
		Data:  data,
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
					Magic: tagMagic,
					Data:  []byte{0x34, 0x12, 0, 0}[:size],
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
