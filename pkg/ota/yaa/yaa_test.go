package yaa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

func TestParseInvalidMagicOffset(t *testing.T) {
	var record bytes.Buffer
	record.WriteString("YAA1")
	binary.Write(&record, binary.LittleEndian, uint16(11))
	record.WriteString("TYP1D")
	for _, prefix := range [][]byte{nil, record.Bytes()} {
		data := append(bytes.Clone(prefix), []byte("BAD!")...)
		err := new(YAA).Parse(bytes.NewReader(data))
		if !errors.Is(err, ErrInvalidMagic) {
			t.Fatalf("error = %v, want ErrInvalidMagic", err)
		}
		for _, want := range []string{fmt.Sprintf("offset %#x", len(prefix)), "0x21444142", "YAA1 or AA01"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want %q", err, want)
			}
		}
	}
}

func TestDecodeEntryOneByteMode(t *testing.T) {
	entry, err := DecodeEntry(bytes.NewReader(append([]byte("TYP1FMOD1"), 0o100)))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Mod != fs.FileMode(0o100) {
		t.Fatalf("mode = %o, want 100", entry.Mod)
	}
	if _, err := DecodeEntry(bytes.NewReader([]byte("TYP1FMOD1"))); err == nil {
		t.Fatal("truncated MOD1 accepted")
	}
}
