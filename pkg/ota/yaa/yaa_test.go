package yaa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// record encodes one archive record: header fields, then the entry's data.
func record(fields string, data []byte) []byte {
	var out bytes.Buffer
	out.WriteString("AA01")
	binary.Write(&out, binary.LittleEndian, uint16(6+len(fields)))
	out.WriteString(fields)
	out.Write(data)
	return out.Bytes()
}

func sizeField(n int) string {
	return "DATA" + string(binary.LittleEndian.AppendUint16(nil, uint16(n)))
}

func fileRecord(path, content string) []byte {
	pathLen := string(binary.LittleEndian.AppendUint16(nil, uint16(len(path))))
	return record("TYP1F"+"PATP"+pathLen+path+sizeField(len(content)), []byte(content))
}

// seekOnly hides ReadAt so Parse has to adapt the reader itself.
type seekOnly struct{ io.ReadSeeker }

// TestParseNestedPayloadReadsInPlace covers an extract entry whose data is a
// nested archive. Its files must be readable, the outer archive must resume
// after it, and the nested files must read from the backing reader: a private
// copy of the payload would be retained for the life of the archive.
func TestParseNestedPayloadReadsInPlace(t *testing.T) {
	nested := append(fileRecord("bin/tool", "nested-one"), fileRecord("bin/other", "nested-two")...)
	archive := append(record("TYP1M"+"YOP1E"+sizeField(len(nested)), nested), fileRecord("after", "outer")...)

	for name, wrap := range map[string]func(*bytes.Reader) io.ReadSeeker{
		"ReaderAt":  func(r *bytes.Reader) io.ReadSeeker { return r },
		"seek only": func(r *bytes.Reader) io.ReadSeeker { return seekOnly{r} },
	} {
		t.Run(name, func(t *testing.T) {
			backing := bytes.Clone(archive)
			var aa YAA
			if err := aa.Parse(wrap(bytes.NewReader(backing))); err != nil {
				t.Fatal(err)
			}
			read := func(path string) string {
				t.Helper()
				for _, ent := range aa.Entries {
					if ent.Path == path {
						out := make([]byte, ent.Size)
						if _, err := ent.Read(out); err != nil {
							t.Fatalf("read %s: %v", path, err)
						}
						return string(out)
					}
				}
				t.Fatalf("entry %s not found in %d entries", path, len(aa.Entries))
				return ""
			}
			for path, want := range map[string]string{"bin/tool": "nested-one", "bin/other": "nested-two", "after": "outer"} {
				if got := read(path); got != want {
					t.Errorf("%s = %q, want %q", path, got, want)
				}
			}

			copy(backing[bytes.Index(backing, []byte("nested-one")):], "CHANGED!!!")
			if got := read("bin/tool"); got != "CHANGED!!!" {
				t.Errorf("bin/tool = %q after the backing data changed; the nested payload was copied", got)
			}
		})
	}
}

func TestParseNestedPayloadTruncated(t *testing.T) {
	nested := fileRecord("bin/tool", "nested-one")
	archive := record("TYP1M"+"YOP1E"+sizeField(len(nested)+64), nested)
	if err := new(YAA).Parse(bytes.NewReader(archive)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want io.ErrUnexpectedEOF for an extract entry longer than the archive", err)
	}
}
