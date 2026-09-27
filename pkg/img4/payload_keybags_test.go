package img4

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"errors"
	"hash/crc32"
	"io"
	"reflect"
	"strings"
	"testing"
)

func keybagTestPayload(t *testing.T, data []byte, keybags []Keybag, compressed bool) []byte {
	t.Helper()
	payload := IM4P{Tag: "IM4P", Type: "test", Version: "synthetic", Data: data}
	if keybags != nil {
		var err error
		payload.Keybag, err = asn1.Marshal(keybags)
		if err != nil {
			t.Fatal(err)
		}
	}
	if compressed {
		payload.Compression = Compression{Algorithm: CompressionAlgorithmLZFSE, UncompressedSize: len(data)}
	}
	encoded, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type keybagCountReader struct {
	r       io.Reader
	bytes   int
	maxRead int
}

func (r *keybagCountReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	n, err := r.r.Read(p)
	r.bytes += n
	return n, err
}

type keybagCountSeeker struct {
	keybagCountReader
	r     *bytes.Reader
	skips int64
}

func (r *keybagCountSeeker) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekCurrent {
		r.skips += offset
	}
	return r.r.Seek(offset, whence)
}

func TestReadPayloadKeybagsSkipsData(t *testing.T) {
	want := []Keybag{{Type: PRODUCTION, IV: bytes.Repeat([]byte{0x11}, 16), Key: bytes.Repeat([]byte{0x22}, 32)}}
	body := bytes.Repeat([]byte{0x55}, 4<<20)
	for _, compressed := range []bool{false, true} {
		for _, keybags := range [][]Keybag{nil, want} {
			encoded := keybagTestPayload(t, body, keybags, compressed)
			for _, seekable := range []bool{false, true} {
				reader := bytes.NewReader(encoded)
				counter := &keybagCountReader{r: reader}
				var input io.Reader = counter
				seeker := &keybagCountSeeker{keybagCountReader: *counter, r: reader}
				if seekable {
					input = seeker
					counter = &seeker.keybagCountReader
				}
				got, err := readPayloadKeybags(input, int64(len(encoded)))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, keybags) {
					t.Fatalf("keybags mismatch (compression=%t seekable=%t)", compressed, seekable)
				}
				if seekable {
					if seeker.skips != int64(len(body)) || counter.bytes > 1024 {
						t.Fatalf("read %d bytes, skipped %d, want metadata only and %d skipped", counter.bytes, seeker.skips, len(body))
					}
				} else if counter.bytes != len(encoded) || counter.maxRead > 32<<10 {
					t.Fatalf("stream read %d bytes (want %d), largest read %d", counter.bytes, len(encoded), counter.maxRead)
				}
			}
		}
	}
}

func TestReadPayloadKeybagsRejectsMalformed(t *testing.T) {
	valid := keybagTestPayload(t, []byte("fake payload"), nil, false)
	oversizedMetadata := keybagTestPayload(t, nil, nil, false)
	var payload IM4P
	if _, err := asn1.Unmarshal(oversizedMetadata, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Raw = nil
	payload.Version = strings.Repeat("v", maxKeybagMetadata)
	oversizedMetadata, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Version = "synthetic"
	payload.Keybag = []byte{0x30, 1}
	malformedKeybag, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Keybag = make([]byte, maxKeybagMetadata)
	oversizedTail, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	dataBounds := bytes.Clone(valid)
	dataOffset := bytes.Index(dataBounds, []byte{0x04, byte(len("fake payload"))})
	if dataOffset < 0 {
		t.Fatal("missing fixture data tag")
	}
	dataBounds[dataOffset+1]++
	cases := map[string][]byte{
		"empty":               nil,
		"wrong sequence tag":  {0x04, 0},
		"indefinite length":   {0x30, 0x80},
		"oversized length":    {0x30, 0x89},
		"signed overflow":     {0x30, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"nonminimal length":   {0x30, 0x81, 1, 0},
		"leading zero length": {0x30, 0x82, 0, 0x80},
		"truncated length":    {0x30, 0x82, 1},
		"truncated sequence":  valid[:len(valid)-1],
		"missing strings":     {0x30, 0},
		"string bounds":       {0x30, 2, 0x16, 4},
		"metadata limit":      oversizedMetadata,
		"tail limit":          oversizedTail,
		"invalid keybag":      malformedKeybag,
		"data bounds":         dataBounds,
		"invalid magic":       bytes.Replace(valid, []byte("IM4P"), []byte("NOPE"), 1),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readPayloadKeybags(bytes.NewReader(encoded), int64(len(encoded))); err == nil {
				t.Fatal("expected malformed payload error")
			}
		})
	}
}

type keybagCountReaderAt struct {
	*bytes.Reader
	bytes int
}

func (r *keybagCountReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.Reader.ReadAt(p, offset)
	r.bytes += n
	return n, err
}

func TestGetKeybagsFromIPSWStoredAndDeflated(t *testing.T) {
	want := []Keybag{{Type: PRODUCTION, IV: bytes.Repeat([]byte{0x11}, 16), Key: bytes.Repeat([]byte{0x22}, 32)}}
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		var archive bytes.Buffer
		zw := zip.NewWriter(&archive)
		for _, name := range []string{"Firmware/fake.im4p", "Firmware/empty.im4p"} {
			file, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method})
			if err != nil {
				t.Fatal(err)
			}
			var keybags []Keybag
			if name == "Firmware/fake.im4p" {
				keybags = want
			}
			if _, err := file.Write(keybagTestPayload(t, bytes.Repeat([]byte{0x55}, 4<<20), keybags, true)); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		reader := &keybagCountReaderAt{Reader: bytes.NewReader(archive.Bytes())}
		zr, err := zip.NewReader(reader, int64(archive.Len()))
		if err != nil {
			t.Fatal(err)
		}
		reader.bytes = 0
		got, err := GetKeybagsFromIPSW(zr.File, KeybagMetaData{}, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Files) != 1 || got.Files[0].Name != "fake.im4p" || !reflect.DeepEqual(got.Files[0].Keybags, want) {
			t.Fatal("incorrect keybag file selection or content")
		}
		if method == zip.Store && reader.bytes > 2048 {
			t.Fatalf("stored ZIP read %d bytes, want metadata only", reader.bytes)
		}
		t.Logf("method=%d archive=%d bytes member reads=%d", method, archive.Len(), reader.bytes)
		if _, err := GetKeybagsFromIPSW(zr.File, KeybagMetaData{}, "["); err == nil {
			t.Fatal("expected invalid pattern error")
		}
	}
}

type keybagTestReadCloser struct {
	io.Reader
	closed   bool
	closeErr error
}

func (r *keybagTestReadCloser) Close() error {
	r.closed = true
	return r.closeErr
}

func TestGetKeybagsFromIPSWClosesReaders(t *testing.T) {
	for _, failure := range []string{"none", "malformed", "truncated", "checksum", "close"} {
		t.Run(failure, func(t *testing.T) {
			data := keybagTestPayload(t, []byte("fake payload"), nil, false)
			if failure == "malformed" {
				data[0] = 0x04
			}
			checksum := crc32.ChecksumIEEE(data)
			if failure == "checksum" {
				checksum ^= 1
			}
			var archive bytes.Buffer
			zw := zip.NewWriter(&archive)
			file, err := zw.CreateRaw(&zip.FileHeader{
				Name: "fake.im4p", Method: 99, CRC32: checksum,
				CompressedSize64: uint64(len(data)), UncompressedSize64: uint64(len(data)),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
			if err != nil {
				t.Fatal(err)
			}
			if failure == "truncated" {
				data = data[:len(data)-1]
			}
			rc := &keybagTestReadCloser{Reader: bytes.NewReader(data)}
			if failure == "close" {
				rc.closeErr = errors.New("synthetic close failure")
			}
			zr.RegisterDecompressor(99, func(io.Reader) io.ReadCloser { return rc })
			_, err = GetKeybagsFromIPSW(zr.File, KeybagMetaData{}, "")
			if failure != "none" && (err == nil || !strings.Contains(err.Error(), "fake.im4p")) {
				t.Fatal("expected contextual member error")
			}
			if failure == "none" && err != nil {
				t.Fatal(err)
			}
			if !rc.closed {
				t.Fatal("member reader was not closed")
			}
		})
	}
}
