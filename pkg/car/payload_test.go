package car

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"io"
	"testing"
)

func bitmapFixture(t *testing.T, encoding compressionType, rows []uint32, bodies ...[]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	flags, length := csiBitmapFlags(0), uint32(len(bodies[0]))
	if rows != nil {
		flags = 1
		length = uint32(len(bodies))
	}
	if err := binary.Write(&b, binary.LittleEndian, csiBitmap{Signature: [4]byte{'M', 'L', 'E', 'C'}, Flags: flags, Encoding: encoding, Length: length}); err != nil {
		t.Fatal(err)
	}
	for i, body := range bodies {
		if rows != nil {
			if err := binary.Write(&b, binary.LittleEndian, csiBitmapChunk{Signature: [4]byte{'K', 'C', 'B', 'C'}, Rows: rows[i], Length: uint32(len(body))}); err != nil {
				t.Fatal(err)
			}
		}
		b.Write(body)
	}
	return b.Bytes()
}

func rawFixture(body []byte) []byte {
	data := make([]byte, 12, 12+len(body))
	copy(data, "DWAR")
	binary.LittleEndian.PutUint32(data[8:], uint32(len(body)))
	return append(data, body...)
}

func TestOriginalPayload(t *testing.T) {
	webp := []byte("RIFF\x04\x00\x00\x00WEBP")
	heif := []byte{0, 0, 0, 20, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1', 0, 0, 0, 0, 'h', 'e', 'i', 'c'}
	for _, tt := range []struct {
		format string
		data   []byte
	}{
		{PixFmtJPEG, []byte{0xff, 0xd8, 0xff, 0xe0, 0, 0}},
		{PixFmtPDF, []byte("%PDF-1.7\nfake document")},
		{PixFmtSVG, []byte("<?xml version=\"1.0\"?><!-- fake --><svg xmlns=\"http://www.w3.org/2000/svg\"/>")},
		{PixFmtWebP, webp}, {PixFmtHEIF, heif}, {PixFmtRawData, []byte("fake payload")},
	} {
		t.Run(tt.format, func(t *testing.T) {
			for _, wrapped := range [][]byte{tt.data, rawFixture(tt.data), bitmapFixture(t, Uncompressed, nil, tt.data), bitmapFixture(t, Uncompressed, []uint32{0, 0}, tt.data[:2], tt.data[2:])} {
				got, err := decodeOriginalPayload(wrapped, tt.format)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, tt.data) {
					t.Fatalf("payload changed: %x", got)
				}
			}
		})
	}
	wrapper := make([]byte, 8)
	binary.LittleEndian.PutUint32(wrapper[4:], uint32(len(heif)))
	wrapper = append(wrapper, heif...)
	got, err := decodeOriginalPayload(bitmapFixture(t, HEVC, nil, wrapper), PixFmtHEIF)
	if err != nil || !bytes.Equal(got, heif) {
		t.Fatalf("HEIF unwrap: %x, %v", got, err)
	}
	wrapper[4]++
	if _, err := decodeOriginalPayload(bitmapFixture(t, HEVC, nil, wrapper), PixFmtHEIF); err == nil {
		t.Fatal("accepted corrupt HEVC length")
	}
}

func TestBitmapCompression(t *testing.T) {
	want := bytes.Repeat([]byte{1, 2, 3, 4}, 20)
	for _, format := range []string{"gzip", "zlib", "deflate"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			var w io.WriteCloser
			switch format {
			case "gzip":
				w = gzip.NewWriter(&b)
			case "zlib":
				w = zlib.NewWriter(&b)
			default:
				var err error
				w, err = flate.NewWriter(&b, flate.DefaultCompression)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := w.Write(want); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := decodeBitmapBytes(b.Bytes(), ZIP, len(want))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("decode: %x, %v", got, err)
			}
			if _, err := decodeBitmapBytes(b.Bytes(), ZIP, len(want)-1); err == nil {
				t.Fatal("accepted oversized expansion")
			}
		})
	}
	got, err := decodeBitmapBytes([]byte{2, 1, 2, 3, 254, 9, 128}, RLE, 6)
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3, 9, 9, 9}) {
		t.Fatalf("RLE: %x, %v", got, err)
	}
	for _, data := range [][]byte{{2, 1}, {254}, {254, 9}} {
		if _, err := decodeBitmapBytes(data, RLE, 2); err == nil {
			t.Fatalf("accepted invalid RLE %x", data)
		}
	}
	// A framed uncompressed LZFSE block exercises the native bounded decoder.
	lzfse := append([]byte("bvx-"), 4, 0, 0, 0)
	lzfse = append(lzfse, 1, 2, 3, 4)
	lzfse = append(lzfse, []byte("bvx$")...)
	got, err = decodeBitmapBytes(lzfse, LZFSE, 4)
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("LZFSE: %x, %v", got, err)
	}
	if _, err := decodeBitmapBytes(append(append([]byte{}, lzfse...), 1), LZFSE, 4); err == nil {
		t.Fatal("accepted trailing LZFSE data")
	}
	if _, err := decodeBitmapBytes(lzfse, LZFSE, 3); err == nil {
		t.Fatal("accepted oversized LZFSE")
	}
}

func TestMalformedPayloadFraming(t *testing.T) {
	good := bitmapFixture(t, Uncompressed, []uint32{1}, []byte{1, 2, 3, 4})
	for _, data := range [][]byte{nil, good[:15], good[:len(good)-1], append(append([]byte{}, good...), 0)} {
		if _, _, err := readCSIBitmap(data); err == nil {
			t.Fatalf("accepted %d-byte malformed bitmap", len(data))
		}
	}
	bad := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(bad[12:16], 0xffffffff)
	if _, _, err := readCSIBitmap(bad); err == nil {
		t.Fatal("accepted excessive chunks")
	}
	if _, err := decodeOriginalPayload(rawFixture([]byte("not a PDF")), PixFmtPDF); err == nil {
		t.Fatal("accepted non-PDF")
	}
	bad = rawFixture([]byte("123"))
	bad[8]++
	if _, err := decodeOriginalPayload(bad, PixFmtRawData); err == nil {
		t.Fatal("accepted truncated RAWD")
	}
}

func TestRenderedPayloadFormat(t *testing.T) {
	for _, sample := range []struct {
		data, declared, want string
	}{
		{`<svg xmlns="http://www.w3.org/2000/svg"/>`, PixFmtRawData, PixFmtSVG},
		{`<?xml version="1.0"?><svg/>`, PixFmtRawData, PixFmtSVG},
		{`<svg xmlns="https://example.invalid/fake"/>`, PixFmtRawData, PixFmtRawData},
		{`<not-an-svg/>`, PixFmtRawData, PixFmtRawData},
		{`plain data`, PixFmtRawData, PixFmtRawData},
		{"%PDF-1.4\n", PixFmtRawData, PixFmtPDF},
		{`<svg/>`, PixFmtJPEG, PixFmtJPEG},
	} {
		if got := renderedPayloadFormat([]byte(sample.data), sample.declared); got != sample.want {
			t.Errorf("format for %q = %q, want %q", sample.data, got, sample.want)
		}
	}
}

func TestSVGDeclaredEncodingPreservesOriginal(t *testing.T) {
	data := []byte("<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><!--caf\xe9--></svg>")
	got, err := decodeOriginalPayload(data, PixFmtSVG)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("original SVG changed or failed: %q, %v", got, err)
	}
	if got := renderedPayloadFormat(data, PixFmtRawData); got != PixFmtSVG {
		t.Fatalf("DATA SVG format = %q", got)
	}
}
