package car

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
	"golang.org/x/net/html/charset"
)

const (
	PixFmtSVG  = "SVG " // SVG source payload.
	PixFmtWebP = "WEBP" // WebP source payload.
)

var errOriginalRLE = fmt.Errorf(
	"%w: RLE-compressed original payload; use --raw to preserve CSI", errUnsupportedRendition)

type bitmapChunk struct {
	data []byte
	rows uint32
}

func readCSIBitmap(data []byte) (csiBitmap, []bitmapChunk, error) {
	var elem csiBitmap
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &elem); err != nil {
		return elem, nil, err
	}
	if elem.Signature != [4]byte{'M', 'L', 'E', 'C'} {
		return elem, nil, fmt.Errorf("invalid bitmap signature: %q", elem.Signature)
	}
	if len(data) > pixel.MaxBytes {
		return elem, nil, fmt.Errorf("bitmap exceeds size limit")
	}
	if !elem.Flags.ChunksFollow() {
		if uint64(elem.Length) != uint64(r.Len()) {
			return elem, nil, fmt.Errorf("bitmap length mismatch: declared %d, have %d", elem.Length, r.Len())
		}
		return elem, []bitmapChunk{{data: data[16:]}}, nil
	}
	if elem.Length == 0 || elem.Length > 65536 || uint64(elem.Length)*20 > uint64(r.Len()) {
		return elem, nil, fmt.Errorf("invalid bitmap chunk count: %d", elem.Length)
	}
	chunks := make([]bitmapChunk, 0, int(elem.Length))
	for range elem.Length {
		var h csiBitmapChunk
		if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
			return elem, nil, err
		}
		if h.Signature != [4]byte{'K', 'C', 'B', 'C'} {
			return elem, nil, fmt.Errorf("invalid bitmap chunk signature: %q", h.Signature)
		}
		if uint64(h.Length) > uint64(r.Len()) {
			return elem, nil, fmt.Errorf("truncated bitmap chunk")
		}
		start := len(data) - r.Len()
		chunks = append(chunks, bitmapChunk{data: data[start : start+int(h.Length)], rows: h.Rows})
		if _, err := r.Seek(int64(h.Length), io.SeekCurrent); err != nil {
			return elem, nil, err
		}
	}
	if r.Len() != 0 {
		return elem, nil, fmt.Errorf("trailing bitmap data: %d bytes", r.Len())
	}
	return elem, chunks, nil
}

func decodeBitmapBytes(data []byte, encoding compressionType, limit int) ([]byte, error) {
	if limit < 0 || limit > pixel.MaxBytes {
		return nil, fmt.Errorf("invalid decode limit")
	}
	switch encoding {
	case Uncompressed:
		if len(data) > limit {
			return nil, fmt.Errorf("uncompressed data exceeds %d bytes", limit)
		}
		return data, nil
	case ZIP:
		var r io.ReadCloser
		var err error
		if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
			r, err = gzip.NewReader(bytes.NewReader(data))
		} else if len(data) >= 2 && data[0]&15 == 8 &&
			(uint16(data[0])<<8|uint16(data[1]))%31 == 0 {
			r, err = zlib.NewReader(bytes.NewReader(data))
		} else {
			r = flate.NewReader(bytes.NewReader(data))
		}
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return compression.ReadLimited(r, limit)
	case LZFSE:
		return compression.DecodeLZFSE(data, limit)
	case LZVN:
		return compression.Decode(data, limit, true)
	default:
		return nil, fmt.Errorf("unsupported bitmap compression: %s", encoding)
	}
}

// decodeOriginalPayload removes CoreUI framing while preserving the source file.
func decodeOriginalPayload(data []byte, format string) ([]byte, error) {
	if len(data) > pixel.MaxBytes {
		return nil, fmt.Errorf("payload exceeds size limit")
	}
	if bytes.HasPrefix(data, []byte("DWAR")) {
		if len(data) < 12 ||
			uint64(binary.LittleEndian.Uint32(data[8:12])) != uint64(len(data)-12) {
			return nil, fmt.Errorf("invalid RAWD payload length")
		}
		data = data[12:]
		if compression.IsAppleStream(data) {
			var err error
			data, err = compression.DecodeLZFSE(data, pixel.MaxBytes)
			if err != nil {
				return nil, err
			}
		}
	} else if bytes.HasPrefix(data, []byte("MLEC")) {
		elem, chunks, err := readCSIBitmap(data)
		if err != nil {
			return nil, err
		}
		// Only bitmap row packets have a verified RLE grammar. Do not guess
		// at the encoding of original-file payloads (including DATA).
		if elem.Encoding == RLE {
			return nil, errOriginalRLE
		}
		if elem.Encoding == HEVC {
			if format != PixFmtHEIF || len(chunks) != 1 {
				return nil, fmt.Errorf("%w: HEVC export requires one HEIF chunk",
					errUnsupportedRendition)
			}
			data = chunks[0].data
			if len(data) < 8 ||
				uint64(binary.LittleEndian.Uint32(data[4:8])) != uint64(len(data)-8) {
				return nil, fmt.Errorf("invalid HEVC wrapper length")
			}
			data = data[8:]
		} else {
			var out []byte
			for _, chunk := range chunks {
				encoding := elem.Encoding
				if encoding == Uncompressed && compression.IsAppleStream(chunk.data) {
					encoding = LZFSE
				}
				part, err := decodeBitmapBytes(chunk.data, encoding, pixel.MaxBytes-len(out))
				if err != nil {
					return nil, err
				}
				out = append(out, part...)
			}
			data = out
		}
	}
	if !validOriginalPayload(data, format) {
		return nil, fmt.Errorf("invalid %q source payload", format)
	}
	return data, nil
}

func validOriginalPayload(data []byte, format string) bool {
	valid := false
	switch format {
	case PixFmtRawData:
		valid = true
	case PixFmtJPEG:
		valid = len(data) >= 3 && bytes.Equal(data[:3], []byte{0xff, 0xd8, 0xff})
	case PixFmtPDF:
		valid = bytes.HasPrefix(data, []byte("%PDF-"))
	case PixFmtWebP:
		valid = len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP" &&
			uint64(binary.LittleEndian.Uint32(data[4:8]))+8 == uint64(len(data))
	case PixFmtSVG:
		d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
		d.CharsetReader = charset.NewReaderLabel
		for {
			tok, err := d.Token()
			if err != nil {
				break
			}
			if start, ok := tok.(xml.StartElement); ok {
				valid = start.Name.Local == "svg"
				break
			}
		}
	case PixFmtHEIF:
		if len(data) >= 16 && string(data[4:8]) == "ftyp" {
			size := uint64(binary.BigEndian.Uint32(data[:4]))
			if size >= 16 && size <= uint64(len(data)) && size%4 == 0 {
				for i := 8; i < int(size); i += 4 {
					if i == 12 {
						continue
					}
					switch string(data[i : i+4]) {
					case "heic", "heix", "hevc", "hevx", "heim", "heis",
						"mif1", "msf1", "MiHE", "MiHB":
						valid = true
					}
				}
			}
		}
	}
	return valid
}

// Identify a known unsupported source wrapper during planning without decoding.
// Malformed wrappers still need decoding to report their framing error.
func (rend *Rendition) hasOriginalRLE() bool {
	if rend.link != nil || rend.Compression != RLE.String() {
		return false
	}
	switch rend.PixelFormat {
	case PixFmtRawData, PixFmtPDF, PixFmtJPEG, PixFmtHEIF, PixFmtSVG, PixFmtWebP:
		elem, _, err := readCSIBitmap(rend.payload)
		return err == nil && elem.Encoding == RLE
	}
	return false
}

func isRenderableFormat(format string) bool {
	return format == PixFmtHEIF || format == PixFmtPDF || format == PixFmtSVG
}

// DATA renditions are recognized by their source headers, not their names.
func renderedPayloadFormat(data []byte, declared string) string {
	if declared != PixFmtRawData {
		return declared
	}
	if bytes.HasPrefix(data, []byte("%PDF-")) {
		return PixFmtPDF
	}
	if len(data) >= 16 && string(data[4:8]) == "ftyp" {
		if _, err := decodeOriginalPayload(data, PixFmtHEIF); err == nil {
			return PixFmtHEIF
		}
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(data) == 0 || data[0] != '<' {
		return declared
	}
	reader := xml.NewDecoder(bytes.NewReader(data))
	reader.CharsetReader = charset.NewReaderLabel
	for {
		token, err := reader.Token()
		if err != nil {
			return declared
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local == "svg" && (start.Name.Space == "" || start.Name.Space == "http://www.w3.org/2000/svg") {
				return PixFmtSVG
			}
			return declared
		}
	}
}
