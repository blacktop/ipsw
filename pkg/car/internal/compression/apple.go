// Package compression handles bounded Apple compression streams used by CAR payloads.
package compression

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/lzfse-cgo"
)

const maxStreamBytes = 256 << 20

// Decode checks Apple stream framing before calling the bounded
// decoder. This also separates concatenated streams without searching for EOS
// magic inside compressed bytes or allocating from untrusted expansion ratios.
func Decode(data []byte, limit int, allowLZVN bool) ([]byte, error) {
	if len(data) == 0 || len(data) > maxStreamBytes || limit <= 0 || limit > maxStreamBytes {
		return nil, fmt.Errorf("deepmap2: invalid compressed stream or output limit")
	}
	if len(data) >= 8 && !IsAppleStream(data) && IsAppleStream(data[4:]) {
		// Some streams carry a four-byte prefix before the Apple block header.
		data = data[4:]
	}
	if !IsAppleStream(data) {
		if !allowLZVN || len(data) < 8 || !bytes.Equal(data[len(data)-8:], []byte{6, 0, 0, 0, 0, 0, 0, 0}) {
			return nil, fmt.Errorf("deepmap2: invalid compression stream")
		}
		size, err := lzvnSize(data, limit)
		if err != nil {
			return nil, err
		}
		dst := make([]byte, size)
		if n := lzfse.DecodeLZVNBuffer(data, dst); n != uint(size) {
			return nil, fmt.Errorf("LZVN decoded %d bytes, expected %d", n, size)
		}
		return dst, nil
	}
	var out []byte
	for len(data) != 0 {
		end, size, err := readAppleStream(data, limit-len(out))
		if err != nil {
			return nil, err
		}
		part := make([]byte, size+1)
		n := lzfse.DecodeBufferInto(data[:end], part)
		if n != size {
			return nil, fmt.Errorf("deepmap2: Apple stream decoded %d bytes, expected %d", n, size)
		}
		out = append(out, part[:n]...)
		data = data[end:]
		if len(data) >= 8 && bytes.Equal(data[:4], []byte{0, 0, 0, 0}) && IsAppleStream(data[4:]) {
			data = data[4:]
		}
	}
	return out, nil
}

// IsAppleStream reports whether data starts with a recognized Apple block header.
func IsAppleStream(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	switch string(data[:4]) {
	case "bvx-", "bvxn", "bvx1", "bvx2":
		return true
	}
	return false
}

func readAppleStream(data []byte, limit int) (int, int, error) {
	pos, output := 0, 0
	for len(data)-pos >= 4 {
		block := data[pos:]
		if string(block[:4]) == "bvx$" {
			if output == 0 {
				return 0, 0, fmt.Errorf("deepmap2: empty Apple stream")
			}
			return pos + 4, output, nil
		}
		if len(block) < 8 {
			break
		}
		rawSize := uint64(binary.LittleEndian.Uint32(block[4:]))
		if rawSize > uint64(max(0, limit-output)) {
			return 0, 0, fmt.Errorf("deepmap2: Apple stream exceeds output limit")
		}
		headerSize, payloadSize := uint64(0), uint64(0)
		switch string(block[:4]) {
		case "bvx-":
			headerSize, payloadSize = 8, rawSize
		case "bvxn", "bvx1":
			if len(block) < 12 {
				return 0, 0, fmt.Errorf("deepmap2: truncated Apple block")
			}
			headerSize = 12
			if string(block[:4]) == "bvx1" {
				headerSize = 772 // Includes the aligned, uncompressed frequency tables.
			}
			payloadSize = uint64(binary.LittleEndian.Uint32(block[8:]))
		case "bvx2":
			if len(block) < 32 {
				return 0, 0, fmt.Errorf("deepmap2: truncated LZFSE v2 header")
			}
			headerSize = uint64(binary.LittleEndian.Uint32(block[24:]))
			if headerSize < 32 || headerSize > 752 {
				return 0, 0, fmt.Errorf("deepmap2: invalid LZFSE v2 header size")
			}
			literalSize := binary.LittleEndian.Uint64(block[8:]) >> 20 & 0xfffff
			lmdSize := binary.LittleEndian.Uint64(block[16:]) >> 40 & 0xfffff
			payloadSize = literalSize + lmdSize
		default:
			return 0, 0, fmt.Errorf("deepmap2: invalid Apple block magic")
		}
		if headerSize+payloadSize > uint64(len(block)) {
			return 0, 0, fmt.Errorf("deepmap2: truncated Apple block payload")
		}
		pos += int(headerSize + payloadSize)
		output += int(rawSize)
	}
	return 0, 0, fmt.Errorf("deepmap2: missing Apple stream terminator")
}

// ReadLimited reads at most limit bytes and rejects oversized input.
func ReadLimited(r io.Reader, limit int) ([]byte, error) {
	if limit < 0 || limit > maxStreamBytes {
		return nil, fmt.Errorf("invalid decode limit: %d", limit)
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("decoded data exceeds %d bytes", limit)
	}
	return data, nil
}

// DecodeLZFSE requires Apple stream framing before invoking the bounded decoder.
func DecodeLZFSE(data []byte, limit int) ([]byte, error) {
	if !IsAppleStream(data) {
		return nil, fmt.Errorf("invalid LZFSE stream")
	}
	// Ordinary CSI payloads and Deepmap2 share Apple compression framing.
	return Decode(data, limit, false)
}
