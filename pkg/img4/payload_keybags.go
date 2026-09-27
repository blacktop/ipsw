package img4

import (
	"archive/zip"
	"encoding/asn1"
	"fmt"
	"io"
	"math"
)

// Only metadata is allocated; payload bodies can be several gigabytes.
const maxKeybagMetadata = 1 << 20

func zippedPayloadKeybags(f *zip.File) (keybags []Keybag, err error) {
	if f.UncompressedSize64 > math.MaxInt64 {
		return nil, fmt.Errorf("payload exceeds supported size")
	}
	if f.Method == zip.Store {
		if f.CompressedSize64 != f.UncompressedSize64 {
			return nil, fmt.Errorf("stored payload has inconsistent sizes")
		}
		// OpenRaw returns a section reader, so skipping Data avoids reading its
		// bytes locally or over HTTP. Whole-member CRC validation is therefore
		// unavailable on this metadata-only path.
		r, err := f.OpenRaw()
		if err != nil {
			return nil, err
		}
		return readPayloadKeybags(r, int64(f.UncompressedSize64))
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := r.Close(); err == nil {
			err = closeErr
		}
	}()
	keybags, err = readPayloadKeybags(r, int64(f.UncompressedSize64))
	if err != nil {
		return nil, err
	}
	// Reach EOF to validate the ZIP checksum, including any trailing bytes.
	_, err = io.Copy(io.Discard, r)
	return keybags, err
}

func readPayloadKeybags(r io.Reader, size int64) ([]Keybag, error) {
	header, remaining, err := readKeybagDERHeader(r, 0x30)
	if err != nil {
		return nil, fmt.Errorf("IM4P sequence: %w", err)
	}
	if size < int64(len(header)) || remaining > size-int64(len(header)) {
		return nil, fmt.Errorf("IM4P sequence exceeds payload size")
	}
	var metadata []byte
	// The three IA5 strings precede the Data OCTET STRING.
	for range 3 {
		header, length, err := readKeybagDERHeader(io.LimitReader(r, remaining), 0x16)
		if err != nil {
			return nil, fmt.Errorf("IM4P string: %w", err)
		}
		remaining -= int64(len(header))
		if length > remaining || length > int64(maxKeybagMetadata-len(metadata)-len(header)) {
			return nil, fmt.Errorf("IM4P string exceeds metadata bounds")
		}
		metadata = append(metadata, header...)
		start := len(metadata)
		metadata = append(metadata, make([]byte, int(length))...)
		if _, err := io.ReadFull(r, metadata[start:]); err != nil {
			return nil, err
		}
		remaining -= length
	}
	header, length, err := readKeybagDERHeader(io.LimitReader(r, remaining), 0x04)
	if err != nil {
		return nil, fmt.Errorf("IM4P data: %w", err)
	}
	remaining -= int64(len(header))
	if length > remaining {
		return nil, fmt.Errorf("IM4P data exceeds sequence size")
	}
	remaining -= length
	if remaining > int64(maxKeybagMetadata-len(metadata)-2) {
		return nil, fmt.Errorf("IM4P tail exceeds metadata bounds")
	}
	if seeker, ok := r.(io.Seeker); ok {
		_, err = seeker.Seek(length, io.SeekCurrent)
	} else {
		_, err = io.CopyN(io.Discard, r, length)
	}
	if err != nil {
		return nil, fmt.Errorf("skip IM4P data: %w", err)
	}
	metadata = append(metadata, 0x04, 0) // Replace Data with an empty OCTET STRING.
	start := len(metadata)
	metadata = append(metadata, make([]byte, int(remaining))...)
	if _, err := io.ReadFull(r, metadata[start:]); err != nil {
		return nil, fmt.Errorf("IM4P metadata: %w", err)
	}
	data, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: metadata})
	if err != nil {
		return nil, err
	}
	payload, err := ParsePayload(data)
	if err != nil {
		return nil, err
	}
	return payload.Keybags, nil
}

// Read only the tag and definite DER length, rejecting noncanonical lengths
// and lengths that cannot fit in the signed offsets used by ZIP readers.
func readKeybagDERHeader(r io.Reader, tag byte) ([]byte, int64, error) {
	var header [10]byte
	if _, err := io.ReadFull(r, header[:2]); err != nil {
		return nil, 0, err
	}
	if header[0] != tag {
		return nil, 0, fmt.Errorf("unexpected ASN.1 tag %#x, expected %#x", header[0], tag)
	}
	if header[1] < 0x80 {
		return header[:2], int64(header[1]), nil
	}
	count := int(header[1] & 0x7f)
	if count == 0 || count > 8 {
		return nil, 0, fmt.Errorf("invalid ASN.1 length")
	}
	if _, err := io.ReadFull(r, header[2:2+count]); err != nil {
		return nil, 0, err
	}
	if header[2] == 0 || (count == 8 && header[2] > 0x7f) {
		return nil, 0, fmt.Errorf("invalid ASN.1 length")
	}
	var length int64
	for _, b := range header[2 : 2+count] {
		length = length<<8 | int64(b)
	}
	if length < 0x80 {
		return nil, 0, fmt.Errorf("nonminimal ASN.1 length")
	}
	return header[:2+count], length, nil
}
