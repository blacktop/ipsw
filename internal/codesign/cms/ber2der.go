package cms

import (
	"bytes"
	"fmt"
)

type asn1Object interface {
	encodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) encodeTo(out *bytes.Buffer) error {
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.encodeTo(inner)
		if err != nil {
			return err
		}
	}
	out.Write(s.tagBytes)
	encodeLength(out, inner.Len())
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) encodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	out.Write(p.content)

	return nil
}

func ber2Der(ber []byte) ([]byte, error) {
	out := new(bytes.Buffer)
	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}
	obj.encodeTo(out)
	return out.Bytes(), nil
}

func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)
	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}
	return nil
}

func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset int) (asn1Object, int, error) {
	tagStart := offset
	b := ber[offset]
	offset++
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		// multi-byte tag: skip high tag number octets
		for ber[offset] >= 0x80 {
			offset++
		}
		offset++
	}
	tagEnd := offset

	kind := b & 0x20

	var length int
	l := ber[offset]
	offset++
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, fmt.Errorf("BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, fmt.Errorf("BER tag length is negative")
		}
		if (int)(ber[offset]) == 0x0 {
			return nil, 0, fmt.Errorf("BER tag length has leading zero")
		}
		//fmt.Printf("--> (compute length) indicator byte: %x\n", l)
		//fmt.Printf("--> (compute length) length bytes: % X\n", ber[offset:offset+numberOfBytes])
		for range numberOfBytes {
			length = length*256 + (int)(ber[offset])
			offset++
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}

	//fmt.Printf("--> length        : %d\n", length)
	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, fmt.Errorf("BER tag length is more than available data")
	}
	//fmt.Printf("--> content start : %d\n", offset)
	//fmt.Printf("--> content end   : %d\n", contentEnd)
	//fmt.Printf("--> content       : % X\n", ber[offset:contentEnd])
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, fmt.Errorf("indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)

			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}

				if terminated {
					break
				}
			}
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, fmt.Errorf("indefinite form tag is missing terminator")
	}
	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}
