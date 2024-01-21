package devicetree

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	// lzfse "github.com/blacktop/go-lzfse"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/blacktop/ipsw/pkg/lzfse"
)

var ErrEncryptedDeviceTree = errors.New("encrypted device tree")

// ParseImg3Data parses a img4 data containing a DeviceTree
func ParseImg3Data(data []byte) (*DeviceTree, error) {

	var i img3.Img3

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &i.Header); err != nil {
		return nil, err
	}

	for {
		var tag img3.Tag

		err := binary.Read(r, binary.LittleEndian, &tag.TagHeader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read img3 tag header: %v", err)
		}

		tag.Data = make([]byte, tag.DataLength)
		tag.Pad = make([]byte, tag.TotalLength-tag.DataLength-12)

		if err := binary.Read(r, binary.LittleEndian, &tag.Data); err != nil {
			return nil, fmt.Errorf("failed to read img3 tag data: %v", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &tag.Pad); err != nil {
			return nil, fmt.Errorf("failed to read img3 tag pad: %v", err)
		}

		i.Tags = append(i.Tags, tag)
	}

	var dr io.Reader
	if bytes.Contains(i.Tags[1].Data[:4], []byte("bvx2")) {
		dat, err := lzfse.NewDecoder(i.Tags[1].Data).DecodeBuffer()
		if err != nil {
			return nil, fmt.Errorf("failed to lzfse decompress DeviceTree: %v", err)
		}
		// dr = bytes.NewReader(lzfse.DecodeBuffer(i.Tags[1].Data))
		dr = bytes.NewReader(dat)
	} else {
		dr = bytes.NewReader(i.Tags[1].Data)
	}

	dtree, err := parseDeviceTree(dr)
	if err != nil {
		for _, tag := range i.Tags {
			magic := string(utils.ReverseBytes(tag.Magic[:]))
			if magic == "KBAG" {
				return nil, ErrEncryptedDeviceTree
			}
		}
		return nil, fmt.Errorf("failed to parse Img3 device tree data: %v", err)
	}

	return dtree, nil
}

// ParseImg4Data parses a img4 data containing a DeviceTree
func ParseImg4Data(data []byte) (*DeviceTree, error) {

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in DEVICETREE.im4p
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ans1 Img4 device tree: %v", err)
	}

	var r io.Reader
	if bytes.Contains(i.Data[:4], []byte("bvx2")) {
		dat, err := lzfse.NewDecoder(i.Data).DecodeBuffer()
		if err != nil {
			return nil, fmt.Errorf("failed to lzfse decompress DeviceTree: %v", err)
		}
		// r = bytes.NewReader(lzfse.DecodeBuffer(i.Data))
		r = bytes.NewReader(dat)
	} else {
		r = bytes.NewReader(i.Data)
	}

	dtree, err := parseDeviceTree(r)
	if err != nil {
		if len(i.KbagData) > 0 {
			return nil, ErrEncryptedDeviceTree
		}
		return nil, fmt.Errorf("failed to parse Img4 device tree data: %v", err)
	}

	return dtree, nil
}
