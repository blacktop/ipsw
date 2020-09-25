// +build aix darwin dragonfly freebsd js,wasm linux nacl netbsd openbsd solaris

package devicetree

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apex/log"
	lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img3"
)

// ParseImg3Data parses a img4 data containing a DeviceTree
func ParseImg3Data(data []byte) (*DeviceTree, error) {

	var i img3.Img3

	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.LittleEndian, &i.Header); err != nil {
		return nil, err
	}

	for {
		var err error
		var tag img3.Tag

		err = binary.Read(r, binary.LittleEndian, &tag.TagHeader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read img3 tag header: %v", err)
		}

		tag.Data = make([]byte, tag.DataLength)
		tag.Pad = make([]byte, tag.TotalLength-tag.DataLength-12)

		err = binary.Read(r, binary.LittleEndian, &tag.Data)
		err = binary.Read(r, binary.LittleEndian, &tag.Pad)

		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read img3 tag data: %v", err)
		}

		i.Tags = append(i.Tags, tag)
	}

	var dr io.Reader
	if bytes.Contains(i.Tags[1].Data[:4], []byte("bvx2")) {
		utils.Indent(log.Debug, 2)("DeviceTree is LZFSE compressed")
		dr = bytes.NewReader(lzfse.DecodeBuffer(i.Tags[1].Data))
	} else {
		dr = bytes.NewReader(i.Tags[1].Data)
	}

	dtree, err := parseDeviceTree(dr)
	if err != nil {
		return nil, err
	}

	return dtree, nil
}

// ParseImg4Data parses a img4 data containing a DeviceTree
func ParseImg4Data(data []byte) (*DeviceTree, error) {

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in DEVICETREE.im4p
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, err
	}

	var r io.Reader
	if bytes.Contains(i.Data[:4], []byte("bvx2")) {
		utils.Indent(log.Debug, 2)("DeviceTree is LZFSE compressed")
		r = bytes.NewReader(lzfse.DecodeBuffer(i.Data))
	} else {
		r = bytes.NewReader(i.Data)
	}

	dtree, err := parseDeviceTree(r)
	if err != nil {
		return nil, err
	}

	return dtree, nil
}
