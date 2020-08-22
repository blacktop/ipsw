// +build windows

package devicetree

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
)

// ParseImg4Data parses a img4 data containing a DeviceTree
func ParseImg4Data(data []byte) (*DeviceTree, error) {

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in DEVICETREE.im4p
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, err
	}

	var r io.Reader
	if bytes.Contains(i.Data[:4], []byte("bvx2")) {
		utils.Indent(log.Info, 2)("DeviceTree is LZFSE compressed")
		return nil, fmt.Errorf("LZFSE decompression not supported on windows")
	} else {
		r = bytes.NewReader(i.Data)
	}

	dtree, err := parseDeviceTree(r)
	if err != nil {
		return nil, err
	}

	return dtree, nil
}
