package devicetree

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/blacktop/ipsw/pkg/img4"
)

var ErrEncryptedDeviceTree = errors.New("encrypted device tree")

// ParseImg3Data parses a img3 data containing a DeviceTree
func ParseImg3Data(data []byte) (*DeviceTree, error) {
	// First try to extract data (handles both encrypted detection and data extraction)
	extractedData, err := img3.ExtractData(data)
	if err != nil {
		// Check if this might be an encrypted IMG3 by parsing and looking for KBAG tags
		i, parseErr := img3.ParseImg3(data)
		if parseErr == nil {
			for _, tag := range i.Tags {
				magic := string(utils.ReverseBytes(tag.Magic[:]))
				if magic == "KBAG" {
					return nil, ErrEncryptedDeviceTree
				}
			}
		}
		return nil, fmt.Errorf("failed to extract IMG3 data: %v", err)
	}

	dr := bytes.NewReader(extractedData)

	dtree, err := parseDeviceTree(dr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IMG3 device tree data: %v", err)
	}

	return dtree, nil
}

// ParseImg4Data parses a img4 data containing a DeviceTree
func ParseImg4Data(data []byte) (*DeviceTree, error) {

	// NOTE: openssl asn1parse -i -inform DER -in DEVICETREE.im4p
	var i Img4

	im4p, err := img4.ParsePayload(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Img4 payload: %v", err)
	}
	data, err = im4p.GetData()
	if err != nil {
		return nil, fmt.Errorf("failed to get Img4 data: %v", err)
	}

	dtree, err := parseDeviceTree(bytes.NewReader(data))
	if err != nil {
		if len(i.KbagData) > 0 {
			return nil, ErrEncryptedDeviceTree
		}
		return nil, fmt.Errorf("failed to parse Img4 device tree data: %v", err)
	}

	return dtree, nil
}
