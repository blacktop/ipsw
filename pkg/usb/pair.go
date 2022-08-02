package usb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/usb/types"
)

func (u *USBConnection) GetPair(dev types.Device) (*types.PairRecord, error) {

	data, err := plist.Marshal(types.ReadPair{
		BundleID:            types.BundleID,
		ClientVersionString: u.clientVersion,
		ProgName:            types.ProgName,
		MessageType:         "ReadPairRecord",
		LibUSBMuxVersion:    3,
		PairRecordID:        dev.Properties.UDID,
	}, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ReadPair: %v", err)
	}

	u.tag++

	if err := binary.Write(u.c, binary.LittleEndian, UsbMuxHeader{
		Length:  sizeOfHeader + uint32(len(data)),
		Request: 8,
		Version: 1,
		Tag:     u.tag,
	}); err != nil {
		return nil, fmt.Errorf("failed to write header: %v", err)
	}
	n, err := u.c.Write(data)
	if n < len(data) {
		return nil, fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to write data: %v", err)
	}

	var header UsbMuxHeader
	if err := binary.Read(u.c, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}
	payload := make([]byte, header.Length-sizeOfHeader)
	if _, err = io.ReadFull(u.c, payload); err != nil {
		return nil, fmt.Errorf("failed to read payload: %v", err)
	}

	type pairRecordData struct {
		PairRecordData []byte
	}

	prd := pairRecordData{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&prd); err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// ioutil.WriteFile("dev_pair.plist", prd.PairRecordData, 0664)

	u.pair = types.PairRecord{}
	if err := plist.NewDecoder(bytes.NewReader(prd.PairRecordData)).Decode(&u.pair); err != nil {
		return nil, fmt.Errorf("failed to decode read pair record payload: %v", err)
	}

	return &u.pair, nil
}
