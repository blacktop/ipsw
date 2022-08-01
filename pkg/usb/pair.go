package usb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/go-plist"
)

type readPair struct {
	BundleID            string
	ClientVersionString string
	MessageType         string
	ProgName            string
	LibUSBMuxVersion    uint32 `plist:"kLibUSBMuxVersion"`
	PairRecordID        string
}

type pairRecordData struct {
	PairRecordData []byte
}

type PairRecord struct {
	HostID            string
	SystemBUID        string
	HostCertificate   []byte
	HostPrivateKey    []byte
	DeviceCertificate []byte
	EscrowBag         []byte
	WiFiMACAddress    string
	RootCertificate   []byte
	RootPrivateKey    []byte
}

func (u *USBConnection) GetPair(dev Device) (*PairRecord, error) {

	data, err := plist.Marshal(readPair{
		BundleID:            bundleID,
		ClientVersionString: u.clientVersion,
		ProgName:            progName,
		MessageType:         "ReadPairRecord",
		LibUSBMuxVersion:    3,
		PairRecordID:        dev.Properties.UDID,
	}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	u.tag++

	if err := binary.Write(u.c, binary.LittleEndian, UsbMuxHeader{
		Length:  sizeOfHeader + uint32(len(data)),
		Request: 8,
		Version: 1,
		Tag:     u.tag,
	}); err != nil {
		return nil, err
	}
	n, err := u.c.Write(data)
	if n < len(data) {
		return nil, fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return nil, err
	}

	var header UsbMuxHeader
	if err := binary.Read(u.c, binary.LittleEndian, &header); err != nil {
		return nil, err
	}
	payload := make([]byte, header.Length-sizeOfHeader)
	if _, err = io.ReadFull(u.c, payload); err != nil {
		return nil, err
	}

	prd := pairRecordData{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&prd); err != nil {
		return nil, err
	}

	// ioutil.WriteFile("dev_pair.plist", prd.PairRecordData, 0664)

	u.pair = PairRecord{}
	if err := plist.NewDecoder(bytes.NewReader(prd.PairRecordData)).Decode(&u.pair); err != nil {
		return nil, err
	}

	return &u.pair, nil
}
