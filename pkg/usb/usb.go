package usb

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/usb/lockdown"
	"github.com/blacktop/ipsw/pkg/usb/types"
)

type UsbMuxHeader struct {
	Length  uint32
	Version uint32
	Request uint32
	Tag     uint32
}

type UsbMuxResponse struct {
	MessageType string
	Number      uint32
}

func (u UsbMuxResponse) IsSuccessFull() bool {
	return u.Number == 0
}

var sizeOfHeader = uint32(binary.Size(UsbMuxHeader{}))

type USBConnection struct {
	c   net.Conn
	ssl *tls.Conn
	ldc *lockdown.Client

	devs []types.Device
	pair types.PairRecord

	tag           uint32
	clientVersion string
	sess          string
}

func NewConnection(version string) (*USBConnection, error) {
	c, err := net.Dial("unix", types.UsbMuxAddress)
	if err != nil {
		return nil, err
	}
	return &USBConnection{
		c:             c,
		clientVersion: fmt.Sprintf("%s-%s", types.ProgName, version),
		tag:           0,
	}, nil
}

func (u *USBConnection) Close() error {
	return u.c.Close()
}

func (u *USBConnection) Refresh() error {
	if err := u.c.Close(); err != nil {
		return err
	}
	c, err := net.Dial("unix", types.UsbMuxAddress)
	if err != nil {
		return err
	}
	u.c = c
	return nil
}

func (u *USBConnection) ListDevices() ([]types.Device, error) {

	data, err := plist.Marshal(types.ReadDevicesType{
		MessageType:         "ListDevices",
		BundleID:            types.BundleID,
		ProgName:            types.ProgName,
		ClientVersionString: u.clientVersion,
		LibUSBMuxVersion:    3,
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

	// ioutil.WriteFile("dev_list.plist", payload, 0664)

	type DeviceList struct {
		DeviceList []types.Device
	}

	deviceList := DeviceList{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&deviceList); err != nil {
		return nil, err
	}

	u.devs = deviceList.DeviceList

	return u.devs, nil
}

func (u *USBConnection) ReadBUID() (string, error) {

	data, err := plist.Marshal(types.ReadDevicesType{
		MessageType:         "ReadBUID",
		BundleID:            types.BundleID,
		ProgName:            types.ProgName,
		ClientVersionString: u.clientVersion,
		LibUSBMuxVersion:    3,
	}, plist.XMLFormat)
	if err != nil {
		return "", err
	}

	u.tag++

	if err := binary.Write(u.c, binary.LittleEndian, UsbMuxHeader{
		Length:  sizeOfHeader + uint32(len(data)),
		Request: 8,
		Version: 1,
		Tag:     u.tag,
	}); err != nil {
		return "", err
	}
	n, err := u.c.Write(data)
	if n < len(data) {
		return "", fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return "", err
	}

	var header UsbMuxHeader
	if err := binary.Read(u.c, binary.LittleEndian, &header); err != nil {
		return "", err
	}
	payload := make([]byte, header.Length-sizeOfHeader)
	if _, err = io.ReadFull(u.c, payload); err != nil {
		return "", err
	}

	// ioutil.WriteFile("dev_buid.plist", payload, 0664)

	reply := struct {
		BUID string `plist:"BUID"`
	}{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&reply); err != nil {
		return "", err
	}

	return reply.BUID, nil
}

type connectMessage struct {
	BundleID            string
	ClientVersionString string
	MessageType         string
	ProgName            string
	LibUSBMuxVersion    uint32 `plist:"kLibUSBMuxVersion"`
	DeviceID            uint32
	PortNumber          uint16
}

func (u *USBConnection) ConnectLockdown(dev types.Device) (*lockdown.Client, error) {

	data, err := plist.Marshal(connectMessage{
		BundleID:            types.BundleID,
		ProgName:            types.ProgName,
		ClientVersionString: u.clientVersion,
		MessageType:         "Connect",
		LibUSBMuxVersion:    3,
		DeviceID:            uint32(dev.DeviceID),
		PortNumber:          lockdown.Port,
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
	_, err = u.c.Write(data)
	// if n < len(data) {
	// 	return nil, fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	// }
	if err != nil {
		return nil, err
	}

	var header UsbMuxHeader
	if err := binary.Read(u.c, binary.LittleEndian, &header); err != nil {
		return nil, err
	}
	u.tag = header.Tag
	payload := make([]byte, header.Length-sizeOfHeader)
	if _, err = io.ReadFull(u.c, payload); err != nil {
		return nil, err
	}

	resp := UsbMuxResponse{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&resp); err != nil {
		return nil, err
	}

	if !resp.IsSuccessFull() {
		return nil, fmt.Errorf("failed to connect to lockdown service: %v", resp)
	}

	// pair, err := u.GetPair(dev)
	// if err != nil {
	// 	return nil, err
	// }

	u.ldc = lockdown.NewClient(u.c, dev, types.PairRecord{})

	return u.ldc, nil
}
