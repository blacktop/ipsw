package usb

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/blacktop/go-plist"
)

const (
	progName             = "ipsw"
	bundleID             = "io.blacktop.ipsw"
	usbMuxAddress        = "/var/run/usbmuxd"
	lockdownPort  uint16 = 32498
)

var sizeOfHeader = uint32(binary.Size(UsbMuxHeader{}))

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

type USBConnection struct {
	c   net.Conn
	ssl *tls.Conn

	pair PairRecord
	tag  uint32

	devs []Device

	clientVersion string
	sess          string
}

func NewConnection(version string) (*USBConnection, error) {
	c, err := net.Dial("unix", usbMuxAddress)
	if err != nil {
		return nil, err
	}
	return &USBConnection{
		c:             c,
		clientVersion: fmt.Sprintf("%s-%s", progName, version),
		tag:           0,
	}, nil
}

func (u *USBConnection) Close() error {
	return u.c.Close()
}

type readDevicesType struct {
	MessageType         string
	BundleID            string
	ProgName            string
	ClientVersionString string
	LibUSBMuxVersion    int
}

type Device struct {
	MessageType string
	DeviceID    int
	Properties  DeviceProperties
}

type DeviceProperties struct {
	DeviceID        int
	ConnectionType  string
	ConnectionSpeed int
	ProductID       int
	LocationID      int
	SerialNumber    string
	UDID            string
	USBSerialNumber string
}

func (u *USBConnection) ListDevices() ([]Device, error) {

	data, err := plist.Marshal(readDevicesType{
		MessageType:         "ListDevices",
		BundleID:            bundleID,
		ProgName:            progName,
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
		DeviceList []Device
	}

	deviceList := DeviceList{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&deviceList); err != nil {
		return nil, err
	}

	u.devs = deviceList.DeviceList

	return u.devs, nil
}

func (u *USBConnection) ReadBUID() (string, error) {

	data, err := plist.Marshal(readDevicesType{
		MessageType:         "ReadBUID",
		BundleID:            bundleID,
		ProgName:            progName,
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

func (u *USBConnection) ConnectLockdown(dev Device) error {

	data, err := plist.Marshal(connectMessage{
		BundleID:            bundleID,
		ClientVersionString: u.clientVersion,
		ProgName:            progName,
		MessageType:         "Connect",
		LibUSBMuxVersion:    3,
		DeviceID:            uint32(dev.DeviceID),
		PortNumber:          lockdownPort,
	}, plist.XMLFormat)
	if err != nil {
		return err
	}

	u.tag++

	if err := binary.Write(u.c, binary.LittleEndian, UsbMuxHeader{
		Length:  sizeOfHeader + uint32(len(data)),
		Request: 8,
		Version: 1,
		Tag:     u.tag,
	}); err != nil {
		return err
	}
	n, err := u.c.Write(data)
	if n < len(data) {
		return fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return err
	}

	var header UsbMuxHeader
	if err := binary.Read(u.c, binary.LittleEndian, &header); err != nil {
		return err
	}
	u.tag = header.Tag
	payload := make([]byte, header.Length-sizeOfHeader)
	if _, err = io.ReadFull(u.c, payload); err != nil {
		return err
	}

	resp := UsbMuxResponse{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&resp); err != nil {
		return err
	}

	if !resp.IsSuccessFull() {
		return fmt.Errorf("failed to connect to lockdown service: %v", resp)
	}

	return nil
}
