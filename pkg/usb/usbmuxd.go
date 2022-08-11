package usb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/blacktop/go-plist"
	"github.com/fatih/color"
)

const (
	ProgName            = "ipsw"
	BundleID            = "io.blacktop.ipsw"
	ClientVersionString = "ipsw-usbmux-0.0.1"
)

var colorFaint = color.New(color.Faint, color.FgHiBlue).SprintFunc()
var colorBold = color.New(color.Bold).SprintFunc()

type Header struct {
	Length      uint32
	Version     uint32
	MessageType uint32
	Tag         uint32
}

var HeaderSize = uint32(binary.Size(Header{}))

type Conn struct {
	net.Conn
	tag uint32
}

func NewConn() (*Conn, error) {
	conn, err := usbmuxdDial()
	if err != nil {
		return nil, err
	}

	return &Conn{Conn: conn}, nil
}

type ResultValue int

const (
	ResultValueOK ResultValue = iota
	ResultValueBadCommand
	ResultValueBadDevice
	ResultValueConnectionRefused
	ResultValueConnectionUnknown1
	ResultValueConnectionUnknown2
	ResultValueBadVersion
)

type connectMessage struct {
	BundleID            string
	ClientVersionString string
	MessageType         string
	ProgName            string
	LibUSBMuxVersion    uint32 `plist:"kLibUSBMuxVersion"`
	DeviceID            uint32
	PortNumber          uint16
}

type resultResponse struct {
	Number ResultValue
}

func (c *Conn) Dial(deviceId, port int) error {
	req := &connectMessage{
		BundleID:            BundleID,
		ClientVersionString: ClientVersionString,
		MessageType:         "Connect",
		ProgName:            ProgName,
		LibUSBMuxVersion:    3,
		DeviceID:            uint32(deviceId),
		PortNumber:          htonl(uint16(port)),
	}
	var resp resultResponse
	if err := c.Request(req, &resp); err != nil {
		return err
	}

	if resp.Number == ResultValueConnectionRefused {
		return syscall.ECONNREFUSED
	}

	return nil
}

type listDevicesRequest struct {
	MessageType         string
	ProgName            string
	ClientVersionString string
}

type listDevicesResponse struct {
	DeviceList []*DeviceAttached
}

type DeviceAttached struct {
	MessageType string
	DeviceID    int
	Properties  *DeviceAttachment
}

type DeviceAttachment struct {
	ConnectionSpeed int
	ConnectionType  string
	DeviceID        int
	LocationID      int
	ProductID       int
	SerialNumber    string
	UDID            string
	USBSerialNumber string
}

func (d DeviceAttachment) String() string {
	return fmt.Sprintf(
		colorFaint("DeviceID: ")+colorBold("%d\n")+
			colorFaint("    ConnectionType:  ")+colorBold("%s\n")+
			colorFaint("    ConnectionSpeed: ")+colorBold("%d\n")+
			colorFaint("    ProductID:       ")+colorBold("%#x\n")+
			colorFaint("    LocationID:      ")+colorBold("%d\n")+
			colorFaint("    SerialNumber:    ")+colorBold("%s\n")+
			colorFaint("    UDID:            ")+colorBold("%s\n")+
			colorFaint("    USBSerialNumber: ")+colorBold("%s\n"),
		d.DeviceID,
		d.ConnectionType,
		d.ConnectionSpeed,
		d.ProductID,
		d.LocationID,
		d.SerialNumber,
		d.UDID,
		d.USBSerialNumber,
	)
}

func (c *Conn) ListDevices() ([]*DeviceAttachment, error) {
	req := &listDevicesRequest{
		MessageType:         "ListDevices",
		ProgName:            ProgName,
		ClientVersionString: ClientVersionString,
	}
	var resp listDevicesResponse
	if err := c.Request(req, &resp); err != nil {
		return nil, err
	}

	devices := make([]*DeviceAttachment, 0, len(resp.DeviceList))
	for _, device := range resp.DeviceList {
		devices = append(devices, device.Properties)
	}

	return devices, nil
}

type PairRecord struct {
	DeviceCertificate []byte
	EscrowBag         []byte
	HostCertificate   []byte
	HostID            string
	HostPrivateKey    []byte
	RootCertificate   []byte
	RootPrivateKey    []byte
	SystemBUID        string
}

type readPairRecordRequest struct {
	BundleID            string
	ClientVersionString string
	ProgName            string
	MessageType         string
	PairRecordID        string `plist:"PairRecordID"`
	LibUSBMuxVersion    uint32 `plist:"kLibUSBMuxVersion"`
}

type readPairRecordResponse struct {
	PairRecordData []byte
}

func (c *Conn) ReadPairRecord(udid string) (*PairRecord, error) {
	req := &readPairRecordRequest{
		BundleID:            BundleID,
		MessageType:         "ReadPairRecord",
		ClientVersionString: ClientVersionString,
		ProgName:            ProgName,
		PairRecordID:        udid,
		LibUSBMuxVersion:    3,
	}
	var resp readPairRecordResponse
	if err := c.Request(req, &resp); err != nil {
		return nil, err
	}

	var record PairRecord
	if _, err := plist.Unmarshal(resp.PairRecordData, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

func (c *Conn) Request(req, resp any) error {
	if err := c.Send(req); err != nil {
		return err
	}

	return c.Recv(resp)
}

func (c *Conn) Send(msg any) error {
	data, err := plist.Marshal(msg, plist.XMLFormat)
	if err != nil {
		return err
	}

	hdr := &Header{
		Length:      uint32(len(data)) + HeaderSize,
		Version:     1,
		MessageType: 8, // plist
		Tag:         atomic.AddUint32(&c.tag, 1),
	}
	if err := binary.Write(c, binary.LittleEndian, hdr); err != nil {
		return err
	}

	return binary.Write(c, binary.LittleEndian, data)
}

func (c *Conn) Recv(msg any) error {
	var hdr Header
	if err := binary.Read(c, binary.LittleEndian, &hdr); err != nil {
		return err
	}

	data := make([]byte, hdr.Length-HeaderSize)
	if _, err := io.ReadFull(c, data); err != nil {
		return err
	}

	if _, err := plist.Unmarshal(data, msg); err != nil {
		return err
	}

	return nil
}

func htonl(v uint16) uint16 {
	return (v << 8 & 0xFF00) | (v >> 8 & 0xFF)
}
