package usb

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/blacktop/go-plist"
)

type Client struct {
	tlsConn    *tls.Conn
	conn       net.Conn
	udid       string
	deviceID   int
	pairRecord *PairRecord
}

func NewClient(udid string, port int) (*Client, error) {
	conn, err := NewConn()
	if err != nil {
		return nil, err
	}

	pairRecord, err := conn.ReadPairRecord(udid)
	if err != nil {
		return nil, err
	}

	devices, err := conn.ListDevices()
	if err != nil {
		return nil, err
	}

	deviceID := -1
	for _, device := range devices {
		if device.UDID == udid {
			deviceID = device.DeviceID
			break
		}
	}

	if deviceID < 0 {
		return nil, fmt.Errorf("unable to find device with udid: %v", udid)
	}

	if err := conn.Dial(deviceID, port); err != nil {
		return nil, err
	}

	return &Client{
		conn:       conn,
		pairRecord: pairRecord,
		udid:       udid,
		deviceID:   deviceID,
	}, nil
}

func (c *Client) EnableSSL() error {
	cert, err := tls.X509KeyPair(c.pairRecord.HostCertificate, c.pairRecord.HostPrivateKey)
	if err != nil {
		return err
	}

	c.tlsConn = tls.Client(c.conn, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	if err := c.tlsConn.Handshake(); err != nil {
		return err
	}

	return nil
}

func (c *Client) DisableSSL() {
	c.tlsConn = nil
}

func (c *Client) Request(req, resp any) error {
	if err := c.Send(req); err != nil {
		return err
	}

	return c.Recv(resp)
}

func (c *Client) Send(req any) error {
	data, err := plist.Marshal(req, plist.XMLFormat)
	if err != nil {
		return err
	}

	if err := binary.Write(c.Conn(), binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}

	return binary.Write(c.Conn(), binary.BigEndian, data)
}

func (c Client) Recv(resp any) error {
	data, err := c.RecvBytes()
	if err != nil {
		return err
	}

	if _, err := plist.Unmarshal(data, resp); err != nil {
		return err
	}

	return nil
}

func (c *Client) RecvBytes() ([]byte, error) {
	size := uint32(0)
	if err := binary.Read(c.Conn(), binary.BigEndian, &size); err != nil {
		return nil, err
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(c.Conn(), data); err != nil {
		return nil, err
	}

	return data, nil
}

func (c *Client) RecvByte() (byte, error) {
	var b byte
	if err := binary.Read(c.Conn(), binary.BigEndian, &b); err != nil {
		return byte(0), err
	}
	return b, nil
}

func (c *Client) UDID() string {
	return c.udid
}

func (c *Client) DeviceID() int {
	return c.deviceID
}

func (c *Client) Conn() net.Conn {
	if c.tlsConn != nil {
		return c.tlsConn
	}

	return c.conn
}

func (c *Client) PairRecord() *PairRecord {
	return c.pairRecord
}

func (c Client) Close() error {
	return c.Conn().Close()
}

func (c *Client) DeviceLinkHandshake() error {
	var versionExchange []any
	if err := c.Recv(&versionExchange); err != nil {
		return err
	}
	reply := []any{"DLMessageVersionExchange", "DLVersionsOk", versionExchange[1]}
	if err := c.Send(reply); err != nil {
		return err
	}
	var ready []any
	return c.Recv(&ready)
}

func (c *Client) DeviceLinkSend(msg any) error {
	return c.Send([]any{"DLMessageProcessMessage", msg})
}

func (c *Client) DeviceLinkRecv() (any, error) {
	var dlMsg []any
	if err := c.Recv(&dlMsg); err != nil {
		return nil, err
	}
	return dlMsg[1], nil
}
