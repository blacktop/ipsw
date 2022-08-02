package lockdown

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/usb/types"
)

const (
	protocolVersion        = "2"
	Port            uint16 = 32498
)

type RequestType string

const (
	RequestTypeQueryType     RequestType = "QueryType"
	RequestTypeSetValue      RequestType = "SetValue"
	RequestTypeGetValue      RequestType = "GetValue"
	RequestTypePair          RequestType = "Pair"
	RequestTypeEnterRecovery RequestType = "EnterRecovery"
	RequestTypeStartSession  RequestType = "StartSession"
	RequestTypeStopSession   RequestType = "StopSession"
	RequestTypeStartService  RequestType = "StartService"
)

type LockdownBasicResponse struct {
	Request string `plist:"Request"`
	Error   string `plist:"Error"`
}

type LockdownValueResponse struct {
	LockdownBasicResponse
	Key   string      `plist:"Key"`
	Value interface{} `plist:"Value"`
}

type startServiceRequest struct {
	Label   string
	Request string
	Service string
}

type StartServiceResponse struct {
	Port             uint16
	Request          string
	Service          string
	EnableServiceSSL bool
	Error            string
}

type startSessionRequest struct {
	Label           string
	ProtocolVersion string
	Request         string
	HostID          string
	SystemBUID      string
}

type StartSessionResponse struct {
	EnableSessionSSL bool
	Request          string
	SessionID        string
}

type stopSessionRequest struct {
	Label           string
	ProtocolVersion string
	Request         string
	SessionID       string
}

type Client struct {
	c    net.Conn
	dev  types.Device
	pair types.PairRecord
	sess string
}

func NewClient(c net.Conn, dev types.Device, pair types.PairRecord) *Client {
	return &Client{c: c, dev: dev, pair: pair}
}

func (ld *Client) StartSession() error {

	data, err := plist.Marshal(startSessionRequest{
		Label:           types.BundleID,
		ProtocolVersion: protocolVersion,
		Request:         "StartSession",
		HostID:          ld.pair.HostID,
		SystemBUID:      ld.pair.SystemBUID,
	}, plist.XMLFormat)
	if err != nil {
		return err
	}

	if err := ld.SendData(data); err != nil {
		return fmt.Errorf("failed to send lockdown start session request: %v", err)
	}

	resp := &StartSessionResponse{}
	if err := ld.ReadData(resp); err != nil {
		return fmt.Errorf("failed to read lockdown start session response: %v", err)
	}

	ld.sess = resp.SessionID

	if resp.EnableSessionSSL {
		if err := ld.StopSession(); err != nil {
			return fmt.Errorf("failed to stop lockdown session: %v", err)
		}
		// FIXME: re-start usbmuxd session ?
		cert, err := tls.X509KeyPair(ld.pair.HostCertificate, ld.pair.HostPrivateKey)
		if err != nil {
			return err
		}
		tlsConn := tls.Server(ld.c, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
			// ClientAuth:         tls.NoClientCert,
			MinVersion: tls.VersionTLS11,
			MaxVersion: tls.VersionTLS13,
		})
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("failed to perfrom tls handshake: %v", err)
		}
		ld.c = net.Conn(tlsConn)
	}

	return nil
}

func (ld *Client) StopSession() error {

	data, err := plist.Marshal(stopSessionRequest{
		Label:           types.BundleID,
		ProtocolVersion: protocolVersion,
		Request:         "StopSession",
		SessionID:       ld.sess,
	}, plist.XMLFormat)
	if err != nil {
		return err
	}

	if err := ld.SendData(data); err != nil {
		return fmt.Errorf("failed to send lockdown start session request: %v", err)
	}

	// resp := &LockdownBasicResponse{}
	// if err := u.LockDownRead(resp); err != nil {
	// 	return fmt.Errorf("failed to read lockdown start session response: %v", err)
	// }

	// if resp.Error != "" {
	// 	return fmt.Errorf(resp.Error)
	// }

	ld.sess = ""

	return nil
}

func (ld *Client) StartService(service string) (*StartServiceResponse, error) {

	if err := ld.StartSession(); err != nil {
		return nil, err
	}

	data, err := plist.Marshal(startServiceRequest{
		Label:   types.BundleID,
		Request: "StartService",
		Service: service,
	}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	if err := ld.SendData(data); err != nil {
		return nil, fmt.Errorf("failed to send lockdown start service request: %v", err)
	}

	resp := &StartServiceResponse{}
	if err := ld.ReadData(resp); err != nil {
		return nil, fmt.Errorf("failed to read lockdown start service response: %v", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf(resp.Error)
	}

	return resp, nil
}

func (ld *Client) SendData(data []byte) error {
	buf := new(bytes.Buffer)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	// build packet
	buf.Write(b)
	buf.Write(data)

	n, err := ld.c.Write(buf.Bytes())
	if n < len(data) {
		return fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return fmt.Errorf("failed to send lockdown packet: %v", err)
	}

	return nil
}

func (ld *Client) ReadData(obj any) error {
	var length uint32
	if err := binary.Read(ld.c, binary.BigEndian, &length); err != nil {
		return err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(ld.c, payload); err != nil {
		return err
	}

	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(obj); err != nil {
		return err
	}

	return nil
}
