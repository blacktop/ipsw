package lockdown

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"

	"github.com/blacktop/go-plist"
)

const (
	lockdownPort    uint16 = 32498
	protocolVersion        = "2"
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

type LockdownBasicRequest struct {
	Label           string      `plist:"Label"`
	ProtocolVersion string      `plist:"ProtocolVersion"`
	Request         RequestType `plist:"Request"`
}

type LockdownValueRequest struct {
	LockdownBasicRequest
	Domain string      `plist:"Domain,omitempty"`
	Key    string      `plist:"Key,omitempty"`
	Value  interface{} `plist:"Value,omitempty"`
}

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

func (u *USBConnection) StartSession(dev Device) error {

	data, err := plist.Marshal(startSessionRequest{
		Label:           bundleID,
		ProtocolVersion: protocolVersion,
		Request:         "StartSession",
		HostID:          u.pair.HostID,
		SystemBUID:      u.pair.SystemBUID,
	}, plist.XMLFormat)
	if err != nil {
		return err
	}

	if err := u.LockDownSendData(data); err != nil {
		return fmt.Errorf("failed to send lockdown start session request: %v", err)
	}

	resp := &StartSessionResponse{}
	if err := u.LockDownRead(resp); err != nil {
		return fmt.Errorf("failed to read lockdown start session response: %v", err)
	}
	u.sess = resp.SessionID

	if resp.EnableSessionSSL {
		if err := u.StopSession(); err != nil {
			return fmt.Errorf("failed to stop lockdown session: %v", err)
		}
		if err := u.ConnectLockdown(dev); err != nil {
			return err
		}
		cert, err := tls.X509KeyPair(u.pair.HostCertificate, u.pair.HostPrivateKey)
		if err != nil {
			return err
		}
		tlsConn := tls.Server(u.c, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
			// ClientAuth:         tls.NoClientCert,
			MinVersion: tls.VersionTLS11,
			MaxVersion: tls.VersionTLS13,
		})
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("failed to perfrom tls handshake: %v", err)
		}
		u.c = net.Conn(tlsConn)
	}

	return nil
}

func (u *USBConnection) StopSession() error {

	data, err := plist.Marshal(stopSessionRequest{
		Label:           bundleID,
		ProtocolVersion: ProtocolVersion,
		Request:         "StopSession",
		SessionID:       u.sess,
	}, plist.XMLFormat)
	if err != nil {
		return err
	}

	if err := u.LockDownSendData(data); err != nil {
		return fmt.Errorf("failed to send lockdown start session request: %v", err)
	}

	// resp := &LockdownBasicResponse{}
	// if err := u.LockDownRead(resp); err != nil {
	// 	return fmt.Errorf("failed to read lockdown start session response: %v", err)
	// }

	// if resp.Error != "" {
	// 	return fmt.Errorf(resp.Error)
	// }

	u.sess = ""

	return nil
}

func (u *USBConnection) StartService(dev Device, service string) (*StartServiceResponse, error) {

	if err := u.ConnectLockdown(dev); err != nil {
		return nil, err
	}

	if err := u.StartSession(dev); err != nil {
		return nil, err
	}

	data, err := plist.Marshal(startServiceRequest{
		Label:   bundleID,
		Request: "StartService",
		Service: service,
	}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	buf.Write(b)
	buf.Write(data)

	n, err := u.c.Write(buf.Bytes())
	if n < len(data) {
		return nil, fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return nil, err
	}

	var length uint32
	if err := binary.Read(u.c, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err = io.ReadFull(u.c, payload); err != nil {
		return nil, err
	}

	ioutil.WriteFile("dev_service_resp.plist", payload, 0664)

	resp := StartServiceResponse{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

type DeviceDetail struct {
	DeviceName                string
	DeviceColor               string
	DeviceClass               string
	ProductVersion            string
	ProductType               string
	ProductName               string
	ModelNumber               string
	SerialNumber              string
	SIMStatus                 string
	PhoneNumber               string
	CPUArchitecture           string
	ProtocolVersion           string
	RegionInfo                string
	TelephonyCapability       bool
	TimeZone                  string
	UniqueDeviceID            string
	WiFiAddress               string
	WirelessBoardSerialNumber string
	BluetoothAddress          string
	BuildVersion              string
}

func (u *USBConnection) GetValue(dev Device, domain, key string) error {
	c, err := net.Dial("unix", "/var/run/usbmuxd")
	if err != nil {
		return err
	}
	defer c.Close()

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

	if err := binary.Write(c, binary.LittleEndian, UsbMuxHeader{
		Length:  sizeOfHeader + uint32(len(data)),
		Request: 8,
		Version: 1,
		Tag:     u.tag,
	}); err != nil {
		return err
	}
	n, err := c.Write(data)
	if n < len(data) {
		return fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return err
	}

	var header UsbMuxHeader
	if err := binary.Read(c, binary.LittleEndian, &header); err != nil {
		return err
	}
	payload := make([]byte, header.Length-sizeOfHeader)
	if _, err = io.ReadFull(c, payload); err != nil {
		return err
	}

	resp := UsbMuxResponse{}
	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(&resp); err != nil {
		return err
	}

	if resp.IsSuccessFull() {

	}
	fmt.Println(resp)

	return nil

}

func (u *USBConnection) LockDownSendData(data []byte) error {
	buf := new(bytes.Buffer)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	// build packet
	buf.Write(b)
	buf.Write(data)

	n, err := u.c.Write(buf.Bytes())
	if n < len(data) {
		return fmt.Errorf("failed writing %d bytes to usb, only %d sent", len(data), n)
	}
	if err != nil {
		return fmt.Errorf("failed to send lockdown packet: %v", err)
	}

	return nil
}

func (u *USBConnection) LockDownRead(obj any) error {
	var length uint32
	if err := binary.Read(u.c, binary.BigEndian, &length); err != nil {
		return err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(u.c, payload); err != nil {
		return err
	}

	if err := plist.NewDecoder(bytes.NewReader(payload)).Decode(obj); err != nil {
		return err
	}

	return nil
}
