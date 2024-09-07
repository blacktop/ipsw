package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"time"

	"github.com/blacktop/go-plist"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName      = "com.apple.pcapd"
	TcpdumpMagic     = 0xa1b2c3d4
	VersionMajor     = 2
	VersionMinor     = 4
	LinkTypeEthernet = 1
	LinkTypeRaw      = 101
)

var ethernetHeader = []byte{0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0x08, 0x00}

type GlobalHeader struct {
	MagicNumber  uint32 // magic number
	VersionMajor uint16 // major version number
	VersionMinor uint16 // minor version number
	Thiszone     int32  // GMT to local correction
	Sigfigs      uint32 // accuracy of timestamps
	Snaplen      uint32 // max length of captured packets, in octets
	Network      uint32 // data link type
}

type PacketHeader struct {
	TimestampSecs      uint32 // timestamp seconds
	TimestampMicroSecs uint32 // timestamp microseconds
	InclLength         uint32 // number of octets of packet saved in file
	OrigLength         uint32 // actual length of packet
}

type IOSPacketHeader struct {
	HdrLength       uint32
	HdrVersion      uint8
	PktLength       uint32
	InterfaceType   iface
	Unit            uint16
	IO              uint8
	ProtocolFamily  protocolFamily
	FramePreLength  uint32
	FramePostLength uint32
	InterfaceName   [16]byte
	Pid             uint32 // little endian
	ProcName        [17]byte
	Svc             uint32 // little endian TODO: map this to name
	SubPid          uint32 // little endian
	SubProcName     [17]byte
	Seconds         uint32
	MicroSeconds    uint32
}

type Client struct {
	c *usb.Client
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		c: c,
	}, nil
}

// TODO: look at tools/idevicebtlogger.c for ideas on how to properly construct PCAP header (missing directionality)
func (c *Client) ReadPacket(ctx context.Context, procName string, wr io.Writer, dump func(IOSPacketHeader, []byte)) error {

	header := GlobalHeader{
		MagicNumber:  TcpdumpMagic,
		VersionMajor: VersionMajor,
		VersionMinor: VersionMinor,
		Thiszone:     0,
		Sigfigs:      0,
		Snaplen:      uint32(65535),
		Network:      uint32(LinkTypeEthernet),
	}

	if err := binary.Write(wr, binary.LittleEndian, header); err != nil {
		return err
	}

	stoped := false
	go func() {
		<-ctx.Done()
		stoped = true
	}()

	for {
		bs, err := c.c.RecvBytes()
		if err != nil {
			return err
		}

		var data []byte
		_, err = plist.Unmarshal(bs, &data)
		if err != nil {
			return err
		}

		buf := bytes.NewReader(data)
		var hdr IOSPacketHeader
		if err := binary.Read(buf, binary.BigEndian, &hdr); err != nil {
			return err
		}

		if len(procName) > 0 {
			pName := strings.TrimSpace(string(hdr.ProcName[:]))
			subName := strings.TrimSpace(string(hdr.SubProcName[:]))
			if !strings.HasPrefix(pName, procName) && !strings.HasPrefix(subName, procName) {
				continue
			}
		}

		if dump != nil {
			go dump(hdr, data)
		}

		pphdr := PacketHeader{
			TimestampSecs:      uint32(time.Now().Unix()),
			TimestampMicroSecs: uint32(time.Now().UnixNano() / 1e6),
			InclLength:         hdr.PktLength,
			OrigLength:         hdr.PktLength,
		}
		if err := binary.Write(wr, binary.LittleEndian, pphdr); err != nil {
			return err
		}

		if hdr.FramePreLength == 0 {
			ext := ethernetHeader
			body := append(ext, data[hdr.HdrLength:]...)
			err = binary.Write(wr, binary.LittleEndian, body)
		} else {
			err = binary.Write(wr, binary.LittleEndian, data[hdr.HdrLength:])
		}

		if err != nil {
			return err
		}

		if stoped {
			break
		}
	}

	return nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
