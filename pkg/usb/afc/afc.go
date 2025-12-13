package afc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

type AfcOp int

const (
	serviceName = "com.apple.afc"
	headerSize  = 40

	MODEMASK = 0777

	afcESuccess             = 0
	afcEUnknownError        = 1
	afcEOpHeaderInvalid     = 2
	afcENoResources         = 3
	afcEReadError           = 4
	afcEWriteError          = 5
	afcEUnknownPacketType   = 6
	afcEInvalidArg          = 7
	afcEObjectNotFound      = 8
	afcEObjectIsDir         = 9
	afcEPermDenied          = 10
	afcEServiceNotConnected = 11
	afcEOpTimeout           = 12
	afcETooMuchData         = 13
	afcEEndOfData           = 14
	afcEOpNotSupported      = 15
	afcEObjectExists        = 16
	afcEObjectBusy          = 17
	afcENoSpaceLeft         = 18
	afcEOpWouldBlock        = 19
	afcEIoError             = 20
	afcEOpInterrupted       = 21
	afcEOpInProgress        = 22
	afcEInternalError       = 23

	afcEMuxError      = 30
	afcENoMem         = 31
	afcENotEnoughData = 32
	afcEDirNotEmpty   = 33

	afcFOpenRdonly   = 0x00000001 /* O_RDONLY */
	afcFOpenRw       = 0x00000002 /* O_RDWR   | O_CREAT */
	afcFOpenWronly   = 0x00000003 /* O_WRONLY | O_CREAT  | O_TRUNC */
	afcFOpenWr       = 0x00000004 /* O_RDWR   | O_CREAT  | O_TRUNC */
	afcFOpenAppend   = 0x00000005 /* O_WRONLY | O_APPEND | O_CREAT */
	afcFOpenRdAppend = 0x00000006 /* O_RDWR   | O_APPEND | O_CREAT */

	afcHardlink = 1
	afcSymlink  = 2

	afcLockSh = 1 | 4 /* shared lock */
	afcLockEx = 2 | 4 /* exclusive lock */
	afcLockUn = 8 | 4 /* unlock */

	afcMagic = "CFA6LPAA"
)

var (
	errorsToErrors = map[uint64]error{
		afcEUnknownError:        errors.New("unknown error"),
		afcEOpHeaderInvalid:     errors.New("invalid operation header"),
		afcENoResources:         errors.New("no resources"),
		afcEReadError:           errors.New("read error"),
		afcEWriteError:          errors.New("write error"),
		afcEUnknownPacketType:   errors.New("unknown packet type"),
		afcEInvalidArg:          errors.New("invalid argument"),
		afcEObjectNotFound:      errors.New("object not found"),
		afcEObjectIsDir:         errors.New("object is a directory"),
		afcEPermDenied:          errors.New("permission denied"),
		afcEServiceNotConnected: errors.New("service not connected"),
		afcEOpTimeout:           errors.New("operation timeout"),
		afcETooMuchData:         errors.New("too much data"),
		afcEEndOfData:           io.EOF,
		afcEOpNotSupported:      errors.New("operation not supported"),
		afcEObjectExists:        errors.New("object exists"),
		afcEObjectBusy:          errors.New("object busy"),
		afcENoSpaceLeft:         errors.New("no space left"),
		afcEOpWouldBlock:        errors.New("operation would block"),
		afcEIoError:             errors.New("io error"),
		afcEOpInterrupted:       errors.New("operation interrupted"),
		afcEOpInProgress:        errors.New("operation in progress"),
		afcEInternalError:       errors.New("internal error"),
	}
)

type Client struct {
	mu        *sync.RWMutex
	c         *usb.Client
	packetNum uint64
}

type Header struct {
	Magic        [8]byte
	EntireLength uint64
	ThisLength   uint64
	PacketNum    uint64
	Operation    uint64
}

func openFlagsToAfcFlags(flags int) uint64 {
	switch flags {
	case os.O_RDONLY:
		return afcFOpenRdonly
	case os.O_RDWR | os.O_CREATE:
		return afcFOpenRw
	case os.O_WRONLY | os.O_CREATE | os.O_TRUNC:
		return afcFOpenWronly
	case os.O_RDWR | os.O_CREATE | os.O_TRUNC:
		return afcFOpenWr
	case os.O_WRONLY | os.O_APPEND | os.O_CREATE:
		return afcFOpenAppend
	case os.O_RDWR | os.O_APPEND | os.O_CREATE:
		return afcFOpenRdAppend
	default:
		panic(fmt.Errorf("unsuported file mode %v", flags))
	}
}

func encodeArgs(args ...any) []byte {
	ret := make([]byte, 0)
	for _, arg := range args {
		switch v := arg.(type) {
		case uint16:
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, v)
			ret = append(ret, b...)
		case uint32:
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, v)
			ret = append(ret, b...)
		case uint64:
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, v)
			ret = append(ret, b...)
		case string:
			ret = append(ret, []byte(v)...)
			ret = append(ret, 0)
		case []byte:
			ret = append(ret, v...)
		default:
			panic(fmt.Errorf("invalid argument type %v", reflect.TypeOf(v)))
		}
	}
	return ret
}

func decodeStringList(data []byte) []string {
	ret := strings.Split(string(data), "\x00")
	return ret[:len(ret)-1]
}

func listToDict(kv []string) map[string]string {
	if len(kv)%2 != 0 {
		panic(fmt.Errorf("number of items for list to dict should be a multiple of 2"))
	}
	ret := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		ret[kv[i]] = kv[i+1]
	}
	return ret
}

func NewClient(udid string, service ...string) (*Client, error) {
	afcServiceName := serviceName
	if len(service) > 0 {
		afcServiceName = service[0]
	}
	c, err := lockdownd.NewClientForService(afcServiceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		c:  c,
		mu: &sync.RWMutex{},
	}, nil
}

func (c *Client) request(operation int, payload []byte, args ...any) (*response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestNoLock(operation, payload, args...)
}

func (c *Client) requestNoLock(operation int, payload []byte, args ...any) (*response, error) {
	if err := c.sendRequest(operation, payload, args...); err != nil {
		return nil, err
	}
	return c.recvResponse()
}

func (c *Client) requestNoReply(operation int, payload []byte, args ...any) error {
	_, err := c.request(operation, payload, args...)
	return err
}

func (c *Client) requestStringList(operation int, payload []byte, args ...any) ([]string, error) {
	resp, err := c.request(operation, payload, args...)
	if err != nil {
		return nil, err
	}
	return decodeStringList(resp.payload), nil
}

func (c *Client) sendHeader(operation int, args []byte, payload []byte) error {
	hdr := &Header{
		EntireLength: headerSize + uint64(len(args)) + uint64(len(payload)),
		ThisLength:   headerSize + uint64(len(args)),
		PacketNum:    atomic.AddUint64(&c.packetNum, 1),
		Operation:    uint64(operation),
	}
	copy(hdr.Magic[:8], []byte(afcMagic))
	return binary.Write(c.c.Conn(), binary.LittleEndian, hdr)
}

func (c *Client) recvHeader() (*Header, error) {
	hdr := &Header{}
	if err := binary.Read(c.c.Conn(), binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

type response struct {
	operation   uint64
	payloadSize uint64
	data        []byte
	payload     []byte
}

func (c *Client) recvResponseBase() (*response, error) {
	hdr, err := c.recvHeader()
	if err != nil {
		return nil, err
	}
	resp := &response{
		operation:   hdr.Operation,
		payloadSize: hdr.EntireLength - hdr.ThisLength,
	}
	toRead := hdr.ThisLength - headerSize
	if toRead == 0 {
		return resp, nil
	}
	resp.data = make([]byte, toRead)
	if _, err := io.ReadFull(c.c.Conn(), resp.data); err != nil {
		return nil, err
	}
	if hdr.Operation == afcOpStatus {
		code := binary.LittleEndian.Uint64(resp.data)
		err = errorsToErrors[code]
	}
	return resp, err
}

func (c *Client) recvResponse() (*response, error) {
	resp, err := c.recvResponseBase()
	if err != nil {
		return nil, err
	}
	if resp.payloadSize == 0 {
		return resp, nil
	}
	resp.payload = make([]byte, resp.payloadSize)
	if _, err := io.ReadFull(c.c.Conn(), resp.payload); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) recvResponseTo(payloadBuf []byte) (*response, error) {
	resp, err := c.recvResponseBase()
	if err != nil {
		return nil, err
	}
	if resp.payloadSize == 0 {
		return resp, nil
	}
	if resp.payloadSize > uint64(len(payloadBuf)) {
		return nil, fmt.Errorf("buffer is %d, needs %d", len(payloadBuf), resp.payloadSize)
	}
	if _, err = io.ReadFull(c.c.Conn(), payloadBuf[:resp.payloadSize]); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) sendRequest(operation int, payload []byte, args ...any) error {
	argsData := encodeArgs(args...)
	if err := c.sendHeader(operation, argsData, payload); err != nil {
		return err
	}
	if _, err := c.c.Conn().Write(argsData); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := c.c.Conn().Write(payload)
		return err
	}
	return nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
