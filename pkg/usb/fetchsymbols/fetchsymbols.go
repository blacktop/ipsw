package fetchsymbols

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.dt.fetchsymbols"
)

var (
	ListFilesPlistRequest uint32 = 0x30303030
	GetFileRequest        uint32 = 0x00000001
)

type ListFilesResponse struct {
	Version uint64   `plist:"version,omitempty"`
	Files   []string `plist:"files,omitempty"`
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

func (c *Client) ListFiles() ([]string, error) {
	if err := c.sendCommand(c.c.Conn(), ListFilesPlistRequest); err != nil {
		return nil, err
	}
	var resp ListFilesResponse
	if err := c.c.Recv(&resp); err != nil {
		return nil, err
	}
	return resp.Files, nil
}

func (c *Client) GetFile(idx uint32) (io.Reader, error) {
	if err := c.sendCommand(c.c.Conn(), GetFileRequest); err != nil {
		return nil, err
	}
	size := uint64(0)
	if err := c.sendRecv(c.c.Conn(), idx, &size); err != nil {
		return nil, err
	}
	return io.LimitReader(c.c.Conn(), int64(size)), nil
}

func (c *Client) sendRecv(rw io.ReadWriter, req, resp any) error {
	if err := binary.Write(rw, binary.BigEndian, req); err != nil {
		return err
	}
	return binary.Read(rw, binary.BigEndian, resp)
}

func (c *Client) sendCommand(rw io.ReadWriter, cmd uint32) error {
	respCmd := uint32(0)
	if err := c.sendRecv(rw, cmd, &respCmd); err != nil {
		return fmt.Errorf("failed to send fetchsymbols command: %v", err)
	}
	if respCmd != cmd {
		return fmt.Errorf("invalid response: wanted %v, got %v", cmd, respCmd)
	}
	return nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
