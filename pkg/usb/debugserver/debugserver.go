package debugserver

import (
	"net"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

type Client struct {
	c         *usb.Client
	gdbServer *GDBServer
}

func NewClient(udid string) (*Client, error) {
	cli, err := lockdownd.NewClientForService("com.apple.debugserver", udid, false)
	if err != nil {
		return nil, err
	}

	cli.DisableSSL()

	return &Client{
		c:         cli,
		gdbServer: NewGDBServer(cli.Conn()),
	}, nil
}

func (c *Client) Recv() (string, error) {
	return c.gdbServer.Recv()
}

func (c *Client) Send(req string) error {
	return c.gdbServer.Send(req)
}

func (c *Client) Request(req string) (string, error) {
	return c.gdbServer.Request(req)
}

func (c *Client) Conn() net.Conn {
	return c.c.Conn()
}

func (c *Client) Close() error {
	return c.c.Close()
}
