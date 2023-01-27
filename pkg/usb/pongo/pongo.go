package pongo

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/apex/log"
	"github.com/google/gousb"
)

const (
	PONGO_USB_VENDOR  = 0x05ac
	PONGO_USB_PRODUCT = 0x4141
)

type Client struct {
	dev *gousb.Device
}

func NewClient() (*Client, error) {
	ctx := gousb.NewContext()
	defer ctx.Close()

	devs, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		if desc.Vendor == PONGO_USB_VENDOR && desc.Product == PONGO_USB_PRODUCT {
			dev, err := ctx.OpenDeviceWithVIDPID(desc.Vendor, desc.Product)
			if err != nil {
				log.Fatalf("Could not open a device: %v", err)
			}
			man, _ := dev.Manufacturer()
			prod, _ := dev.Product()
			log.WithFields(log.Fields{
				"vendor":  man,
				"product": prod,
			}).Debug("Found USB Device")
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}

	if len(devs) == 0 {
		return nil, fmt.Errorf("no 'pongoOS' devices found")
	}

	return &Client{
		dev: devs[0],
	}, nil
}

func (c *Client) Close() error {
	return c.dev.Close()
}

func (c *Client) SendCommand(cmd string) error {
	if n, err := c.dev.Control(0x21, 3, 0, 0, []byte(cmd+"\n")); err != nil {
		return fmt.Errorf("%s.Control(%s): %v", c.dev, cmd, err)
	} else if n != len(cmd)+1 {
		return fmt.Errorf("%s.Control(%s): %d bytes written, want %d", c.dev, cmd, n, len(cmd)+1)
	}
	return nil
}

func encodeUint32(x uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, x)
	return buf[bits.LeadingZeros32(x)>>3:]
}

func (c *Client) GetStdOut() (string, error) {
	var out string

	progress := []byte{1}
	bbuf := make([]byte, 0x1000)

	for progress[0] == 1 {
		if _, err := c.dev.Control(0xa1, 2, 0, 0, progress); err != nil {
			return "", fmt.Errorf("%s.Control(%s): %v", c.dev, "get stdout", err)
		}

		n, err := c.dev.Control(0xa1, 1, 0, 0, bbuf)
		if err != nil {
			return "", fmt.Errorf("%s.Control(%s): %v", c.dev, "get stdout", err)
		}

		if n == 0 {
			break
		}

		out += string(bbuf[:n])
	}

	return out, nil
}
