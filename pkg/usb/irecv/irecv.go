package irecv

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/google/gousb"
)

const (
	AppleUSBVendor = 0x5ac
)

type Client struct {
	SDOM string
	CPID string
	CPRV string
	CPFM string
	SCEP string
	BDID string
	ECID string
	IBFL string
	SRNM string

	dev *gousb.Device
}

func NewClient() (*Client, error) {
	ctx := gousb.NewContext()
	defer ctx.Close()

	devs, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		dev, err := ctx.OpenDeviceWithVIDPID(desc.Vendor, desc.Product)
		if err != nil {
			log.Fatalf("Could not open a device: %v", err)
		}
		man, _ := dev.Manufacturer()
		prod, _ := dev.Product()
		log.WithFields(log.Fields{
			"vendor":  man,
			"product": prod,
		}).Debug("USB Device")
		return desc.Vendor == AppleUSBVendor && strings.Contains(prod, "Recovery Mode")
	})
	if err != nil {
		return nil, err
	}

	if len(devs) == 0 {
		return nil, fmt.Errorf("no 'Recovery Mode' devices found")
	}

	serial, err := devs[0].SerialNumber()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`^SDOM:(?P<SDOM>\d+) CPID:(?P<CPID>\d+) CPRV:(?P<CPRV>\d+) CPFM:(?P<CPFM>\d+) SCEP:(?P<SCEP>\d+) BDID:(?P<BDID>\d+) ECID:(?P<ECID>\S+) IBFL:(?P<IBFL>\S+) SRNM:\[(?P<SRNM>\S+)\]$`)
	if re.MatchString(serial) {
		matches := re.FindStringSubmatch(serial)
		if len(matches) != 10 {
			return nil, fmt.Errorf("failed to parse SerialNumber")
		}
		return &Client{
			SDOM: matches[1],
			CPID: matches[2],
			CPRV: matches[3],
			CPFM: matches[4],
			SCEP: matches[5],
			BDID: matches[6],
			ECID: matches[7],
			IBFL: matches[8],
			SRNM: matches[9],
			dev:  devs[0],
		}, nil
	} else {
		return &Client{
			dev: devs[0],
		}, nil
	}
}

func (c *Client) Close() error {
	return c.dev.Close()
}

func (c *Client) SendCommand(cmd string) error {
	if n, err := c.dev.Control(gousb.ControlVendor, 0x0, 0x0, 0x0, []byte(cmd+"\x00")); err != nil {
		return fmt.Errorf("%s.Control(%s): %v", c.dev, cmd, err)
	} else if n != len(cmd)+1 {
		return fmt.Errorf("%s.Control(%s): %d bytes written, want %d", c.dev, cmd, n, len(cmd)+1)
	}
	return nil
}

func (c *Client) SendFile(file string) error {
	return nil
}

func (c *Client) SetAutoboot(set bool) error {
	if err := c.SendCommand("setenv auto-boot " + fmt.Sprintf("%t", set)); err != nil {
		return err
	}
	return c.SendCommand("saveenv")
}

func (c *Client) Reboot(set bool) error {
	return c.SendCommand("reboot")
}
