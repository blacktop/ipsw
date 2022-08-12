package syslog

import (
	"io"

	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const serviceName = "com.apple.syslog_relay"

func Syslog(udid string) (io.ReadCloser, error) {
	cli, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}

	if err := cli.Send("watch"); err != nil {
		return nil, err
	}

	return cli.Conn(), nil
}
