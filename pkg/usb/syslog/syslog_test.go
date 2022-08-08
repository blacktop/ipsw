package syslog

import (
	"io"
	"os"
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestSyslog(t *testing.T) {
	conn, err := usb.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	defer func(conn *usb.Conn) {
		_ = conn.Close()
	}(conn)

	devices, err := conn.ListDevices()
	if err != nil {
		t.Fatal(err)
	}

	for _, device := range devices {
		r, err := Syslog(device.UDID)
		if err != nil {
			t.Fatal(err)
		}

		io.Copy(os.Stdout, r)
	}
}
