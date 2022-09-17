package lockdownd

import (
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestLockdowndClient_GetValues(t *testing.T) {
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
		cli, err := NewClient(device.SerialNumber)
		if err != nil {
			t.Fatal(err)
		}
		values, err := cli.GetValues()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", values)
		cli.Close()
	}
}
