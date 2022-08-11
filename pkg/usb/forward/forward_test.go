package forward

import (
	"context"
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestStart(t *testing.T) {
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

	if err := Start(context.Background(), devices[0].UDID, 2222, 2222, func(s string, err error) {
		if err != nil {
			t.Fatal(err)
		}

		t.Log(s)
	}); err != nil {
		t.Fatal(err)
	}

	select {}
}
