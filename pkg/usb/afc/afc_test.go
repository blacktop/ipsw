package afc

import (
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestClient_CopyFileToDevice(t *testing.T) {
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
	t.Log(devices)

	device := devices[0]
	afcClient, err := NewClient(device.UDID)
	if err != nil {
		t.Fatal(err)
	}
	defer func(afcClient *Client) {
		_ = afcClient.Close()
	}(afcClient)

	t.Log(afcClient)

	// /private/var/mobile/Media
	if err := afcClient.CopyFileToDevice(
		"/libcoredebugd.dylib",
		"/Users/gofmt/Work/Code/iosprojects/rootlesspayload/Payload",
	); err != nil {
		t.Fatal(err)
	}
}
