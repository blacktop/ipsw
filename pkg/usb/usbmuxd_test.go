package usb

import (
	"testing"
)

func TestConn_ListDevices(t *testing.T) {
	conn, err := NewConn()
	if err != nil {
		t.Fatal(err)
	}
	defer func(conn *Conn) {
		_ = conn.Close()
	}(conn)

	devices, err := conn.ListDevices()
	if err != nil {
		t.Fatal(err)
	}

	for _, device := range devices {
		t.Logf("%#v", device)
		pair, err := conn.ReadPairRecord(device.SerialNumber)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("%#v", pair)
	}
}
