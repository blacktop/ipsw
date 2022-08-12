package pcap

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestClient_ReadOPacket(t *testing.T) {
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

		err = cli.ReadPacket(context.Background(), "", os.Stdout, func(hdr IOSPacketHeader, data []byte) {
			fmt.Println("\n----")
			fmt.Println(hex.Dump(data))
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = cli.Close()
	}
}
