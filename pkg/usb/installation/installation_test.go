package installation

import (
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestClient_Lookup(t *testing.T) {
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
		cli, err := NewClient(device.UDID)
		if err != nil {
			t.Fatal(err)
		}

		exePath, err := cli.LookupExePath("me.ele.ios.eleme")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(exePath)

		container, err := cli.LookupContainer("me.ele.ios.eleme")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(container)

		apps, err := cli.InstalledApps()
		if err != nil {
			t.Fatal(err)
		}

		// t.Logf("%#v", apps)
		for k, v := range apps {
			t.Log(k, v)
		}
	}
}

func TestClient_Archive(t *testing.T) {
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

	cli, err := NewClient(devices[0].UDID)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	if err := cli.Archive("com.dbgman.pangolin", func(event *ProgressEvent) {
		t.Log(event)
	}); err != nil {
		t.Fatal(err)
	}
}
