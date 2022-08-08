package debugserver

import (
	"io"
	"net"
	"testing"

	"github.com/blacktop/ipsw/pkg/usb"
)

func TestProxy(t *testing.T) {
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

	if len(devices) < 1 {
		t.Fatal("not device")
	}

	device := devices[0]

	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func(listen net.Listener) {
		_ = listen.Close()
	}(listen)

	port := listen.Addr().(*net.TCPAddr).Port
	t.Log("debugserver proxy listen on:", port)
	for {
		conn, err := listen.Accept()
		if err != nil {
			t.Log(err)
			continue
		}
		dc, err := NewClient(device.UDID)
		if err != nil {
			conn.Close()
			t.Log(err)
			continue
		}

		t.Log("new conn from:", conn.RemoteAddr())
		startProxy(dc.Conn(), conn)
	}
}

func startProxy(conn1, conn2 io.ReadWriteCloser) {
	go func() {
		defer conn1.Close()
		defer conn2.Close()
		io.Copy(conn2, conn1)
	}()
	go func() {
		defer conn1.Close()
		defer conn2.Close()
		io.Copy(conn1, conn2)
	}()
}
