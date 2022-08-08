//go:build windows

package usb

import (
	"net"
)

func usbmuxdDial() (net.Conn, error) {
	return net.Dial("tcp", "localhost:27015")
}
