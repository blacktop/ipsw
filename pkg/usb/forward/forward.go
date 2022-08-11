package forward

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/blacktop/ipsw/pkg/usb"
)

func Start(ctx context.Context, udid string, lport, rport int, callback func(string, error)) (err error) {
	listen, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lport))
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				_ = listen.Close()
				return
			default:
			}

			conn, err := listen.Accept()
			if err != nil {
				if callback != nil {
					callback("", fmt.Errorf("accepting new conn error: %v", err))
				}
				continue
			}
			if callback != nil {
				callback("new client connected", nil)
			}

			go startNewProxy(ctx, conn, udid, rport, callback)
		}
	}()

	return nil
}

func startNewProxy(ctx context.Context, conn net.Conn, udid string, rport int, callback func(string, error)) {
	c, err := usb.NewClient(udid, rport)
	if err != nil {
		if callback != nil {
			callback("", fmt.Errorf("failed to connect to device port %d: %v", rport, err))
		}
		return
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
		_ = c.Close()
	}()
	go func() {
		io.Copy(conn, c.Conn())
	}()
	go func() {
		io.Copy(c.Conn(), conn)
	}()
}
