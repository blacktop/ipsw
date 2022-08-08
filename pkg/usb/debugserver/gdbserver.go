package debugserver

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
)

type GDBServer struct {
	rw      io.ReadWriter
	scanner *bufio.Scanner
}

func NewGDBServer(rw io.ReadWriter) *GDBServer {
	scanner := bufio.NewScanner(rw)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		const lenPacketSuffix = 3
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		start := bytes.IndexRune(data, '$')
		end := bytes.IndexRune(data, '#')
		if start < 0 || end < 0 || len(data) < end+lenPacketSuffix {
			return 0, nil, err
		}

		if end < start {
			return 0, nil, errors.New("invalid payload")
		}

		return end + lenPacketSuffix, data[start+1 : end], nil
	})

	return &GDBServer{rw: rw, scanner: scanner}
}

func (*GDBServer) chksum(pck string) string {
	sum := 0
	for _, b := range pck {
		sum += int(b)
	}
	return hex.EncodeToString([]byte{byte(sum % 256)})
}

func (g *GDBServer) formatPacket(pck string) string {
	if pck == "QStartNoAckMode" {
		return "$" + pck + "#" + g.chksum(pck)
	}
	if pck == "QEnableErrorStrings" {
		return "+$" + pck + "#00"
	}

	return "+$" + pck + "#" + g.chksum(pck)
}

func (g *GDBServer) Recv() (string, error) {
	if g.scanner.Scan() == false {
		return "", g.scanner.Err()
	}
	return g.scanner.Text(), nil
}

func (g *GDBServer) Send(req string) error {
	pck := g.formatPacket(req)
	if _, err := g.rw.Write([]byte(pck)); err != nil {
		return err
	}
	return nil
}

func (g *GDBServer) Request(req string) (string, error) {
	if err := g.Send(req); err != nil {
		return "", err
	}
	return g.Recv()
}
