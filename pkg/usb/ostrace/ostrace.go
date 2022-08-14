package ostrace

import (
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.os_trace_relay"
)

var (
	ListFilesPlistRequest uint32 = 0x30303030
	GetFileRequest        uint32 = 0x00000001
)

type ListFilesResponse struct {
	Version uint64   `plist:"version,omitempty"`
	Files   []string `plist:"files,omitempty"`
}

type Client struct {
	udid string
}

func NewClient(udid string) *Client {
	return &Client{
		udid: udid,
	}
}

type pidListTypeRequest struct {
	Request string `plist:"Request"`
}

type pidListEntry struct {
	ProcessName string `plist:"ProcessName,omitempty"`
}

type pidListTypeResponse struct {
	Payload map[string]pidListEntry `plist:"Payload,omitempty"`
	Status  string                  `plist:"Status,omitempty"`
}

func (c *Client) PidList() (map[string]string, error) {
	fc, err := lockdownd.NewClientForService(serviceName, c.udid, false)
	if err != nil {
		return nil, err
	}

	req := &pidListTypeRequest{
		Request: "PidList",
	}
	if err := fc.Send(req); err != nil {
		return nil, err
	}
	if _, err := fc.RecvByte(); err != nil { // skip the first byte (which is 1)
		return nil, err
	}
	var resp pidListTypeResponse
	if err := fc.Recv(&resp); err != nil {
		return nil, err
	}

	pid2name := make(map[string]string)
	for pid, entry := range resp.Payload {
		pid2name[pid] = entry.ProcessName
	}

	fc.Close()

	return pid2name, nil
}
