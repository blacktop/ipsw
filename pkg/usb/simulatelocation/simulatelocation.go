package simulatelocation

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
)

const (
	serviceName = "com.apple.dt.simulatelocation"
)

type Client struct {
	c *usb.Client
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		c: c,
	}, nil
}

func (c *Client) Set(latitude, longitude string) error {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(len(latitude))); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, []byte(latitude)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(len(longitude))); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, []byte(longitude)); err != nil {
		return err
	}

	n, err := c.c.Conn().Write(buf.Bytes())
	if n != buf.Len() {
		return fmt.Errorf("failed to set location: expected to write %d bytes, wrote %d", buf.Len(), n)
	}

	return err
}

func (c *Client) Clear() error {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, uint32(1)); err != nil {
		return err
	}

	n, err := c.c.Conn().Write(buf.Bytes())

	if n != buf.Len() {
		return fmt.Errorf("failed to clear location: expected to write %d bytes, wrote %d", buf.Len(), n)
	}

	return err
}

type Gpx struct {
	XMLName xml.Name `xml:"gpx"`
	Tracks  []Track  `xml:"trk"`
}

type Track struct {
	XMLName       xml.Name       `xml:"trk"`
	TrackSegments []TrackSegment `xml:"trkseg"`
	Name          string         `xml:"name"`
}

type TrackSegment struct {
	XMLName     xml.Name     `xml:"trkseg"`
	TrackPoints []TrackPoint `xml:"trkpt"`
}

type TrackPoint struct {
	XMLName        xml.Name `xml:"trkpt"`
	PointLongitude string   `xml:"lon,attr"`
	PointLatitude  string   `xml:"lat,attr"`
	PointTime      string   `xml:"time"`
}

// Simulate live tracking using a .gpx file
func (c *Client) PlayGPX(filename string) error {
	dat, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read gpx file %s: %v", filename, err)
	}

	var gpx Gpx
	if err := xml.Unmarshal(dat, &gpx); err != nil {
		return fmt.Errorf("failed to parse gpx file %s: %v", filename, err)
	}

	var lastPointTime time.Time
	for _, trk := range gpx.Tracks {
		for _, seg := range trk.TrackSegments {
			for _, pt := range seg.TrackPoints {
				currentPointTime, err := time.Parse(time.RFC3339, pt.PointTime)

				if !lastPointTime.IsZero() {
					if err != nil {
						return err
					}

					duration := currentPointTime.Unix() - lastPointTime.Unix()

					if duration > 0 {
						time.Sleep(time.Duration(duration) * time.Second)
					}
				}

				lastPointTime = currentPointTime

				if err := c.Set(pt.PointLatitude, pt.PointLongitude); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
