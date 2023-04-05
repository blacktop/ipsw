// Package idev provides the /idev route and handlers
package idev

import (
	"fmt"
	"net/http"

	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/gin-gonic/gin"
)

func idevInfo(c *gin.Context) {
	conn, err := usb.NewConn()
	if err != nil {
		c.JSON(http.StatusInternalServerError, fmt.Errorf("failed to connect to usbmuxd: %w", err))
		return
	}
	defer conn.Close()

	devices, err := conn.ListDevices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	if len(devices) == 0 {
		c.JSON(http.StatusOK, gin.H{"status": "no devices found", "devices": nil})
		return
	}

	var dds []*lockdownd.DeviceValues

	for _, device := range devices {
		cli, err := lockdownd.NewClient(device.SerialNumber)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}

		values, err := cli.GetValues()
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}

		dds = append(dds, values)

		cli.Close()
	}

	c.JSON(http.StatusOK, gin.H{"devices": dds})
}
