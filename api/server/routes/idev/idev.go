// Package idev provides the /idev route and handlers
package idev

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb"
	"github.com/blacktop/ipsw/pkg/usb/amfi"
	"github.com/blacktop/ipsw/pkg/usb/heartbeat"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/gin-gonic/gin"
)

// swagger:response idevInfoResponse
type idevInfoResponse struct {
	Devices []*lockdownd.DeviceValues `json:"devices,omitempty"`
}

func idevInfo(c *gin.Context) {
	conn, err := usb.NewConn()
	if err != nil {
		c.JSON(http.StatusInternalServerError, fmt.Errorf("failed to connect to usbmuxd: %w", err))
		return
	}
	defer conn.Close()

	devices, err := conn.ListDevices()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
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
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}

		values, err := cli.GetValues()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}

		dds = append(dds, values)

		cli.Close()
	}

	c.JSON(http.StatusOK, idevInfoResponse{Devices: dds})
}

func idevAmfiDev(c *gin.Context) {
	udid := c.Query("udid")

	ok, err := utils.IsDeveloperModeEnabled(udid)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	if ok {
		c.JSON(http.StatusOK, gin.H{"status": "Developer Mode is already enabled", "device": udid})
		return
	} else {
		cli, err := amfi.NewClient(udid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		defer cli.Close()

		if err := cli.EnableDeveloperMode(); err != nil {
			if errors.Is(err, amfi.ErrPasscodeSet) {
				c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: fmt.Errorf("cannot enabled Developer Mode when a pass-code is set: %w", err).Error()})
				return
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
				return
			}
		}

		awake := make(chan bool)
		defer close(awake)
		errs := make(chan error)
		defer close(errs)

		go func() {
			rebooting := false
			for {
				hb, err := heartbeat.NewClient(udid)
				if err != nil {
					rebooting = true
					time.Sleep(1 * time.Second)
					continue // ignore heartbeat connection errors (device may be rebooting)
				}
				beat, err := hb.Beat()
				if err != nil {
					errs <- fmt.Errorf("failed to start heartbeat: %w", err)
				}
				if rebooting && beat.Command == "Marco" { // REBOOTED
					awake <- true
					break
				}
				hb.Close()
				time.Sleep(1 * time.Second)
			}
		}()

		select {
		case err := <-errs:
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		case <-awake:
			cli, err := amfi.NewClient(udid)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
				return
			}
			defer cli.Close()
			if err := cli.EnableDeveloperModePostRestart(); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
				return
			}
		case <-time.After(time.Minute):
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: fmt.Errorf("device did not restart in time (1 minute)").Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "Developer Mode enabled", "device": udid})
}
