// Package devicelist contains the routes for the device_list API
package devicelist

import (
	"net/http"
	"sort"

	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	// swagger:route GET /device_list DeviceList getDeviceList
	//
	// List XCode Devices.
	//
	// This will return JSON of all XCode devices.
	//
	//     Produces:
	//     - application/json
	rg.GET("/device_list", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		devices, err := xcode.GetDevices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}

		sort.Sort(xcode.ByProductType{Devices: devices})

		c.JSON(http.StatusOK, devices)
	})
}
