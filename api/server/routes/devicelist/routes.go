// Package devicelist contains the /device_list routes for the API
package devicelist

import (
	"net/http"
	"sort"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/pkg/xcode"
	"github.com/gin-gonic/gin"
)

// swagger:response
type deviceListResponse struct {
	Devices []xcode.Device `json:"devices"`
}

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	// swagger:route GET /device_list DeviceList getDeviceList
	//
	// List Xcode Devices.
	//
	// This will return JSON of all Xcode devices.
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: deviceListResponse
	//       500: genericError
	rg.GET("/device_list", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")

		devices, err := xcode.GetDevices()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}

		sort.Sort(xcode.ByProductType{Devices: devices})

		c.JSON(http.StatusOK, deviceListResponse{Devices: devices})
	})
}
