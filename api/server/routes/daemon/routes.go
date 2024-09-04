// Package daemon provides the daemon routes
package daemon

import (
	"net/http"
	"runtime"

	"github.com/gin-gonic/gin"

	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/api/types"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	// swagger:route HEAD /_ping Daemon headDaemonPing
	//
	// Ping
	//
	// This will return if 200 the daemon is running.
	//
	//     Responses:
	//       200:
	//       	description: "no error"
	//   		schema:
	//     			type: "string"
	//     			example: "(empty)"
	rg.HEAD("/_ping", pingHandler)
	// swagger:route GET /_ping Daemon getDaemonPing
	//
	// Ping
	//
	// This will return "OK" if the daemon is running.
	//
	//     Responses:
	//       200:
	//       	description: "no error"
	//   		schema:
	//     			type: "string"
	//     			example: "OK"
	rg.GET("/_ping", pingHandler)
	// swagger:route GET /version Daemon getDaemonVersion
	//
	// Version
	//
	// This will return the daemon version info.
	//
	//     Responses:
	//       200: versionResponse
	rg.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, versionResponse{types.Version{
			APIVersion:     api.DefaultVersion,
			OSType:         runtime.GOOS,
			BuilderVersion: types.BuildVersion,
		}})
	})
}

// swagger:response versionResponse
type versionResponse struct {
	// swagger:allOf
	types.Version
}

func pingHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")

	if c.Request.Method == "HEAD" {
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("Content-Length", "0")
		return
	}
	c.String(http.StatusOK, "OK")
}
