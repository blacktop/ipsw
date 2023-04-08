// Package daemon provides the daemon routes
package daemon

import (
	"net/http"
	"runtime"

	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/api/types"
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	rg.HEAD("/_ping", pingHandler)
	rg.GET("/_ping", pingHandler)
	rg.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, types.Version{
			ApiVersion:     api.DefaultVersion,
			OSType:         runtime.GOOS,
			BuilderVersion: types.BuildVersion,
		})
	})
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
