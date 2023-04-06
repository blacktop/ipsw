package system

import (
	"net/http"
	"runtime"

	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/api/types"
	"github.com/gin-gonic/gin"
)

// Ping contains response of Engine API:
// GET "/_ping"
type Ping struct {
	APIVersion     string
	OSType         string
	BuilderVersion string
}

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	m := rg.Group("/system")

	m.HEAD("/_ping", pingHandler)
	m.GET("/_ping", pingHandler)
}

func pingHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")

	if c.Request.Method == "HEAD" {
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("Content-Length", "0")
		return
	}

	c.JSON(http.StatusOK, Ping{
		APIVersion:     api.DefaultVersion,
		OSType:         runtime.GOOS,
		BuilderVersion: types.BuildVersion,
	})
}
