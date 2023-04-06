package info

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	rg.GET("/info/ipsw", getInfo)
	rg.GET("/info/ota", getInfo)
	rg.GET("/info/ipsw/remote", getRemoteInfo)
	rg.GET("/info/ota/remote", getRemoteInfo)
}
