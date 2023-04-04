package ipsw

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/ipsw")
	dl.GET("/fs/files", getFsFiles)
	dl.GET("/fs/ents", getFsEntitlements)
}
