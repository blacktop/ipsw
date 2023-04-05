package idev

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/idev")
	// base path
	dl.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "extract")
	})

	dl.GET("/info", idevInfo)
}
