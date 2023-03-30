package ent

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/ent")
	// base path
	dl.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "ent")
	})

	// dl.GET("/ent", extractDSC)
}
