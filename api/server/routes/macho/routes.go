package macho

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	m := rg.Group("/macho")
	// base path
	m.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "macho")
	})

	m.GET("/info", machoInfo)
}
