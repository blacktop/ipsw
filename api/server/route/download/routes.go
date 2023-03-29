package download

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/download")
	dl.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "download")
	})
	dl.GET("/ipsw/:id", downloadIPSW)
}
