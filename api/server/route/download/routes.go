package download

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/download")
	// base path
	dl.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "download")
	})
	// GET download IPSW
	dl.GET("/ipsw", downloadIPSW)
	// GET latest iOS version
	dl.GET("/ipsw/latest/version", latestVersion)
	// GET latest iOS build
	dl.GET("/ipsw/latest/build", latestBuild)
}
