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
	// commands
	// dl.GET("/dev", handler) // TODO:
	// dl.GET("/git", handler) // TODO:
	// dl.GET("/ipa", handler) // TODO:
	// GET download IPSW
	dl.GET("/ipsw", downloadIPSW)
	// GET download latest iOS IPSWs
	dl.GET("/ipsw/ios/latest", downloadLatestIPSWs)
	// GET latest iOS version
	dl.GET("/ipsw/ios/latest/version", latestVersion)
	// GET latest iOS build
	dl.GET("/ipsw/ios/latest/build", latestBuild)
	// dl.GET("/macos", handler) // TODO:
	// dl.GET("/ota", handler)   // TODO:
	// dl.GET("/rss", handler)   // TODO:
	// dl.GET("/tss", handler)   // TODO:
	// dl.GET("/wiki", handler)  // TODO:
}
