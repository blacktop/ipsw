// Package download contains the /download routes
package download

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/download")

	// dl.GET("/dev", handler) // TODO:
	// dl.GET("/git", handler) // TODO:
	// dl.GET("/ipa", handler) // TODO:
	// dl.GET("/ipsw", downloadIPSW) // TODO:
	// dl.GET("/ipsw/ios/latest", downloadLatestIPSWs) // TODO:

	// swagger:route GET /download/ipsw/ios/latest/version Download getDownloadLatestIPSWsVersion
	//
	// Latest iOS Version
	//
	// Get latest iOS version.
	dl.GET("/ipsw/ios/latest/version", latestVersion)
	// swagger:route GET /download/ipsw/ios/latest/build Download getDownloadLatestIPSWsBuild
	//
	// Latest iOS Build
	//
	// Get latest iOS build.
	dl.GET("/ipsw/ios/latest/build", latestBuild)

	// dl.GET("/macos", handler) // TODO:
	// dl.GET("/ota", handler)   // TODO:
	// dl.GET("/rss", handler)   // TODO:
	// dl.GET("/tss", handler)   // TODO:
	// dl.GET("/wiki", handler)  // TODO:
}
