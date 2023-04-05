package dsc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/dsc")
	// base path
	dl.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "dsc")
	})

	// dl.GET("/a2s", extractKBAG)
	// dl.GET("/ida", extractKernel)
	// dl.GET("/imps", extractKernel)
	dl.GET("/info", dscInfo)
	dl.POST("/sym", dscSymbols)
	dl.GET("/str", dscStrings)
}
