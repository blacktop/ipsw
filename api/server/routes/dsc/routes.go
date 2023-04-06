package dsc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dr := rg.Group("/dsc")
	// base path
	dr.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "dsc")
	})
	// commands
	// dr.GET("/a2f", handler)     // TODO: implement this
	// dr.GET("/a2o", handler)     // TODO: implement this
	// dr.GET("/a2s", handler)     // TODO: implement this
	// dr.GET("/disass", handler)  // TODO: implement this
	// dr.GET("/dump", handler)    // TODO: implement this
	// dr.GET("/extract", handler) // TODO: implement this
	// dr.GET("/ida", handler)     // TODO: implement this
	// dr.GET("/image", handler)   // TODO: implement this
	dr.GET("/imports", dscImports)
	dr.GET("/info", dscInfo)
	dr.GET("/macho", dscMacho)
	// dr.GET("/o2a", handler)     // TODO: implement this
	// dr.GET("/objc", handler)    // TODO: implement this
	// dr.GET("/patches", handler) // TODO: implement this
	// dr.GET("/search", handler)  // TODO: implement this
	// dr.GET("/slide", handler)   // TODO: implement this
	// dr.GET("/split", handler)   // TODO: implement this
	dr.GET("/str", dscStrings)
	// dr.GET("/stubs", handler) // TODO: implement this
	// dr.GET("/swift", handler) // TODO: implement this
	dr.POST("/symaddr", dscSymbols)
	// dr.GET("/tbd", handler)    // TODO: implement this
	// dr.GET("/webkit", handler) // TODO: implement this
	// dr.GET("/xref", handler)   // TODO: implement this
}
