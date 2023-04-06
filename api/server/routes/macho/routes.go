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
	// commands
	// m.GET("/a2o", handler)    // TODO: implement this
	// m.GET("/a2s", handler)    // TODO: implement this
	// m.GET("/bbl", handler)    // TODO: implement this
	// m.GET("/disass", handler) // TODO: implement this
	// m.GET("/dump", handler)   // TODO: implement this
	m.GET("/info", machoInfo)
	// m.GET("/lipo", handler)   // TODO: implement this
	// m.GET("/o2a", handler)    // TODO: implement this
	// m.GET("/patch", handler)  // TODO: implement this
	// m.GET("/search", handler) // TODO: implement this
	// m.GET("/sign", handler)   // TODO: implement this
}
