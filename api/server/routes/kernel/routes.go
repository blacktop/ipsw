package kernel

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	kg := rg.Group("/kernel")
	// base path
	kg.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, "kernel")
	})
	// commands
	// kg.GET("/ctfdump", handler) // TODO: implement this
	// kg.GET("/dec", handler)     // TODO: implement this
	// kg.GET("/dwarf", handler)   // TODO: implement this
	// kg.GET("/extract", handler) // TODO: implement this
	kg.GET("/kexts", listKexts)
	// kg.GET("/sbopts", handler)     // TODO: implement this
	// kg.GET("/symbolsets", handler) // TODO: implement this
	// kg.GET("/syscall", handler)    // TODO: implement this
	kg.GET("/version", getVersion)
}
