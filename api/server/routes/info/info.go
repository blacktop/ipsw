// Package info provides a route for getting info about an IPSW or OTA file
package info

import (
	"net/http"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gin-gonic/gin"
)

func getInfo(c *gin.Context) {
	path := c.Query("path")
	i, err := info.Parse(path)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"path": path, "info": i})
}
