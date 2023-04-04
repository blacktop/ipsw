package info

import (
	"net/http"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gin-gonic/gin"
)

func getInfo(c *gin.Context) {
	ipswPath := c.Query("ipsw_path")
	i, err := info.Parse(ipswPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"ipsw_path": ipswPath, "info": i})
}
