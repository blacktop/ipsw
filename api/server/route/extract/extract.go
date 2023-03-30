package extract

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func extractDSC(c *gin.Context) {
	ipswPath := c.Query("ipsw_path")
	c.IndentedJSON(http.StatusOK, gin.H{"ipsw_path": ipswPath})
}

func extractKBAG(c *gin.Context) {
	ipswPath := c.Query("ipsw_path")
	c.IndentedJSON(http.StatusOK, gin.H{"ipsw_path": ipswPath})
}

func extractKernel(c *gin.Context) {
	ipswPath := c.Query("ipsw_path")
	c.IndentedJSON(http.StatusOK, gin.H{"ipsw_path": ipswPath})
}

func extractPattern(c *gin.Context) {
	ipswPath := c.Query("ipsw_path")
	c.IndentedJSON(http.StatusOK, gin.H{"ipsw_path": ipswPath})
}
