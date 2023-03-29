package download

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func downloadIPSW(c *gin.Context) {
	id := c.Param("id")

	c.IndentedJSON(http.StatusOK, gin.H{"message": "ipsw not found", "id": id})
}
