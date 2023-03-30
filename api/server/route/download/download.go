package download

import (
	"net/http"

	"github.com/blacktop/ipsw/internal/commands/download/ipsw"
	"github.com/gin-gonic/gin"
)

func downloadIPSW(c *gin.Context) {
	version := c.Query("version")
	build := c.Query("build")
	device := c.Query("device")

	c.IndentedJSON(http.StatusOK, gin.H{"version": version, "build": build, "device": device})
}
func downloadLatestIPSWs(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, gin.H{"count": 0})
}

func latestVersion(c *gin.Context) {
	version, err := ipsw.GetLatestIosVersion("", false)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"version": version})
}

func latestBuild(c *gin.Context) {
	build, err := ipsw.GetLatestIosBuild()
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"build": build})
}
