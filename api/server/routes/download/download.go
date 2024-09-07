package download

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/commands/download/ipsw"
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

// swagger:response
type latestIpswIosVersionResponse struct {
	Version string `json:"version"`
}

func latestVersion(c *gin.Context) {
	version, err := ipsw.GetLatestIosVersion("", true)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, latestIpswIosVersionResponse{Version: version})
}

// swagger:response
type latestIpswIosBuildResponse struct {
	Build string `json:"build"`
}

func latestBuild(c *gin.Context) {
	build, err := ipsw.GetLatestIosBuild()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, latestIpswIosBuildResponse{Build: build})
}
