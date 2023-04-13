// Package info provides a route for getting info about an IPSW or OTA file
package info

import (
	"net/http"
	"strconv"

	"github.com/blacktop/ipsw/internal/download"
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

func getRemoteInfo(c *gin.Context) {
	insecure, _ := strconv.ParseBool(c.Query("insecure"))
	zr, err := download.NewRemoteZipReader(c.Query("url"), &download.RemoteConfig{
		Proxy:    c.Query("proxy"),
		Insecure: insecure,
	})
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"url": c.Query("url"), "info": i})
}
