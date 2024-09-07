// Package info provides a route for getting info about an IPSW or OTA file
package info

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
)

// swagger:response
type infoResponse struct {
	Path string     `json:"path"`
	Info *info.Info `json:"info"`
}

func getInfo(c *gin.Context) {
	path := c.Query("path")

	i, err := info.Parse(path)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, infoResponse{Path: path, Info: i})
}

// swagger:response
type infoRemoteResponse struct {
	URL  string     `json:"path"`
	Info *info.Info `json:"info"`
}

func getRemoteInfo(c *gin.Context) {
	insecure, _ := strconv.ParseBool(c.Query("insecure"))

	zr, err := download.NewRemoteZipReader(c.Query("url"), &download.RemoteConfig{
		Proxy:    c.Query("proxy"),
		Insecure: insecure,
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, infoRemoteResponse{URL: c.Query("url"), Info: i})
}
