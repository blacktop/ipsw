// Package diff provides /diff routes for diffing two files/text blobs
package diff

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aymanbagabas/go-udiff"
	"github.com/gin-gonic/gin"

	"github.com/blacktop/ipsw/api/types"
)

// swagger:parameters postDiffFiles postDiffBlobs
type diffFilesParams struct {
	Previous string `json:"prev" binding:"required"`
	Current  string `json:"curr" binding:"required"`
}

// swagger:response diffResponse
type diffResponse struct {
	Diff string `json:"diff"`
}

// AddRoutes adds the diff routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dr := rg.Group("/diff")
	// swagger:route POST /diff/files Diff postDiffFiles
	//
	// Files
	//
	// This will return the diff of two text files.
	//
	//     Responses:
	//       200: diffResponse
	//       400: genericError
	//       500: genericError
	dr.POST("/files", func(c *gin.Context) {
		var params diffFilesParams
		if err := c.ShouldBindJSON(&params); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
			return
		}
		a, err := os.ReadFile(filepath.Clean(params.Previous))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		b, err := os.ReadFile(filepath.Clean(params.Current))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.IndentedJSON(http.StatusOK, diffResponse{Diff: udiff.Unified(params.Previous, params.Current, fmt.Sprintln(a), fmt.Sprintln(b))})
	})
	// swagger:route POST /diff/blobs Diff postDiffBlobs
	//
	// Blobs
	//
	// This will return the diff of two text blobs.
	//
	//     Responses:
	//       200: diffResponse
	//       400: genericError
	dr.POST("/blobs", func(c *gin.Context) {
		var params diffFilesParams
		if err := c.ShouldBindJSON(&params); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
			return
		}
		c.IndentedJSON(http.StatusOK, diffResponse{Diff: udiff.Unified("", "", fmt.Sprintln(params.Previous), fmt.Sprintln(params.Current))})
	})
}
