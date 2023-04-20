// Package diff provides /diff routes for diffing two files/text blobs
package diff

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aymanbagabas/go-udiff"
	"github.com/blacktop/ipsw/api/types"
	"github.com/gin-gonic/gin"
)

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
		prevPath := c.Query("prev")
		currPath := c.Query("curr")
		if prevPath == "" || currPath == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: "missing required 'prev' or 'curr' query parameter"})
			return
		}
		a, err := os.ReadFile(filepath.Clean(prevPath))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		b, err := os.ReadFile(filepath.Clean(currPath))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.IndentedJSON(http.StatusOK, diffResponse{Diff: udiff.Unified(prevPath, currPath, fmt.Sprintln(a), fmt.Sprintln(b))})
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
		prevBlob := c.Query("prev")
		currBlob := c.Query("curr")
		if prevBlob == "" || currBlob == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing required 'prev' or 'curr' query parameter"})
			return
		}
		c.IndentedJSON(http.StatusOK, diffResponse{Diff: udiff.Unified("", "", fmt.Sprintln(prevBlob), fmt.Sprintln(currBlob))})
	})
}
