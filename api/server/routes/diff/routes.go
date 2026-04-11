// Package diff provides /diff routes for diffing two text blobs
package diff

import (
	"fmt"
	"net/http"

	"github.com/aymanbagabas/go-udiff"
	"github.com/blacktop/ipsw/api/types"
	"github.com/gin-gonic/gin"
)

// swagger:parameters postDiffBlobs
type diffFilesParams struct {
	Previous string `json:"prev" binding:"required"`
	Current  string `json:"curr" binding:"required"`
}

// swagger:response diffResponse
type diffResponse struct {
	Diff string `json:"diff"`
}

// AddRoutes adds the diff routes to the router.
//
// Note: a former POST /diff/files endpoint that read arbitrary host paths was
// removed (CWE-22 arbitrary file read). Clients should read files locally and
// submit content to /diff/blobs.
func AddRoutes(rg *gin.RouterGroup) {
	dr := rg.Group("/diff")
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
