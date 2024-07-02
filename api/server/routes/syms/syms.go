// Package syms provides the /syms API route
package syms

import (
	"net/http"
	"path/filepath"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/internal/syms"
	"github.com/gin-gonic/gin"
)

// swagger:response
type successResponse struct {
	Success bool `json:"success,omitempty"`
}

// AddRoutes adds the syms routes to the router
func AddRoutes(rg *gin.RouterGroup, db db.Database) {
	// swagger:route POST /syms/scan Syms postScan
	//
	// Scan
	//
	// Scan symbols for a given IPSW.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to IPSW
	//         required: true
	//         type: string
	//
	//     Responses:
	//       200: successResponse
	//       500: genericError
	rg.POST("/syms/scan", func(c *gin.Context) {
		ipswPath := filepath.Clean(c.Query("path"))
		if err := syms.Scan(ipswPath, db); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, successResponse{Success: true})
	})
}
