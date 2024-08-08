// Package mount provides the /mount API route
package mount

import (
	"errors"
	"net/http"
	"path/filepath"
	"slices"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gin-gonic/gin"
)

// swagger:response
type mountReponse struct {
	mount.Context
}

// swagger:response
type successResponse struct {
	Success bool `json:"success,omitempty"`
}

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup, pemDB string) {
	// swagger:route POST /mount/{type} Mount postMount
	//
	// Mount
	//
	// Mount a DMG inside a given IPSW.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: type
	//         in: path
	//         description: type of DMG to mount (app|sys|fs)
	//         required: true
	//         type: string
	//       + name: path
	//         in: query
	//         description: path to IPSW
	//         required: true
	//         type: string
	//       + name: pem_db
	//         in: query
	//         description: path to AEA pem DB JSON file
	//         required: false
	//         type: string
	//     Responses:
	//       500: genericError
	//       200: mountReponse
	rg.POST("/mount/:type", func(c *gin.Context) {
		ipswPath, ok := c.GetQuery("path")
		if !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: "missing path query parameter"})
			return
		} else {
			ipswPath = filepath.Clean(ipswPath)
		}
		pemDbPath, ok := c.GetQuery("pem_db")
		if ok {
			pemDbPath = filepath.Clean(pemDbPath)
		} else {
			if pemDB != "" {
				pemDbPath = filepath.Clean(pemDB)
			}
		}
		dmgType := c.Param("type")
		if !slices.Contains([]string{"app", "sys", "fs"}, dmgType) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid dmg type: must be app, sys, or fs"})
			return
		}
		ctx, err := mount.DmgInIPSW(ipswPath, dmgType, pemDbPath)
		if err != nil {
			if errors.Unwrap(err) == info.ErrorCryptexNotFound {
				c.AbortWithError(http.StatusNotFound, err)
				return
			}
			c.AbortWithError(http.StatusInternalServerError, err)
		}
		c.JSON(http.StatusOK, mountReponse{
			*ctx,
		})
	})
	// swagger:operation POST /unmount Mount postUnmount
	//
	// Unmount
	//
	// Unmount a previously mounted DMG.
	//
	// ---
	// consumes:
	//   - "application/json"
	// produces:
	//   - "application/json"
	// parameters:
	//   -
	//     in: "body"
	//     name: "body"
	//     description: "The unmount context (returned from /mount)"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         mount_point:
	//           type: string
	//         dmg_path:
	//           type: string
	// responses:
	//   '200':
	//     description: successful response
	//     schema:
	//       $ref: '#/responses/successResponse'
	//   '500':
	//     description: error response
	//     schema:
	//       $ref: '#/responses/genericError'
	rg.POST("/unmount", func(c *gin.Context) {
		ctx := mount.Context{}
		if err := c.ShouldBindJSON(&ctx); err != nil {
			c.IndentedJSON(http.StatusBadRequest, err)
			return
		}
		if err := ctx.Unmount(); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, successResponse{Success: true})
	})
}
