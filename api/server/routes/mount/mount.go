// Package mount provides the /mount API route
package mount

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gin-gonic/gin"
)

// swagger:response
type mountReponse struct {
	// in: body
	Body mount.Context
}

// swagger:response
type successResponse struct {
	Success bool `json:"success,omitempty"`
}

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup, pemDB string) {
	// Keep ownership server-side: older clients only echo mount_point/dmg_path.
	var mu sync.Mutex
	mounts := make(map[string]*mount.Context)
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
	//         description: type of DMG to mount (app|sys|fs|exc|rdisk|rosetta)
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
	//       + name: mount_point
	//         in: query
	//         description: custom mount point path
	//         required: false
	//         type: string
	//       + name: device
	//         in: query
	//         description: device product type or board (e.g. Mac18,5 or j873gap)
	//         required: false
	//         type: string
	//       + name: ident
	//         in: query
	//         description: identity variant for rdisk (e.g. 'Erase', 'Update', or 'Recovery')
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

		mountPointParam, _ := c.GetQuery("mount_point")
		if mountPointParam != "" {
			mountPointParam = filepath.Clean(mountPointParam)
		}
		ident, _ := c.GetQuery("ident")

		dmgType := c.Param("type")
		if !slices.Contains(mount.DmgTypes, dmgType) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid dmg type: must be one of: %s", strings.Join(mount.DmgTypes, ", "))})
			return
		}
		ctx, err := mount.DmgInIPSW(ipswPath, dmgType, &mount.Config{
			Device:     c.Query("device"),
			PemDB:      pemDbPath,
			MountPoint: mountPointParam,
			Ident:      ident,
		})
		if err != nil {
			if errors.Unwrap(err) == info.ErrorCryptexNotFound {
				c.AbortWithError(http.StatusNotFound, err)
				return
			}
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		if canonical, err := filepath.EvalSymlinks(ctx.MountPoint); err == nil {
			ctx.MountPoint = canonical
		}
		mu.Lock()
		defer mu.Unlock()
		if previous := mounts[ctx.MountPoint]; previous == nil || previous.AlreadyMounted {
			mounts[ctx.MountPoint] = ctx
		}
		c.JSON(http.StatusOK, ctx)
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
	//     description: "Echo the full context returned from /mount, including its ownership flags"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         mount_point:
	//           type: string
	//         dmg_path:
	//           type: string
	//         already_mounted:
	//           type: boolean
	//         owns_directory:
	//           type: boolean
	//         retain_dmg:
	//           type: boolean
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
		if canonical, err := filepath.EvalSymlinks(ctx.MountPoint); err == nil {
			ctx.MountPoint = canonical
		}
		mu.Lock()
		defer mu.Unlock()
		owned := mounts[ctx.MountPoint]
		if owned == nil {
			owned = &ctx // Preserve support for mounts acquired outside this daemon.
		}
		if err := owned.Unmount(); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		delete(mounts, ctx.MountPoint)
		c.JSON(http.StatusOK, successResponse{Success: true})
	})
}
