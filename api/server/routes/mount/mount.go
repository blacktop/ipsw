// Package mount provides the /mount API route
package mount

import (
	"net/http"
	"path/filepath"

	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
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
	rg.POST("/mount/:type", func(c *gin.Context) {
		ipswPath := filepath.Clean(c.Query("path"))
		dmgType := c.Param("type")
		if !utils.StrSliceContains([]string{"app", "sys", "fs"}, dmgType) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid dmg type: must be app, sys, or fs"})
			return
		}
		ctx, err := mount.DmgInIPSW(ipswPath, dmgType)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
		}
		c.JSON(http.StatusOK, gin.H{"dmg_path": ctx.DmgPath, "mount_point": ctx.MountPoint, "already_mounted": ctx.AlreadyMounted})
	})
	// swagger:route POST /unmount Mount postUnmount
	//
	// Unmount
	//
	// Unmount a previously mounted DMG.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: mount_point
	//         in: path
	//         description: mount point of DMG
	//         required: true
	//         type: string
	//       + name: dmg_path
	//         in: query
	//         description: path to DMG
	//         type: string
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
		c.JSON(http.StatusOK, gin.H{"success": true})
	})
}
