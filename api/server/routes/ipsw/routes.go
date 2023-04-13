package ipsw

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/ipsw")
	// swagger:route GET /ipsw/fs/files IPSW getIpswFsFiles
	//
	// Files
	//
	// Get IPSW Filesystem DMG file listing.
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
	dl.GET("/fs/files", getFsFiles)
	// swagger:route GET /ipsw/fs/ents IPSW getIpswFsEntitlements
	//
	// Entitlements
	//
	// Get IPSW Filesystem DMG MachO entitlements.
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
	dl.GET("/fs/ents", getFsEntitlements)
}
