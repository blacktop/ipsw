package ipsw

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup, pemDB string) {
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
	//       + name: pem_db
	//         in: query
	//         description: path to AEA pem DB JSON file
	//         required: false
	//         type: string
	//
	//     Responses:
	//       200: getFsFilesResponse
	//       500: genericError
	dl.GET("/fs/files", getFsFiles(pemDB))
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
	//       + name: pem_db
	//         in: query
	//         description: path to AEA pem DB JSON file
	//         required: false
	//         type: string
	//
	//     Responses:
	//       200: getFsEntitlementsResponse
	//       500: genericError
	dl.GET("/fs/ents", getFsEntitlements(pemDB))
	// swagger:route GET /ipsw/fs/launchd IPSW getIpswFsLaunchd
	//
	// launchd Config
	//
	// Get <code>launchd</code> config from IPSW Filesystem DMG.
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
	//       + name: pem_db
	//         in: query
	//         description: path to AEA pem DB JSON file
	//         required: false
	//         type: string
	//
	//     Responses:
	//       200: getFsLaunchdConfigResponse
	//       500: genericError
	dl.GET("/fs/launchd", getFsLaunchdConfig(pemDB))
}
