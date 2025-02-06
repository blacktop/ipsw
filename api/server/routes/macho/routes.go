package macho

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	m := rg.Group("/macho")
	// m.GET("/a2o", handler)    // TODO: implement this
	// m.GET("/a2s", handler)    // TODO: implement this
	// m.GET("/bbl", handler)    // TODO: implement this
	// m.GET("/disass", handler) // TODO: implement this
	// m.GET("/dump", handler)   // TODO: implement this

	// swagger:route GET /macho/info MachO getMachoInfo
	//
	// Info
	//
	// Get MachO info.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to MachO
	//         required: true
	//         type: string
	//	    + name: arch
	//         in: query
	//         description: architecture to get info for in universal MachO
	//         required: false
	//         type: string
	//     Responses:
	//       200: machoInfoResponse
	//       400: genericError
	//       500: genericError
	m.GET("/info", machoInfo)
	// swagger:route GET /macho/info/strings MachO getMachoInfoStrings
	//
	// Strings
	//
	// Get MachO strings.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to MachO
	//         required: true
	//         type: string
	//	    + name: arch
	//         in: query
	//         description: architecture to get info for in universal MachO
	//         required: false
	//         type: string
	//     Responses:
	//       200: machoStringsResponse
	//       400: genericError
	//       500: genericError
	m.GET("/info/strings", machoStrings)

	// m.GET("/lipo", handler)   // TODO: implement this
	// m.GET("/o2a", handler)    // TODO: implement this
	// m.GET("/patch", handler)  // TODO: implement this
	// m.GET("/search", handler) // TODO: implement this
	// m.GET("/sign", handler)   // TODO: implement this
}
